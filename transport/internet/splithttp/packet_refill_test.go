package splithttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

// A one-byte range selects exactly 18000 while exercising the variable path.
// Each POST can be held after reading its body, so synctest can let the writer
// fill the pipe before the uploader considers the next request.
func packetRefillConn(t *testing.T, post func([]byte) error) net.Conn {
	t.Helper()
	config := &Config{Mode: "packet-up", ScMaxEachPostBytes: &RangeConfig{From: 18000, To: 18001},
		ScMinPostsIntervalMs: &RangeConfig{From: 0, To: 1}, XPaddingBytes: &RangeConfig{From: 1, To: 1}}
	stream := &internet.MemoryStreamConfig{ProtocolName: "splithttp", ProtocolSettings: config}
	dest := xnet.TCPDestination(xnet.LocalHostIP, 80)
	client := &DefaultDialerClient{transportConfig: config, httpVersion: "2", client: &http.Client{Transport: packetUpRoundTripper(func(r *http.Request) (*http.Response, error) {
		trace := httptrace.ContextClientTrace(r.Context())
		if r.Method == "GET" {
			a, b := net.Pipe()
			trace.GotConn(httptrace.GotConnInfo{Conn: a})
			a.Close()
			b.Close()
		} else {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			if err := post(body); err != nil {
				return nil, err
			}
			trace.WroteRequest(httptrace.WroteRequestInfo{})
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
	})}}
	key := dialerConf{dest, stream}
	globalDialerAccess.Lock()
	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*XmuxManager)
	}
	globalDialerMap[key] = NewXmuxManager(XmuxConfig{}, func() XmuxConn { return client })
	globalDialerAccess.Unlock()
	conn, err := Dial(context.Background(), dest, stream)
	if err != nil {
		t.Fatal(err)
	}
	<-conn.(*splitConn).reader.(*WaitReadCloser).Wait
	t.Cleanup(func() {
		conn.Close()
		globalDialerAccess.Lock()
		delete(globalDialerMap, key)
		globalDialerAccess.Unlock()
	})
	return conn
}

func TestPacketUpRefillSaturated(t *testing.T) {
	errors.LogDebug(context.Background(), "testing packet-up refill")
	synctest.Test(t, func(t *testing.T) {
		packets := make(chan []byte, 1)
		release := make(chan struct{})
		defer close(release)
		conn := packetRefillConn(t, func(b []byte) error { packets <- b; <-release; return nil })
		conn.Write([]byte{42})
		if first := <-packets; !bytes.Equal(first, []byte{42}) {
			t.Fatalf("seed body %v", first)
		}
		data := make([]byte, 12*24576+17)
		for i := range data {
			data[i] = byte(i*31 + i/8192)
		}
		written := make(chan error, 1)
		go func() {
			n, err := conn.Write(data)
			if err == nil && n != len(data) {
				err = fmt.Errorf("write %d/%d", n, len(data))
			}
			written <- err
		}()
		var got []byte
		var lengths []int
		for len(got) < len(data) {
			synctest.Wait()
			if len(got) == 0 && conn.(*splitConn).writer.(uploadWriter).Len() != 24576 {
				t.Error("seed queue was not three full buffers")
			}
			release <- struct{}{}
			body := <-packets
			lengths = append(lengths, len(body))
			got = append(got, body...)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("payload mismatch")
		}
		for i, n := range lengths {
			want := min(18000, len(data)-i*18000)
			if n != want {
				t.Errorf("POST %d=%d want=%d; sizes=%v", i, n, want, lengths)
				break
			}
		}
		for i := 0; i+1 < len(lengths)-1; i += 2 {
			if lengths[i]+lengths[i+1] == 24576 {
				t.Errorf("forced batch pair at %d: %v", i, lengths)
				break
			}
		}
	})
}

func TestPacketUpRefillShortWrite(t *testing.T) {
	errors.LogDebug(context.Background(), "testing packet-up short write")
	synctest.Test(t, func(t *testing.T) {
		packets := make(chan []byte, 8)
		conn := packetRefillConn(t, func(b []byte) error { packets <- b; return nil })
		for _, size := range []int{17, 24576, 1} {
			start := time.Now()
			data := bytes.Repeat([]byte{byte(size)}, size)
			if _, err := conn.Write(data); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			var got []byte
			for len(packets) > 0 {
				got = append(got, <-packets...)
			}
			// No follow-up Write, EOF or elapsed virtual time may be required.
			if !bytes.Equal(got, data) {
				t.Errorf("immediate body %d/%d", len(got), size)
			}
			if elapsed := time.Since(start); elapsed != 0 {
				t.Errorf("added idle wait: %v", elapsed)
			}
		}
	})
}

func TestPacketUpRefillOwnership(t *testing.T) {
	for _, state := range []string{"open", "closed", "interrupted", "error"} {
		t.Run(state, func(t *testing.T) {
			r, w := pipe.New(pipe.WithSizeLimit(18999))
			defer w.Close()
			data := bytes.Repeat([]byte{31}, 24576)
			queued := packetBuffers(data, buf.Size)
			refs := append(buf.MultiBuffer(nil), queued...)
			for _, b := range queued {
				if err := w.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
					t.Fatal(err)
				}
			}
			pending := packetBuffers(bytes.Repeat([]byte{17}, 6576), 17)
			owned := append(buf.MultiBuffer(nil), pending...)
			var wantErr error
			switch state {
			case "closed":
				w.Close()
			case "interrupted":
				r.Interrupt()
				wantErr = io.ErrClosedPipe
			case "error":
				mb, _ := r.TryReadMultiBuffer()
				buf.ReleaseMulti(mb)
				wantErr = fmt.Errorf("injected read failure")
				r.ReturnAnError(wantErr)
			}
			pending, err := refillPacketUp(r, pending, 18000)
			if err != wantErr {
				t.Fatalf("error=%v want=%v", err, wantErr)
			}
			if pending.Len() >= 2*19000+buf.Size {
				t.Fatalf("pending bound: %d", pending.Len())
			}
			if wantErr == nil {
				want := append(bytes.Repeat([]byte{17}, 6576), data...)
				if pending.String() != string(want) {
					t.Fatal("refill changed bytes")
				}
				seen := make(map[*buf.Buffer]bool)
				for _, b := range pending {
					if seen[b] {
						t.Fatal("duplicate ownership")
					}
					seen[b] = true
				}
				for _, b := range append(owned, refs...) {
					if !seen[b] {
						t.Fatal("lost original buffer")
					}
				}
			}
			buf.ReleaseMulti(pending)
			for _, b := range append(owned, refs...) {
				if b.Len() != 0 {
					t.Fatal("unreleased buffer")
				}
			}
		})
	}
	// EOF with a short pending tail must preserve that tail for the caller.
	r, w := pipe.New()
	w.Close()
	mb, err := refillPacketUp(r, packetBuffers([]byte("tail"), 2), 18000)
	defer buf.ReleaseMulti(mb)
	if err != io.EOF || mb.String() != "tail" {
		t.Fatalf("EOF tail: %q %v", mb.String(), err)
	}
}

func TestPacketUpRefillPostFailure(t *testing.T) {
	errors.LogDebug(context.Background(), "testing packet-up refill failure")
	synctest.Test(t, func(t *testing.T) {
		packets := make(chan []byte, 1)
		release := make(chan struct{})
		conn := packetRefillConn(t, func(b []byte) error { packets <- b; <-release; return fmt.Errorf("peer disconnected") })
		conn.Write([]byte{1})
		<-packets
		written := make(chan error, 1)
		go func() { _, err := conn.Write(make([]byte, 1<<20)); written <- err }()
		synctest.Wait()
		close(release)
		synctest.Wait()
		select {
		case err := <-written:
			if err != io.ErrClosedPipe {
				t.Fatalf("write error: %v", err)
			}
		default:
			t.Fatal("writer remains blocked after peer failure")
		}
	})
}
