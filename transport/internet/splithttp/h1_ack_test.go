package splithttp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// A Write completing is not an HTTP acknowledgement. Also, serializing a
// request into a bytes.Buffer must not fire the on-wire WroteRequest signal.
func TestH1PacketAcknowledgement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()
		client := &DefaultDialerClient{transportConfig: &Config{XPaddingBytes: &RangeConfig{From: 1, To: 1}},
			httpVersion:    "1.1",
			dialUploadConn: func(context.Context) (net.Conn, error) { return clientConn, nil }}
		defer client.Close()
		written := make(chan httptrace.WroteRequestInfo, 8)
		ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
			WroteRequest: func(info httptrace.WroteRequestInfo) { written <- info },
		})
		finished := make(chan error, 1)
		go func() {
			finished <- client.PostPacket(ctx, "http://localhost/", "session", "0", packetBuffers([]byte("payload"), 4))
		}()
		synctest.Wait()
		if len(written) != 0 {
			t.Error("WroteRequest fired before any socket bytes could be consumed")
		}
		requestRead := make(chan error, 1)
		go func() {
			r, err := http.ReadRequest(bufio.NewReader(serverConn))
			if err == nil {
				var body []byte
				body, err = io.ReadAll(r.Body)
				r.Body.Close()
				if err == nil && string(body) != "payload" {
					err = fmt.Errorf("bad payload %q", body)
				}
			}
			requestRead <- err
		}()
		if err := <-requestRead; err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if len(written) != 1 {
			t.Errorf("WroteRequest callbacks=%d want=1", len(written))
		}
		if len(finished) != 0 {
			t.Error("PostPacket returned success before the server sent an HTTP response")
		}
		go fmt.Fprint(serverConn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		synctest.Wait()
		select {
		case err := <-finished:
			if err != nil {
				t.Fatal(err)
			}
		default:
			t.Error("PostPacket did not complete after acknowledgement")
		}
	})
}

func TestH1PacketRejectResponse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		client := &DefaultDialerClient{transportConfig: &Config{}, httpVersion: "1.1",
			dialUploadConn: func(context.Context) (net.Conn, error) { return a, nil }}
		defer client.Close()
		go func() {
			r, err := http.ReadRequest(bufio.NewReader(b))
			if err != nil {
				return
			}
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
			fmt.Fprint(b, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
		}()
		if err := client.PostPacket(context.Background(), "http://localhost/", "session", "0", packetBuffers([]byte("payload"), 4)); err == nil {
			t.Error("PostPacket accepted a rejected upload")
		}
	})
}

type h1ObservedWrite struct {
	net.Conn
	afterWrite func(int, error)
}

func (c *h1ObservedWrite) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.afterWrite(n, err)
	return n, err
}

// The real TCP peer holds its second request in the socket receive queue.
// No custom finalizer closes the client: this exercises netFD's own finalizer.
func TestH1PacketGCPreservesQueuedRequest(t *testing.T) {
	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)
	oldProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(oldProcs)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	firstResponse := make(chan struct{})
	readSecond := make(chan struct{})
	peerResult := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			peerResult <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		for seq := 0; seq < 2; seq++ {
			if seq == 1 {
				<-readSecond
			}
			r, err := http.ReadRequest(reader)
			if err != nil {
				peerResult <- fmt.Errorf("read seq%d: %w", seq, err)
				return
			}
			body, err := io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil || string(body) != "payload" {
				peerResult <- fmt.Errorf("seq%d body=%q err=%v", seq, body, err)
				return
			}
			if _, err = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"); err != nil {
				peerResult <- err
				return
			}
			if seq == 0 {
				close(firstResponse)
			}
		}
		peerResult <- nil
	}()
	secondWrite := make(chan struct{})
	var writes, dials atomic.Int32
	var bytesWritten atomic.Int64
	client := &DefaultDialerClient{transportConfig: &Config{XPaddingBytes: &RangeConfig{From: 1, To: 1}}, httpVersion: "1.1",
		dialUploadConn: func(context.Context) (net.Conn, error) {
			dials.Add(1)
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				return nil, err
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			observed := &h1ObservedWrite{Conn: conn, afterWrite: func(n int, err error) {
				bytesWritten.Add(int64(n))
				if writes.Add(1) == 2 {
					close(secondWrite)
				}
			}}
			return observed, nil
		}}
	post := func(seq string) error {
		return client.PostPacket(context.Background(), "http://localhost/", "session", seq, packetBuffers([]byte("payload"), 4))
	}
	if err := post("0"); err != nil {
		t.Fatal(err)
	}
	<-firstResponse
	secondResult := make(chan error, 1)
	go func() { secondResult <- post("1") }()
	<-secondWrite
	var early bool
	select {
	case err := <-secondResult:
		early = true
		if err != nil {
			t.Errorf("early second return: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
	}
	// Two GCs clear the primary and victim pool caches. Additional collection
	// gives the actual netFD finalizer time to close any unreachable socket.
	for range 4 {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	close(readSecond)
	peerErr := <-peerResult
	t.Logf("dials=%d successful Write bytes=%d returnedBeforeAck=%v peer=%v", dials.Load(), bytesWritten.Load(), early, peerErr)
	if dials.Load() != 1 {
		t.Errorf("expected the same H1 connection; got %d", dials.Load())
	}
	if peerErr != nil {
		t.Errorf("GC lost a written request: %v", peerErr)
	}
	if early {
		t.Error("request completed without a server acknowledgement")
	} else if err := <-secondResult; err != nil {
		t.Error(err)
	}
	client.Close()
	runtime.KeepAlive(client)
}

func TestH1PacketResponseLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, response      string
		wantError, reusable bool
	}{
		{"chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nack\r\n0\r\n\r\n", false, true},
		{"close", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", false, false},
		{"truncated", "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nx", true, false},
		{"disconnect", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := net.Pipe()
				defer a.Close()
				defer b.Close()
				client := &DefaultDialerClient{transportConfig: &Config{XPaddingBytes: &RangeConfig{From: 1, To: 1}}, httpVersion: "1.1", dialUploadConn: func(context.Context) (net.Conn, error) { return a, nil }}
				serverDone := make(chan struct{})
				go func() {
					defer close(serverDone)
					r, err := http.ReadRequest(bufio.NewReader(b))
					if err != nil {
						return
					}
					io.Copy(io.Discard, r.Body)
					r.Body.Close()
					fmt.Fprint(b, tc.response)
					if tc.wantError {
						b.Close()
					}
				}()
				err := client.PostPacket(context.Background(), "http://localhost/", "session", "0", packetBuffers([]byte("payload"), 4))
				if (err != nil) != tc.wantError {
					t.Errorf("error=%v wantError=%v", err, tc.wantError)
				}
				<-serverDone
				pool := client.h1Uploads()
				pool.mu.Lock()
				idle := len(pool.idle)
				pool.mu.Unlock()
				if !tc.reusable && idle != 0 {
					t.Error("non-reusable connection returned to pool")
				}
				client.Close()
			})
		})
	}
}

type h1ShortWrite struct {
	net.Conn
	closed bool
}

func (c *h1ShortWrite) Write(p []byte) (int, error) { return len(p) / 2, nil }
func (c *h1ShortWrite) Close() error                { c.closed = true; return c.Conn.Close() }

func TestH1PacketShortSocketWrite(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := &h1ShortWrite{Conn: a}
	client := &DefaultDialerClient{transportConfig: &Config{}, httpVersion: "1.1", dialUploadConn: func(context.Context) (net.Conn, error) { return c, nil }}
	if err := client.PostPacket(context.Background(), "http://localhost/", "session", "0", packetBuffers([]byte("payload"), 4)); err != io.ErrShortWrite {
		t.Errorf("error=%v want short write", err)
	}
	if !c.closed {
		t.Error("short write connection not closed")
	}
}
