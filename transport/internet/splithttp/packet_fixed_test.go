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

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

type packetUpRoundTripper func(*http.Request) (*http.Response, error)

func (f packetUpRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPacketUpFixedBuffering(t *testing.T) {
	// The global logger owns process-wide channels, outside the test bubble.
	errors.LogDebug(context.Background(), "testing fixed packet-up buffering")
	for _, tc := range []struct{ limit, queued, body int }{
		{64, 8192, 64}, {32768, 32768, 32768}, {1000000, 999424, 999424},
	} {
		t.Run(fmt.Sprint(tc.limit), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				packets := make(chan int, 1024)
				release := make(chan struct{})
				config := &Config{Mode: "packet-up", ScMaxEachPostBytes: &RangeConfig{From: int32(tc.limit), To: int32(tc.limit)},
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
						return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader([]byte{1})), Header: make(http.Header)}, nil
					}
					body, err := io.ReadAll(r.Body)
					if err != nil {
						return nil, err
					}
					packets <- len(body)
					<-release
					trace.WroteRequest(httptrace.WroteRequestInfo{})
					return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
				})}}
				key := dialerConf{dest, stream}
				globalDialerAccess.Lock()
				if globalDialerMap == nil {
					globalDialerMap = make(map[dialerConf]*XmuxManager)
				}
				globalDialerMap[key] = NewXmuxManager(XmuxConfig{}, func() XmuxConn { return client })
				globalDialerAccess.Unlock()
				defer func() { globalDialerAccess.Lock(); delete(globalDialerMap, key); globalDialerAccess.Unlock() }()
				conn, err := Dial(context.Background(), dest, stream)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				<-conn.(*splitConn).reader.(*WaitReadCloser).Wait
				if _, err := conn.Write(make([]byte, 64)); err != nil {
					t.Fatal(err)
				}
				if first := <-packets; first != 64 {
					t.Fatalf("seed POST=%d", first)
				}
				data := make([]byte, 2*tc.limit+8192)
				written := make(chan error, 1)
				go func() {
					n, e := conn.Write(data)
					if e == nil && n != len(data) {
						e = fmt.Errorf("accepted %d/%d", n, len(data))
					}
					written <- e
				}()
				// The first HTTP request is held until the writer is durably
				// blocked by the pipe, independent of OS scheduling or timing.
				synctest.Wait()
				if queued := conn.(*splitConn).writer.(uploadWriter).Len(); queued != int32(tc.queued) {
					t.Errorf("queue=%d want=%d", queued, tc.queued)
				}
				close(release)
				next := <-packets
				if next != tc.body {
					t.Errorf("full POST=%d want=%d", next, tc.body)
				}
				if err := <-written; err != nil {
					t.Fatal(err)
				}
				conn.Close()
				synctest.Wait()
				total := 64 + next
				for len(packets) > 0 {
					total += <-packets
				}
				if total != 64+len(data) {
					t.Fatalf("received %d/%d bytes", total, 64+len(data))
				}
			})
		})
	}
}
