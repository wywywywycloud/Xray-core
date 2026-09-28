package splithttp

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func TestH1PacketRotationDrain(t *testing.T) {
	errors.LogDebug(context.Background(), "testing H1 rotation drain")
	for _, limit := range []int32{2, 3, 100} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				config := &Config{Mode: "packet-up", ScMaxEachPostBytes: &RangeConfig{From: 64, To: 64},
					ScMinPostsIntervalMs: &RangeConfig{From: 0, To: 1}, XPaddingBytes: &RangeConfig{From: 1, To: 1}}
				stream := &internet.MemoryStreamConfig{ProtocolName: "splithttp", ProtocolSettings: config}
				dest := xnet.TCPDestination(xnet.LocalHostIP, 80)
				release := make(chan struct{})
				var mu sync.Mutex
				packets := make(map[int][]byte)
				used := make(map[*DefaultDialerClient]bool)
				acknowledged := 0
				var clients []*DefaultDialerClient
				var owned []*XmuxClient
				manager := NewXmuxManager(XmuxConfig{HMaxRequestTimes: &RangeConfig{From: limit, To: limit}}, func() XmuxConn {
					client := &DefaultDialerClient{transportConfig: config, httpVersion: "1.1"}
					client.client = &http.Client{Transport: packetUpRoundTripper(func(r *http.Request) (*http.Response, error) {
						a, b := net.Pipe()
						httptrace.ContextClientTrace(r.Context()).GotConn(httptrace.GotConnInfo{Conn: a})
						a.Close()
						b.Close()
						return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
					})}
					client.dialUploadConn = func(context.Context) (net.Conn, error) {
						a, b := net.Pipe()
						go func() {
							defer b.Close()
							r, err := http.ReadRequest(bufio.NewReader(b))
							if err != nil {
								return
							}
							data, err := io.ReadAll(r.Body)
							r.Body.Close()
							if err != nil {
								return
							}
							parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
							seq, err := strconv.Atoi(parts[len(parts)-1])
							if err != nil {
								t.Error(err)
								return
							}
							mu.Lock()
							packets[seq] = data
							used[client] = true
							mu.Unlock()
							<-release
							_, err = fmt.Fprint(b, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
							if err == nil {
								mu.Lock()
								acknowledged++
								mu.Unlock()
							}
						}()
						return a, nil
					}
					clients = append(clients, client)
					return client
				})
				key := dialerConf{dest, stream}
				globalDialerAccess.Lock()
				if globalDialerMap == nil {
					globalDialerMap = make(map[dialerConf]*XmuxManager)
				}
				globalDialerMap[key] = manager
				globalDialerAccess.Unlock()
				defer func() {
					globalDialerAccess.Lock()
					delete(globalDialerMap, key)
					globalDialerAccess.Unlock()
					for _, c := range clients {
						c.Close()
					}
				}()
				conn, err := Dial(context.Background(), dest, stream)
				if err != nil {
					t.Fatal(err)
				}
				<-conn.(*splitConn).reader.(*WaitReadCloser).Wait
				var shared net.Conn
				if limit == 100 {
					shared, err = Dial(context.Background(), dest, stream)
					if err != nil {
						t.Fatal(err)
					}
					<-shared.(*splitConn).reader.(*WaitReadCloser).Wait
					defer shared.Close()
					if len(clients) != 1 {
						t.Fatal("streams did not share a client")
					}
				}
				// More than the cross-rotation cap: the tail must wait for ACKs,
				// then drain even after closing the logical stream.
				data := make([]byte, 36*64)
				for i := range data {
					data[i] = byte(i*17 + 5)
				}
				if n, err := conn.Write(data); err != nil || n != len(data) {
					t.Fatalf("write %d: %v", n, err)
				}
				synctest.Wait()
				mu.Lock()
				sent := len(packets)
				mu.Unlock()
				if sent != h1MaxConcurrentUploads {
					t.Errorf("before ACK: POSTs=%d want=%d", sent, h1MaxConcurrentUploads)
				}
				if limit < 100 && len(clients) < 3 {
					t.Error("did not exercise several rotations")
				}
				globalDialerAccess.Lock()
				owned = append(owned, manager.xmuxClients...)
				// Force current client retirement while it still has queued work.
				for _, c := range owned {
					c.NotUsed.Store(true)
					c.maybeClose()
				}
				globalDialerAccess.Unlock()
				start := time.Now()
				conn.Close()
				synctest.Wait()
				for _, c := range clients {
					if used[c] && c.IsClosed() {
						t.Error("retirement closed client before ACK")
					}
				}
				close(release)
				synctest.Wait()
				if time.Since(start) != 0 {
					t.Error("drain needed a timeout")
				}
				mu.Lock()
				var received []byte
				for i := 0; i < len(packets); i++ {
					received = append(received, packets[i]...)
				}
				if !bytes.Equal(received, data) || acknowledged != 36 {
					t.Errorf("received=%d/%d ACKs=%d/36", len(received), len(data), acknowledged)
				}
				mu.Unlock()
				if shared != nil {
					if clients[0].IsClosed() {
						t.Fatal("closing one stream closed its shared client")
					}
					if _, err := shared.Write([]byte{42}); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					mu.Lock()
					if acknowledged != 37 || !bytes.Equal(packets[0], []byte{42}) {
						t.Error("surviving stream could not upload")
					}
					mu.Unlock()
					shared.Close()
					synctest.Wait()
				}
				for _, c := range owned {
					if c.Running.Load() != 0 || c.leases.Load() != 0 {
						t.Error("retained XMUX references")
					}
				}
			})
		})
	}
}
