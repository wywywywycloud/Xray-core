package splithttp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

func TestH1PoolCancellation(t *testing.T) {
	for _, body := range []bool{false, true} {
		for _, closeClient := range []bool{false, true} {
			t.Run(fmt.Sprintf("body=%v/close=%v", body, closeClient), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ready := make(chan struct{})
					peerDone := make(chan struct{})
					var dials atomic.Int32
					client := &DefaultDialerClient{httpVersion: "1.1", transportConfig: &Config{}, dialUploadConn: func(context.Context) (net.Conn, error) {
						a, b := net.Pipe()
						id := dials.Add(1)
						go func() {
							defer b.Close()
							r, err := http.ReadRequest(bufio.NewReader(b))
							if err != nil {
								return
							}
							io.Copy(io.Discard, r.Body)
							r.Body.Close()
							if id == 1 {
								if body {
									fmt.Fprint(b, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n")
								}
								close(ready)
								io.Copy(io.Discard, b)
								close(peerDone)
							} else {
								fmt.Fprint(b, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
							}
						}()
						return a, nil
					}}
					defer client.Close()
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					result := make(chan error, 1)
					go func() {
						result <- client.PostPacket(ctx, "http://localhost/", "s", "0", packetBuffers([]byte("body"), 4))
					}()
					<-ready
					start := time.Now()
					if closeClient {
						client.Close()
					} else {
						cancel()
					}
					synctest.Wait()
					select {
					case err := <-result:
						if err == nil {
							t.Error("cancelled POST succeeded")
						}
					default:
						t.Fatal("POST stuck after cancellation")
					}
					select {
					case <-peerDone:
					default:
						t.Fatal("peer connection was not closed")
					}
					if time.Since(start) != 0 {
						t.Fatal("cancellation needed timeout")
					}
					p := client.h1Uploads()
					p.mu.Lock()
					remaining := len(p.conns) + len(p.idle)
					p.mu.Unlock()
					if remaining != 0 || len(p.slots) != 0 {
						t.Fatalf("retained resources: conns+idle=%d slots=%d", remaining, len(p.slots))
					}
					if closeClient {
						if !client.IsClosed() {
							t.Error("closed client still available")
						}
					} else {
						if err := client.PostPacket(context.Background(), "http://localhost/", "s", "1", packetBuffers([]byte("next"), 4)); err != nil {
							t.Fatalf("recovery: %v", err)
						}
						if dials.Load() != 2 {
							t.Errorf("recovery dials=%d", dials.Load())
						}
					}
				})
			})
		}
	}
}

func TestH1PoolIdleExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		peerDone := make(chan struct{})
		client := &DefaultDialerClient{httpVersion: "1.1", transportConfig: &Config{}, dialUploadConn: func(context.Context) (net.Conn, error) {
			a, b := net.Pipe()
			go func() {
				defer b.Close()
				defer close(peerDone)
				r, err := http.ReadRequest(bufio.NewReader(b))
				if err != nil {
					return
				}
				io.Copy(io.Discard, r.Body)
				r.Body.Close()
				fmt.Fprint(b, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
				io.Copy(io.Discard, b)
			}()
			return a, nil
		}}
		defer client.Close()
		if err := client.PostPacket(context.Background(), "http://localhost/", "s", "0", packetBuffers([]byte("body"), 4)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(xnet.ConnIdleTimeout)
		synctest.Wait()
		select {
		case <-peerDone:
		default:
			t.Fatal("idle peer remains open")
		}
		p := client.h1Uploads()
		p.mu.Lock()
		remaining := len(p.conns) + len(p.idle) + len(p.idleTimers)
		p.mu.Unlock()
		if remaining != 0 {
			t.Fatal("expired connection retained")
		}
	})
}

func TestH1PoolBoundAndClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var dials, peers atomic.Int32
		client := &DefaultDialerClient{httpVersion: "1.1", transportConfig: &Config{}, dialUploadConn: func(context.Context) (net.Conn, error) {
			dials.Add(1)
			a, b := net.Pipe()
			go func() {
				defer b.Close()
				defer peers.Add(1)
				r, err := http.ReadRequest(bufio.NewReader(b))
				if err != nil {
					return
				}
				io.Copy(io.Discard, r.Body)
				r.Body.Close()
				io.Copy(io.Discard, b)
			}()
			return a, nil
		}}
		const count = h1MaxConcurrentUploads + 4
		results := make(chan error, count)
		for i := range count {
			go func() {
				results <- client.PostPacket(context.Background(), "http://localhost/", "s", fmt.Sprint(i), packetBuffers([]byte("body"), 4))
			}()
		}
		synctest.Wait()
		if dials.Load() != h1MaxConcurrentUploads {
			t.Errorf("open connections=%d want=%d", dials.Load(), h1MaxConcurrentUploads)
		}
		if len(results) != 0 {
			t.Error("unacknowledged calls returned")
		}
		start := time.Now()
		client.Close()
		synctest.Wait()
		if len(results) != count {
			t.Fatalf("completed=%d want=%d", len(results), count)
		}
		for range count {
			if <-results == nil {
				t.Error("closed POST succeeded")
			}
		}
		if peers.Load() != h1MaxConcurrentUploads {
			t.Errorf("closed peers=%d", peers.Load())
		}
		if time.Since(start) != 0 {
			t.Fatal("Close waited for timeout")
		}
		p := client.h1Uploads()
		p.mu.Lock()
		remaining := len(p.conns) + len(p.idle)
		p.mu.Unlock()
		if remaining != 0 || len(p.slots) != 0 {
			t.Fatal("pool retained resources")
		}
	})
}

func TestH1PoolResponseDeadline(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(fmt.Sprint(body), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client := &DefaultDialerClient{httpVersion: "1.1", transportConfig: &Config{}, dialUploadConn: func(context.Context) (net.Conn, error) {
					a, b := net.Pipe()
					go func() {
						defer b.Close()
						r, err := http.ReadRequest(bufio.NewReader(b))
						if err != nil {
							return
						}
						io.Copy(io.Discard, r.Body)
						r.Body.Close()
						if body {
							fmt.Fprint(b, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
						}
						io.Copy(io.Discard, b)
					}()
					return a, nil
				}}
				defer client.Close()
				start := time.Now()
				err := client.PostPacket(context.Background(), "http://localhost/", "s", "0", packetBuffers([]byte("body"), 4))
				if err == nil {
					t.Fatal("stalled response succeeded")
				}
				if elapsed := time.Since(start); elapsed != h1ResponseIdleTimeout {
					t.Fatalf("elapsed=%v bound=%v", elapsed, h1ResponseIdleTimeout)
				}
				synctest.Wait()
				assertH1PhaseEmpty(t, client)
				client.dialUploadConn = h1PhaseSuccessPipe
				if err := client.PostPacket(context.Background(), "http://localhost/", "s", "1", packetBuffers([]byte("recover"), 4)); err != nil {
					t.Fatal(err)
				}
				assertH1PhaseEmpty(t, client)
			})
		})
	}
}
