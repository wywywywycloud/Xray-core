package splithttp

import (
	"bufio"
	"context"
	"crypto/sha256"
	gotls "crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

type progressTrackedConn struct {
	net.Conn
	live *atomic.Int32
	once sync.Once
}

func (c *progressTrackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.live.Add(-1) })
	return err
}

// Opt-in wall-clock regression: actual TCP, no relay, no mock deadlines. The
// client must receive an HTTP acknowledgement, not just enqueue a valid body.
func TestH1ProgressRealTCP(t *testing.T) {
	if os.Getenv("H1_PROGRESS_TCP") != "1" {
		t.Skip("set H1_PROGRESS_TCP=1 for the 64/128-second real TCP regressions")
	}
	serverTLS, clientTLS := h1TestTLSConfig(t)
	for _, tc := range []struct {
		name           string
		narrow         bool
		size, parallel int
		rate           int64
		secure         bool
	}{
		{"default-64s", false, 1 << 20, 1, 16384, false},
		{"narrow-128s", true, 1 << 20, 1, 8192, false},
		{"queue-31-128s", true, 32768, 31, 512, false},
		{"chrome-tls-64s", true, 1 << 20, 1, 16384, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			data := make([]byte, tc.size)
			for i := range data {
				data[i] = byte(i*31 + 7)
			}
			want := sha256.Sum256(data)
			peerDone := make(chan error, tc.parallel+1)
			var serverLive, clientLive, clientPeak, dials atomic.Int32
			go func() {
				for range tc.parallel + 1 {
					c, err := listener.Accept()
					if err != nil {
						return
					}
					serverLive.Add(1)
					if tc.narrow {
						c.(*net.TCPConn).SetReadBuffer(16384)
					}
					if tc.secure {
						c = gotls.Server(c, serverTLS.Clone())
					}
					go func() {
						defer serverLive.Add(-1)
						defer c.Close()
						c.SetDeadline(time.Now().Add(180 * time.Second))
						r, err := http.ReadRequest(bufio.NewReader(c))
						if err != nil {
							peerDone <- err
							return
						}
						defer r.Body.Close()
						slow := strings.Contains(r.URL.Path, "slow")
						start := time.Now()
						h := sha256.New()
						var total int64
						block := make([]byte, 4096)
						for {
							n, e := r.Body.Read(block)
							if n > 0 {
								h.Write(block[:n])
								total += int64(n)
								if slow {
									time.Sleep(time.Until(start.Add(time.Duration(total) * time.Second / time.Duration(tc.rate))))
								}
							}
							if e != nil {
								if e != io.EOF {
									err = e
								}
								break
							}
						}
						if err == nil && (total != int64(len(data)) || fmt.Sprintf("%x", h.Sum(nil)) != fmt.Sprintf("%x", want)) {
							err = fmt.Errorf("body mismatch: %d bytes", total)
						}
						t.Logf("server path=%s bytes=%d sha256=%x error=%v", r.URL.Path, total, h.Sum(nil), err)
						if err == nil {
							_, err = fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
						}
						if err == nil {
							_, err = io.Copy(io.Discard, c)
						}
						peerDone <- err
					}()
				}
			}()
			client := &DefaultDialerClient{httpVersion: "1.1", transportConfig: &Config{}, dialUploadConn: func(ctx context.Context) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
				if err != nil {
					return nil, err
				}
				if tc.narrow {
					c.(*net.TCPConn).SetWriteBuffer(16384)
				}
				dials.Add(1)
				n := clientLive.Add(1)
				for old := clientPeak.Load(); n > old; old = clientPeak.Load() {
					if clientPeak.CompareAndSwap(old, n) {
						break
					}
				}
				tracked := &progressTrackedConn{Conn: c, live: &clientLive}
				if tc.secure {
					return secureH1Upload(ctx, tracked, clientTLS.Clone(), &utls.HelloChrome_Auto)
				}
				return tracked, nil
			}}
			defer client.Close()
			for _, phase := range []string{"slow", "recovery"} {
				ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
				start := time.Now()
				count := 1
				if phase == "slow" {
					count = tc.parallel
				}
				results := make(chan error, count)
				for i := range count {
					go func() {
						results <- client.PostPacket(ctx, "http://localhost/"+phase+"/", "s", fmt.Sprint(i), packetBuffers(data, 8192))
					}()
				}
				if count > 1 {
					time.Sleep(35 * time.Second)
					t.Logf("queue at 35s: dials=%d client_sockets=%d peak=%d results=%d", dials.Load(), clientLive.Load(), clientPeak.Load(), len(results))
					if dials.Load() != 30 || clientLive.Load() != 30 || clientPeak.Load() != 30 || len(results) != 0 {
						t.Error("queue did not retain 31st POST behind exactly 30 sockets")
					}
				}
				for range count {
					if err := <-results; err != nil {
						t.Errorf("%s: %v", phase, err)
					}
				}
				elapsed := time.Since(start)
				cancel()
				t.Logf("phase=%s elapsed=%s completed_POSTs=%d live=%d", phase, elapsed, count, clientLive.Load())
				if phase == "slow" && elapsed < time.Duration(tc.size)*time.Second/time.Duration(tc.rate)-time.Second {
					t.Error("returned before paced body and ACK")
				}
				// A failed old client can leave buffered bytes at the peer. Wait
				// for that peer separately: its digest never substitutes for ACK.
				for range count {
					select {
					case e := <-peerDone:
						if e != nil {
							t.Errorf("%s peer: %v", phase, e)
						}
					case <-time.After(140 * time.Second):
						t.Fatal("peer did not naturally finish")
					}
				}
				p := client.h1Uploads()
				p.mu.Lock()
				retained := len(p.conns) + len(p.idle) + len(p.idleTimers)
				p.mu.Unlock()
				if retained != 0 || len(p.slots) != 0 || clientLive.Load() != 0 {
					t.Errorf("%s retained=%d slots=%d sockets=%d", phase, retained, len(p.slots), clientLive.Load())
				}
			}
			deadline := time.Now().Add(time.Second)
			for serverLive.Load() != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if serverLive.Load() != 0 {
				t.Error("peer resources survived both requests")
			}
			if clientPeak.Load() > h1MaxConcurrentUploads {
				t.Errorf("peak=%d", clientPeak.Load())
			}
			t.Logf("cleanup before fixture shutdown: client_sockets=%d server_sockets=%d peak=%d", clientLive.Load(), serverLive.Load(), clientPeak.Load())
		})
	}
}
