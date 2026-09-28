package splithttp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func h1PhaseSuccessPipe(context.Context) (net.Conn, error) {
	a, b := net.Pipe()
	go func() {
		defer b.Close()
		r, err := http.ReadRequest(bufio.NewReader(b))
		if err != nil {
			return
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		fmt.Fprint(b, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}()
	return a, nil
}

func assertH1PhaseEmpty(t *testing.T, client *DefaultDialerClient) {
	t.Helper()
	p := client.h1Uploads()
	p.mu.Lock()
	retained := len(p.conns) + len(p.idle) + len(p.idleTimers)
	p.mu.Unlock()
	if retained != 0 || len(p.slots) != 0 {
		t.Fatalf("retained=%d slots=%d", retained, len(p.slots))
	}
}

func TestH1PhaseQueueAndProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var live, peak, dials atomic.Int32
		client := &DefaultDialerClient{httpVersion: "1.1", transportConfig: &Config{}, dialUploadConn: func(context.Context) (net.Conn, error) {
			a, b := net.Pipe()
			dials.Add(1)
			n := live.Add(1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			go func() {
				defer b.Close()
				r, err := http.ReadRequest(bufio.NewReader(b))
				if err != nil {
					return
				}
				defer r.Body.Close()
				block := make([]byte, 4096)
				total := 0
				for {
					n, e := r.Body.Read(block)
					total += n
					if n > 0 {
						time.Sleep(4 * time.Second)
					}
					if e != nil {
						if e != io.EOF {
							return
						}
						break
					}
				}
				if total != 65536 {
					t.Errorf("body=%d", total)
				}
				fmt.Fprint(b, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			}()
			return &progressTrackedConn{Conn: a, live: &live}, nil
		}}
		defer client.Close()
		results := make(chan error, h1MaxConcurrentUploads+1)
		for i := range h1MaxConcurrentUploads + 1 {
			go func() {
				results <- client.PostPacket(context.Background(), "http://localhost/", "s", fmt.Sprint(i), packetBuffers(make([]byte, 65536), 8192))
			}()
		}
		synctest.Wait()
		if dials.Load() != h1MaxConcurrentUploads {
			t.Fatalf("dials=%d", dials.Load())
		}
		time.Sleep(40 * time.Second)
		synctest.Wait()
		if len(results) != 0 {
			t.Errorf("%d requests expired or succeeded before complete bodies/ACKs", len(results))
		}
		for range h1MaxConcurrentUploads + 1 {
			if err := <-results; err != nil {
				t.Error(err)
			}
		}
		synctest.Wait()
		if peak.Load() > h1MaxConcurrentUploads || live.Load() != 0 {
			t.Errorf("peak=%d live=%d", peak.Load(), live.Load())
		}
		assertH1PhaseEmpty(t, client)
	})
}

func TestH1PhaseResponseProgress(t *testing.T) {
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
				time.Sleep(45 * time.Second)
				fmt.Fprint(b, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n")
				for range 4 {
					time.Sleep(100 * time.Second)
					if _, err := b.Write([]byte{1}); err != nil {
						return
					}
				}
			}()
			return a, nil
		}}
		defer client.Close()
		start := time.Now()
		if err := client.PostPacket(context.Background(), "http://localhost/", "s", "0", packetBuffers([]byte("body"), 4)); err != nil {
			t.Fatal(err)
		}
		if time.Since(start) != 445*time.Second {
			t.Fatalf("duration=%v", time.Since(start))
		}
		assertH1PhaseEmpty(t, client)
	})
}

func TestH1PhaseDialDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &DefaultDialerClient{httpVersion: "1.1", transportConfig: &Config{}, dialUploadConn: func(ctx context.Context) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }}
		defer client.Close()
		start := time.Now()
		err := client.PostPacket(context.Background(), "http://localhost/", "s", "0", packetBuffers([]byte("body"), 4))
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != h1DialTimeout {
			t.Fatalf("error=%v duration=%v", err, time.Since(start))
		}
		assertH1PhaseEmpty(t, client)
		client.dialUploadConn = h1PhaseSuccessPipe
		if err := client.PostPacket(context.Background(), "http://localhost/", "s", "1", packetBuffers([]byte("recover"), 4)); err != nil {
			t.Fatal(err)
		}
		assertH1PhaseEmpty(t, client)
	})
}

func TestH1PhaseWriteStall(t *testing.T) {
	for _, mode := range []string{"idle", "cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := net.Pipe()
				defer b.Close()
				client := &DefaultDialerClient{httpVersion: "1.1", transportConfig: &Config{}, dialUploadConn: func(context.Context) (net.Conn, error) { return a, nil }}
				defer client.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if mode == "deadline" {
					var deadlineCancel context.CancelFunc
					ctx, deadlineCancel = context.WithTimeout(ctx, 7*time.Second)
					defer deadlineCancel()
				}
				result := make(chan error, 1)
				start := time.Now()
				go func() {
					result <- client.PostPacket(ctx, "http://localhost/", "s", "0", packetBuffers(make([]byte, 65536), 8192))
				}()
				synctest.Wait()
				if mode == "cancel" {
					cancel()
				}
				if err := <-result; err == nil {
					t.Fatal("stalled write succeeded")
				}
				want := h1WriteIdleTimeout
				if mode == "cancel" {
					want = 0
				}
				if mode == "deadline" {
					want = 7 * time.Second
				}
				if time.Since(start) != want {
					t.Fatalf("elapsed=%v want=%v", time.Since(start), want)
				}
				if _, err := b.Read(make([]byte, 1)); err != io.EOF {
					t.Fatalf("peer after cleanup: %v", err)
				}
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

func TestH1PhaseCallerDeadline(t *testing.T) {
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
				io.Copy(io.Discard, b)
			}()
			return a, nil
		}}
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		defer cancel()
		start := time.Now()
		err := client.PostPacket(ctx, "http://localhost/", "s", "0", packetBuffers([]byte("body"), 4))
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != 7*time.Second {
			t.Fatalf("error=%v elapsed=%v", err, time.Since(start))
		}
		synctest.Wait()
		assertH1PhaseEmpty(t, client)
		client.dialUploadConn = h1PhaseSuccessPipe
		if err := client.PostPacket(context.Background(), "http://localhost/", "s", "1", packetBuffers([]byte("recover"), 4)); err != nil {
			t.Fatal(err)
		}
		assertH1PhaseEmpty(t, client)
	})
}
