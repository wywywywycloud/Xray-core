package splithttp_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	. "github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type packetSizeEntropy struct{ value atomic.Uint32 }

func (r *packetSizeEntropy) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r.value.Load())
	}
	return len(p), nil
}

// Keep controlled entropy in a subprocess, away from unrelated tests and TLS.
// Actual HTTP bodies are checked without a probabilistic diversity assertion.
func TestPacketUpPostSizes(t *testing.T) {
	if os.Getenv("XRAY_PACKET_SIZE_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestPacketUpPostSizes$", "-test.timeout=30s", "-test.v")
		cmd.Env = append(os.Environ(), "XRAY_PACKET_SIZE_CHILD=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v\n%s", err, output)
		}
		t.Log(string(output))
		return
	}
	entropy := new(packetSizeEntropy)
	rand.Reader = entropy
	for _, fixed := range []bool{false, true} {
		t.Run(fmt.Sprintf("fixed=%v", fixed), func(t *testing.T) {
			entropy.value.Store(0)
			type packet struct {
				seq  int
				body []byte
			}
			packets := make(chan packet, 256)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					return
				}
				parts := strings.Split(r.URL.Path, "/")
				seq, _ := strconv.Atoi(parts[len(parts)-1])
				packets <- packet{seq, body}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			addr := server.Listener.Addr().(*net.TCPAddr)
			limits := &RangeConfig{From: 64, To: 320}
			if fixed {
				limits = &RangeConfig{From: 127, To: 127}
			}
			conn, err := Dial(context.Background(), net.TCPDestination(net.LocalHostIP, net.Port(addr.Port)), &internet.MemoryStreamConfig{
				ProtocolName: "splithttp",
				ProtocolSettings: &Config{Path: "/sizes/", Mode: "packet-up", ScMaxEachPostBytes: limits,
					ScMinPostsIntervalMs: &RangeConfig{From: 0, To: 1}, XPaddingBytes: &RangeConfig{From: 1, To: 1}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			seq := 0
			for batch, size := range []int{2048, 2048, 17, 1025} {
				cap := 64
				if batch > 0 {
					entropy.value.Store(255)
					cap = 319
				}
				if fixed {
					cap = 127
				}
				want := make([]byte, size)
				for i := range want {
					want[i] = byte(i + batch)
				}
				if n, err := conn.Write(want); err != nil || n != size {
					t.Fatalf("write: %d, %v", n, err)
				}
				if batch == 3 {
					// Closing the writer must still drain the queued final batch.
					if err := conn.Close(); err != nil {
						t.Fatal(err)
					}
				}
				got := make([]byte, 0, size)
				pending := map[int][]byte{}
				for len(got) < size {
					select {
					case p := <-packets:
						pending[p.seq] = p.body
					case <-time.After(3 * time.Second):
						t.Fatalf("batch %d: timeout after %d/%d bytes", batch, len(got), size)
					}
					for pending[seq] != nil {
						body := pending[seq]
						wantLen := min(cap, size-len(got))
						if len(body) != wantLen {
							t.Fatalf("batch %d seq %d: body=%d want=%d", batch, seq, len(body), wantLen)
						}
						got = append(got, body...)
						delete(pending, seq)
						seq++
					}
				}
				if !bytes.Equal(got, want) {
					t.Fatal("payload corrupted")
				}
			}
		})
	}
}

func TestPacketUpCloseAndPeerFailure(t *testing.T) {
	for _, peerFailure := range []bool{false, true} {
		t.Run(fmt.Sprintf("peerFailure=%v", peerFailure), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				}
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			addr := server.Listener.Addr().(*net.TCPAddr)
			pin := sha256.Sum256(server.Certificate().Raw)
			conn, err := Dial(ctx, net.TCPDestination(net.LocalHostIP, net.Port(addr.Port)), &internet.MemoryStreamConfig{
				ProtocolName:     "splithttp",
				SecurityType:     "tls",
				SecuritySettings: &tls.Config{PinnedPeerCertSha256: [][]byte{pin[:]}, NextProtocol: []string{"h2"}},
				ProtocolSettings: &Config{Mode: "packet-up", ScMaxEachPostBytes: &RangeConfig{From: 64, To: 320},
					ScMinPostsIntervalMs: &RangeConfig{From: 0, To: 1}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if !peerFailure {
				// The caller closes the connection on cancellation; HTTP requests
				// deliberately use context.WithoutCancel in the existing transport.
				cancel()
				if err := conn.Close(); err != nil {
					t.Fatal(err)
				}
			}
			result := make(chan error, 1)
			go func() { _, e := conn.Write(make([]byte, 1<<20)); result <- e }()
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("write unexpectedly succeeded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("writer remained blocked")
			}
		})
	}
}
