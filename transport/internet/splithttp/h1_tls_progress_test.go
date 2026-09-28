package splithttp

import (
	"bufio"
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func h1TestTLSConfig(t *testing.T) (*gotls.Config, *gotls.Config) {
	t.Helper()
	certificate, _ := cert.MustGenerate(nil, cert.CommonName("localhost"))
	pemCert, pemKey := certificate.ToPEM()
	pair, err := gotls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		t.Fatal(err)
	}
	server := &gotls.Config{Certificates: []gotls.Certificate{pair}, MinVersion: gotls.VersionTLS13, MaxVersion: gotls.VersionTLS13}
	// net.Pipe fixture; this does not alter production verification settings.
	client := &gotls.Config{InsecureSkipVerify: true, ServerName: "localhost", MinVersion: gotls.VersionTLS13, MaxVersion: gotls.VersionTLS13}
	return server, client
}

type h1RecordCapture struct {
	net.Conn
	mu      sync.Mutex
	enabled bool
	data    []byte
	writes  []int
}

func (c *h1RecordCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.enabled {
		c.data = append(c.data, p...)
		c.writes = append(c.writes, len(p))
	}
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func TestH1TLSRecordBoundaries(t *testing.T) {
	serverConfig, clientConfig := h1TestTLSConfig(t)
	for _, version := range []uint16{gotls.VersionTLS12, gotls.VersionTLS13} {
		t.Run(fmt.Sprintf("version=%x", version), func(t *testing.T) {
			server, client := serverConfig.Clone(), clientConfig.Clone()
			server.MinVersion, server.MaxVersion = version, version
			client.MinVersion, client.MaxVersion = version, version
			server.CipherSuites = []uint16{gotls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, gotls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
			testH1TLSRecordBoundaries(t, server, client, version)
		})
	}
}

type h1RecordShape struct {
	Type   byte
	Length int
}

func testH1TLSRecordBoundaries(t *testing.T, serverConfig, clientConfig *gotls.Config, version uint16) {
	for _, chrome := range []bool{false, true} {
		t.Run(fmt.Sprintf("chrome=%v", chrome), func(t *testing.T) {
			var fingerprint *utls.ClientHelloID
			if chrome {
				fingerprint = &utls.HelloChrome_Auto
			}
			var results [2][]h1RecordShape
			var rawWrites [2][]int
			for variant := range 2 {
				synctest.Test(t, func(t *testing.T) {
					a, b := net.Pipe()
					capture := &h1RecordCapture{Conn: a}
					server := gotls.Server(b, serverConfig.Clone())
					peerDone := make(chan error, 1)
					bodies := [][]byte{bytes.Repeat([]byte{1}, 47), bytes.Repeat([]byte{2}, 196645), bytes.Repeat([]byte{3}, 32777)}
					go func() {
						defer server.Close()
						reader := bufio.NewReader(server)
						for _, want := range bodies {
							r, err := http.ReadRequest(reader)
							if err != nil {
								peerDone <- err
								return
							}
							body, err := io.ReadAll(r.Body)
							r.Body.Close()
							if err != nil || !bytes.Equal(body, want) {
								peerDone <- fmt.Errorf("body mismatch: %v", err)
								return
							}
							if _, err := fmt.Fprint(server, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"); err != nil {
								peerDone <- err
								return
							}
						}
						peerDone <- nil
					}()
					var conn net.Conn
					var err error
					if variant == 1 {
						conn, err = secureH1Upload(context.Background(), capture, clientConfig.Clone(), fingerprint)
					} else {
						var c xtls.Interface
						if chrome {
							c = xtls.UClient(capture, clientConfig.Clone(), fingerprint).(xtls.Interface)
						} else {
							c = xtls.Client(capture, clientConfig.Clone()).(xtls.Interface)
						}
						err = c.HandshakeContext(context.Background())
						conn = c
					}
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					capture.mu.Lock()
					capture.enabled = true
					capture.mu.Unlock()
					client := &DefaultDialerClient{httpVersion: "1.1", transportConfig: &Config{}, dialUploadConn: func(context.Context) (net.Conn, error) { return conn, nil }}
					defer client.Close()
					reader := bufio.NewReader(conn)
					for i, body := range bodies {
						req, err := http.NewRequest("POST", fmt.Sprintf("http://localhost/stable/%d", i), bytes.NewReader(body))
						if err != nil {
							t.Fatal(err)
						}
						if variant == 1 {
							err = client.postH1Packet(context.Background(), req, nil)
						} else {
							var serialized bytes.Buffer
							err = req.Write(&serialized)
							if err == nil {
								_, err = conn.Write(serialized.Bytes())
							}
							if err == nil {
								var resp *http.Response
								resp, err = http.ReadResponse(reader, req)
								if err == nil {
									_, err = io.Copy(io.Discard, resp.Body)
									resp.Body.Close()
								}
							}
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					if err := <-peerDone; err != nil {
						t.Fatal(err)
					}
					capture.mu.Lock()
					data := bytes.Clone(capture.data)
					rawWrites[variant] = append([]int(nil), capture.writes...)
					capture.enabled = false
					capture.mu.Unlock()
					for len(data) > 0 {
						if len(data) < 5 {
							t.Fatal("truncated record header")
						}
						n := int(binary.BigEndian.Uint16(data[3:5]))
						if len(data) < n+5 {
							t.Fatal("truncated record")
						}
						if data[0] != 23 {
							t.Logf("post-handshake record type=%d length=%d variant=%d", data[0], n, variant)
						}
						results[variant] = append(results[variant], h1RecordShape{data[0], n})
						data = data[n+5:]
					}
				})
			}
			if !reflect.DeepEqual(results[0], results[1]) {
				t.Fatalf("TLS fragments differ:\nreference %v\nprogress  %v", results[0], results[1])
			}
			if !reflect.DeepEqual(rawWrites[0], rawWrites[1]) {
				t.Fatalf("ciphertext Write partition differs: %v / %v", rawWrites[0], rawWrites[1])
			}
			found := false
			fullRecord := 16406
			if version == gotls.VersionTLS12 {
				fullRecord = 16413
			}
			for _, n := range rawWrites[1] {
				if n == fullRecord {
					found = true
				}
			}
			if !found {
				t.Fatalf("did not cover full record of %d bytes", fullRecord)
			}
			t.Logf("same 3 request bodies/history: %d identical record lengths and ciphertext Writes: %v", len(results[1]), results[1])
		})
	}
}

func TestH1TLSProgressDeadlines(t *testing.T) {
	for _, mode := range []string{"idle", "external", "external-during", "clear-during", "close"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := net.Pipe()
				defer b.Close()
				conn := &h1TLSWriteProgress{Conn: a, armed: true}
				defer conn.Close()
				start := time.Now()
				want := h1WriteIdleTimeout
				if mode == "external" {
					conn.SetDeadline(start.Add(7 * time.Second))
					want = 7 * time.Second
				}
				result := make(chan error, 1)
				go func() { _, err := conn.Write(make([]byte, 16406)); result <- err }()
				synctest.Wait()
				if mode == "external-during" {
					conn.SetWriteDeadline(start.Add(7 * time.Second))
					want = 7 * time.Second
				}
				if mode == "clear-during" {
					conn.SetDeadline(time.Time{})
				}
				if mode == "close" {
					conn.Close()
					want = 0
				}
				if err := <-result; err == nil {
					t.Fatal("stalled ciphertext Write succeeded")
				}
				if time.Since(start) != want {
					t.Fatalf("elapsed=%v want=%v", time.Since(start), want)
				}
				if mode != "close" {
					// A raw deadline can be reset; TLS timeouts remain terminal and
					// are discarded by the H1 pool, rather than retried in-place.
					if err := conn.SetDeadline(time.Time{}); err != nil {
						t.Fatal(err)
					}
					go io.Copy(io.Discard, b)
					if _, err := conn.Write([]byte("reset")); err != nil {
						t.Fatal(err)
					}
				}
			})
		})
	}
}

func TestH1UploadHandshakeBound(t *testing.T) {
	_, config := h1TestTLSConfig(t)
	for _, chrome := range []bool{false, true} {
		for _, mode := range []string{"timeout", "cancel", "close", "deadline"} {
			t.Run(fmt.Sprintf("chrome=%v/%s", chrome, mode), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					a, b := net.Pipe()
					defer b.Close()
					peerDone := make(chan struct{})
					go func() { io.Copy(io.Discard, b); close(peerDone) }()
					client := &DefaultDialerClient{httpVersion: "1.1", transportConfig: &Config{}, dialUploadConn: func(ctx context.Context) (net.Conn, error) {
						var fp *utls.ClientHelloID
						if chrome {
							fp = &utls.HelloChrome_Auto
						}
						return secureH1Upload(ctx, a, config.Clone(), fp)
					}}
					defer client.Close()
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					if mode == "deadline" {
						var dc context.CancelFunc
						ctx, dc = context.WithTimeout(ctx, 7*time.Second)
						defer dc()
					}
					result := make(chan error, 1)
					start := time.Now()
					go func() {
						result <- client.PostPacket(ctx, "http://localhost/", "s", "0", packetBuffers([]byte("body"), 4))
					}()
					synctest.Wait()
					want := h1DialTimeout
					if mode == "deadline" {
						want = 7 * time.Second
					}
					if mode == "cancel" {
						cancel()
						want = 0
					}
					if mode == "close" {
						client.Close()
						want = 0
					}
					if err := <-result; err == nil {
						t.Fatal("silent handshake succeeded")
					}
					synctest.Wait()
					if time.Since(start) != want {
						t.Fatalf("elapsed=%v want=%v", time.Since(start), want)
					}
					select {
					case <-peerDone:
					default:
						t.Fatal("handshake raw connection leaked")
					}
					assertH1PhaseEmpty(t, client)
					if mode != "close" {
						client.dialUploadConn = h1PhaseSuccessPipe
						if err := client.PostPacket(context.Background(), "http://localhost/", "s", "1", packetBuffers([]byte("recover"), 4)); err != nil {
							t.Fatal(err)
						}
					}
				})
			})
		}
	}
}

func TestH1TLSProgressKeepsExternalDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := net.Pipe()
		conn := &h1TLSWriteProgress{Conn: a, armed: true}
		defer conn.Close()
		stop := make(chan struct{})
		peerDone := make(chan struct{})
		go func() {
			defer close(peerDone)
			defer b.Close()
			for range 3 {
				select {
				case <-time.After(20 * time.Second):
				case <-stop:
					return
				}
				if _, err := io.ReadFull(b, make([]byte, 16406)); err != nil {
					return
				}
			}
		}()
		start := time.Now()
		conn.SetWriteDeadline(start.Add(45 * time.Second))
		for i := range 3 {
			_, err := conn.Write(make([]byte, 16406))
			if i < 2 && err != nil {
				t.Fatal(err)
			}
			if i == 2 && err == nil {
				t.Fatal("progress overwrote external deadline")
			}
		}
		if time.Since(start) != 45*time.Second {
			t.Fatalf("elapsed=%v", time.Since(start))
		}
		close(stop)
		<-peerDone
	})
}

func TestH1TLSStallRecovery(t *testing.T) {
	serverConfig, clientConfig := h1TestTLSConfig(t)
	for _, mode := range []string{"write-idle", "write-cancel", "write-close", "write-deadline", "ack-idle", "ack-cancel", "ack-close", "ack-deadline"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				writeStall := strings.HasPrefix(mode, "write")
				release := make(chan struct{})
				peerDone := make(chan error, 2)
				dials := 0
				dial := func(ctx context.Context) (net.Conn, error) {
					dials++
					first := dials == 1
					a, b := net.Pipe()
					server := gotls.Server(b, serverConfig.Clone())
					go func() {
						defer server.Close()
						if err := server.Handshake(); err != nil {
							peerDone <- err
							return
						}
						if first && writeStall {
							<-release
						}
						r, err := http.ReadRequest(bufio.NewReader(server))
						if err == nil {
							var body []byte
							body, err = io.ReadAll(r.Body)
							r.Body.Close()
							if !first && (err != nil || string(body) != "recover") {
								peerDone <- fmt.Errorf("recovery payload: %q %v", body, err)
								return
							}
						}
						if first {
							if !writeStall {
								<-release
							}
							io.Copy(io.Discard, server)
							peerDone <- nil
							return
						}
						if err == nil {
							_, err = fmt.Fprint(server, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
						}
						peerDone <- err
					}()
					return secureH1Upload(ctx, a, clientConfig.Clone(), &utls.HelloChrome_Auto)
				}
				client := &DefaultDialerClient{httpVersion: "1.1", transportConfig: &Config{}, dialUploadConn: dial}
				defer func() { client.Close() }()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if strings.HasSuffix(mode, "deadline") {
					var dc context.CancelFunc
					ctx, dc = context.WithTimeout(ctx, 7*time.Second)
					defer dc()
				}
				result := make(chan error, 1)
				start := time.Now()
				go func() {
					result <- client.PostPacket(ctx, "http://localhost/", "s", "0", packetBuffers(make([]byte, 65536), 8192))
				}()
				synctest.Wait()
				want := h1ResponseIdleTimeout
				if writeStall {
					want = h1WriteIdleTimeout
				}
				if strings.HasSuffix(mode, "cancel") {
					cancel()
					want = 0
				}
				if strings.HasSuffix(mode, "close") {
					go client.Close()
					want = 0
				}
				if strings.HasSuffix(mode, "deadline") {
					want = 7 * time.Second
				}
				if err := <-result; err == nil {
					t.Fatal("stalled TLS upload succeeded")
				}
				elapsed := time.Since(start)
				if elapsed < want || elapsed > want+250*time.Millisecond {
					t.Fatalf("elapsed=%v expected %v plus bounded TLS Close", elapsed, want)
				}
				close(release)
				if err := <-peerDone; err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				assertH1PhaseEmpty(t, client)
				if strings.HasSuffix(mode, "close") {
					client = &DefaultDialerClient{httpVersion: "1.1", transportConfig: &Config{}, dialUploadConn: dial}
				}
				if err := client.PostPacket(context.Background(), "http://localhost/", "s", "1", packetBuffers([]byte("recover"), 4)); err != nil {
					t.Fatal(err)
				}
				if err := <-peerDone; err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				assertH1PhaseEmpty(t, client)
				if dials != 2 {
					t.Fatalf("recovery dials=%d", dials)
				}
			})
		})
	}
}
