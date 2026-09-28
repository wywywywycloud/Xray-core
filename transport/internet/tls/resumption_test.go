package tls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func resumptionFixture(t *testing.T, version uint16) (*gotls.Config, *Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "one.test"}, DNSNames: []string{"one.test", "two.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &gotls.Config{Certificates: []gotls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: version, MaxVersion: version}, &Config{ServerName: "one.test", EnableSessionResumption: true, DisableSystemRoot: true, Certificate: []*Certificate{{Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Usage: Certificate_AUTHORITY_VERIFY}}}
}

func resumptionServer(t *testing.T, cfg *gotls.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				s := gotls.Server(c, cfg)
				if s.Handshake() != nil {
					return
				}
				s.Write([]byte{42})
				var b [1]byte
				io.ReadFull(s, b[:])
			}()
		}
	}()
	return ln.Addr().String()
}

func resumptionDial(t *testing.T, addr string, cfg *gotls.Config, mode string, cache utls.ClientSessionCache) (bool, error) {
	resumed, _, err := resumptionProbe(t, addr, cfg, mode, cache)
	return resumed, err
}

type recordingConn struct {
	net.Conn
	wire bytes.Buffer
}

func (c *recordingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.wire.Write(p[:n])
	return n, err
}

func resumptionProbe(t *testing.T, addr string, cfg *gotls.Config, mode string, cache utls.ClientSessionCache) (bool, []byte, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, nil, err
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	recorded := &recordingConn{Conn: raw}
	raw = recorded
	var conn net.Conn
	var resumed func() bool
	switch mode {
	case "go":
		c := Client(raw, cfg).(*Conn)
		conn = c
		resumed = func() bool { return c.ConnectionState().DidResume }
	case "cache-only":
		ucfg := copyConfig(cfg)
		ucfg.ClientSessionCache = cache
		c := utls.UClient(raw, ucfg, utls.HelloChrome_Auto)
		conn = c
		resumed = func() bool { return c.ConnectionState().DidResume }
	default:
		c := UClient(raw, cfg, &utls.HelloChrome_Auto).(*UConn)
		conn = c
		resumed = func() bool { return c.ConnectionState().DidResume }
	}
	if err := conn.(interface{ HandshakeContext(context.Context) error }).HandshakeContext(context.Background()); err != nil {
		return false, recorded.wire.Bytes(), err
	}
	var b [1]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil {
		return false, recorded.wire.Bytes(), err
	}
	if b[0] != 42 {
		t.Fatal("payload corrupted")
	}
	conn.Write([]byte{1})
	return resumed(), recorded.wire.Bytes(), nil
}

// Parse bytes actually passed to TCP, independently of uTLS's handshake state.
func clientHelloExtensions(t *testing.T, wire []byte) ([]uint16, map[uint16][]byte) {
	t.Helper()
	var hello []byte
	for len(wire) >= 5 {
		n := int(binary.BigEndian.Uint16(wire[3:5]))
		if len(wire) < 5+n {
			t.Fatal("truncated record")
		}
		if wire[0] == 22 {
			hello = append(hello, wire[5:5+n]...)
		}
		wire = wire[5+n:]
	}
	if len(hello) < 39 || hello[0] != 1 {
		t.Fatal("missing ClientHello")
	}
	p := hello[4+2+32:]
	p = p[1+int(p[0]):]
	p = p[2+int(binary.BigEndian.Uint16(p)):]
	p = p[1+int(p[0]):]
	n := int(binary.BigEndian.Uint16(p))
	p = p[2 : 2+n]
	ids := []uint16{}
	extensions := map[uint16][]byte{}
	for len(p) > 0 {
		id := binary.BigEndian.Uint16(p)
		n := int(binary.BigEndian.Uint16(p[2:]))
		ids = append(ids, id)
		extensions[id] = p[4 : 4+n]
		p = p[4+n:]
	}
	return ids, extensions
}

func checkPSK(t *testing.T, wire []byte, expected bool) {
	t.Helper()
	ids, ext := clientHelloExtensions(t, wire)
	psk, ok := ext[41]
	if ok != expected {
		t.Fatalf("wire PSK=%v want=%v extensions=%v", ok, expected, ids)
	}
	if !ok {
		return
	}
	if ids[len(ids)-1] != 41 {
		t.Fatal("PSK must be last")
	}
	if len(psk) < 6 {
		t.Fatal("empty PSK")
	}
	identities := int(binary.BigEndian.Uint16(psk))
	if identities < 7 || 2+identities+3 > len(psk) {
		t.Fatal("invalid identities")
	}
	ticketLen := int(binary.BigEndian.Uint16(psk[2:]))
	if ticketLen == 0 || ticketLen+6 != identities {
		t.Fatal("expected one nonempty ticket")
	}
	binders := psk[2+identities:]
	if int(binary.BigEndian.Uint16(binders)) != len(binders)-2 {
		t.Fatal("binder vector length")
	}
	binder := binders[3:]
	if int(binders[2]) != len(binder) || (len(binder) != 32 && len(binder) != 48) || bytes.Equal(binder, make([]byte, len(binder))) {
		t.Fatal("invalid binder")
	}
	t.Logf("wire ClientHello: ticket=%d bytes binder=%d bytes PSK-last=true", ticketLen, len(binder))
}

func TestResumptionLifecycle(t *testing.T) {
	for _, version := range []uint16{gotls.VersionTLS12, gotls.VersionTLS13} {
		for _, mode := range []string{"go", "chrome"} {
			t.Run(mode+"/"+gotls.VersionName(version), func(t *testing.T) {
				server, client := resumptionFixture(t, version)
				addr := resumptionServer(t, server)
				dial := func(want bool, psk bool) {
					t.Helper()
					resumed, wire, err := resumptionProbe(t, addr, client.GetTLSConfig(), mode, nil)
					if err != nil {
						t.Fatal(err)
					}
					if resumed != want {
						t.Fatalf("resumed=%v want=%v", resumed, want)
					}
					if version == gotls.VersionTLS13 {
						checkPSK(t, wire, psk)
					}
				}
				dial(false, false)
				dial(true, true)
				var key [32]byte
				rand.Read(key[:])
				server.SetSessionTicketKeys([][32]byte{key})
				dial(false, true)
				dial(true, true) // rejected ticket falls back, fresh ticket then resumes
				client.EnableSessionResumption = false
				dial(false, false)
				dial(false, false)
			})
		}
	}
}

func TestResumptionIsolation(t *testing.T) {
	for _, mode := range []string{"go", "chrome"} {
		t.Run(mode, func(t *testing.T) {
			server, client := resumptionFixture(t, gotls.VersionTLS13)
			addr := resumptionServer(t, server)
			dial := func(address string, want bool) {
				t.Helper()
				r, wire, err := resumptionProbe(t, address, client.GetTLSConfig(), mode, nil)
				if err != nil {
					t.Fatal(err)
				}
				if r != want {
					t.Fatalf("resumed=%v want=%v", r, want)
				}
				checkPSK(t, wire, want)
			}
			dial(addr, false)
			dial(addr, true)
			// Same ticket keys and cert, distinct server port: no cross-endpoint offer.
			second := resumptionServer(t, server)
			dial(second, false)
			dial(second, true)
			client.ServerName = "two.test"
			dial(addr, false)
			dial(addr, true)
			client.NextProtocol = []string{"http/1.1"}
			dial(addr, false)
			dial(addr, true)
			pin := sha256.Sum256(server.Certificates[0].Certificate[0])
			client.PinnedPeerCertSha256 = [][]byte{pin[:]}
			dial(addr, false)
			dial(addr, true)
			client.PinnedPeerCertSha256 = [][]byte{make([]byte, 32)}
			_, wire, err := resumptionProbe(t, addr, client.GetTLSConfig(), mode, nil)
			if err == nil {
				t.Fatal("wrong pin accepted")
			}
			checkPSK(t, wire, false)
			client.PinnedPeerCertSha256 = nil
			client.ServerName = "wrong.test"
			_, wire, err = resumptionProbe(t, addr, client.GetTLSConfig(), mode, nil)
			if err == nil {
				t.Fatal("wrong SNI accepted")
			}
			checkPSK(t, wire, false)
			client.ServerName = "one.test"
			client.Certificate = nil
			_, wire, err = resumptionProbe(t, addr, client.GetTLSConfig(), mode, nil)
			if err == nil {
				t.Fatal("untrusted certificate accepted")
			}
			checkPSK(t, wire, false)
		})
	}
}

func TestResumptionRevalidatesPeer(t *testing.T) {
	for _, mode := range []string{"go", "chrome"} {
		t.Run(mode, func(t *testing.T) {
			server, client := resumptionFixture(t, gotls.VersionTLS13)
			addr := resumptionServer(t, server)
			cfg := client.GetTLSConfig()
			var calls atomic.Int32
			verify := cfg.VerifyPeerCertificate
			cfg.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error { calls.Add(1); return verify(raw, chains) }
			for i := 0; i < 2; i++ {
				r, err := resumptionDial(t, addr, cfg, mode, nil)
				if err != nil {
					t.Fatal(err)
				}
				if r != (i == 1) {
					t.Fatal("unexpected resumption")
				}
			}
			if calls.Load() != 2 {
				t.Fatalf("verifier invoked %d times want 2", calls.Load())
			}
			// A stricter verifier must still be enforced even on an otherwise valid ticket.
			cfg.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return errors.New("policy rejected") }
			if _, err := resumptionDial(t, addr, cfg, mode, nil); err == nil {
				t.Fatal("resumption bypassed verifier")
			}
		})
	}
}

func TestResumptionConcurrent(t *testing.T) {
	server, client := resumptionFixture(t, gotls.VersionTLS13)
	addr := resumptionServer(t, server)
	if _, err := resumptionDial(t, addr, client.GetTLSConfig(), "chrome", nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				r, err := resumptionDial(t, addr, client.GetTLSConfig(), "chrome", nil)
				if err != nil || !r {
					t.Errorf("resume=%v error=%v", r, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestResumptionVerifyNamesAndCAPin(t *testing.T) {
	for _, mode := range []string{"go", "chrome"} {
		t.Run(mode, func(t *testing.T) {
			server, client := resumptionFixture(t, gotls.VersionTLS13)
			caDER := server.Certificates[0].Certificate[0]
			ca, err := x509.ParseCertificate(caDER)
			if err != nil {
				t.Fatal(err)
			}
			leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"one.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, server.Certificates[0].PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			server.Certificates = []gotls.Certificate{{Certificate: [][]byte{der, caDER}, PrivateKey: leafKey}}
			addr := resumptionServer(t, server)
			client.ServerName = "front.test"
			client.VerifyPeerCertByName = []string{"one.test"}
			for i := 0; i < 2; i++ {
				r, err := resumptionDial(t, addr, client.GetTLSConfig(), mode, nil)
				if err != nil || r != (i == 1) {
					t.Fatalf("name policy resumed=%v err=%v", r, err)
				}
			}
			pin := sha256.Sum256(caDER)
			client.PinnedPeerCertSha256 = [][]byte{pin[:]}
			client.Certificate = nil
			for i := 0; i < 2; i++ {
				r, err := resumptionDial(t, addr, client.GetTLSConfig(), mode, nil)
				if err != nil || r != (i == 1) {
					t.Fatalf("CA pin resumed=%v err=%v", r, err)
				}
			}
			client.VerifyPeerCertByName = []string{"wrong.test"}
			_, wire, err := resumptionProbe(t, addr, client.GetTLSConfig(), mode, nil)
			if err == nil {
				t.Fatal("wrong verified name accepted")
			}
			checkPSK(t, wire, false)
			client.VerifyPeerCertByName = nil
			client.ServerName = "one.test"
			for i := 0; i < 2; i++ {
				r, err := resumptionDial(t, addr, client.GetTLSConfig(), mode, nil)
				if err != nil || r != (i == 1) {
					t.Fatalf("CA pin with SNI resumed=%v err=%v", r, err)
				}
			}
			client.ServerName = "wrong.test"
			if _, err := resumptionDial(t, addr, client.GetTLSConfig(), mode, nil); err == nil {
				t.Fatal("CA pin bypassed SNI")
			}
		})
	}
}

func TestResumptionDynamicNames(t *testing.T) {
	for _, mode := range []string{"go", "chrome"} {
		t.Run(mode, func(t *testing.T) {
			server, client := resumptionFixture(t, gotls.VersionTLS13)
			addr := resumptionServer(t, server)
			client.VerifyPeerCertByName = []string{"frommitm"}
			dial := func(name string, want bool) {
				t.Helper()
				cfg := client.GetTLSConfig()
				cfg.Rand.(*RandCarrier).VerifyPeerCertByName = []string{name}
				r, wire, err := resumptionProbe(t, addr, cfg, mode, nil)
				if err != nil || r != want {
					t.Fatalf("resume=%v err=%v", r, err)
				}
				checkPSK(t, wire, want)
			}
			dial("one.test", false)
			dial("one.test", true)
			dial("two.test", false)
			dial("two.test", true)
		})
	}
}

type corruptBinderConn struct {
	net.Conn
	corrupted bool
	wire      []byte
}

func (c *corruptBinderConn) Write(p []byte) (int, error) {
	if !c.corrupted && len(p) > 9 && p[0] == 22 && p[5] == 1 {
		p = bytes.Clone(p)
		p[len(p)-1] ^= 1
		c.corrupted = true
		c.wire = bytes.Clone(p)
	}
	return c.Conn.Write(p)
}
func TestResumptionBadBinder(t *testing.T) {
	server, client := resumptionFixture(t, gotls.VersionTLS13)
	addr := resumptionServer(t, server)
	if _, err := resumptionDial(t, addr, client.GetTLSConfig(), "chrome", nil); err != nil {
		t.Fatal(err)
	}
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	bad := &corruptBinderConn{Conn: raw}
	conn := UClient(bad, client.GetTLSConfig(), &utls.HelloChrome_Auto).(*UConn)
	if err := conn.HandshakeContext(context.Background()); err == nil || !bad.corrupted {
		t.Fatal("corrupt binder accepted")
	}
	checkPSK(t, bad.wire, true)
}

func TestResumptionWebsocketHandshake(t *testing.T) {
	server, client := resumptionFixture(t, gotls.VersionTLS13)
	server.NextProtos = []string{"http/1.1"}
	client.NextProtocol = []string{"http/1.1"}
	addr := resumptionServer(t, server)
	for i := 0; i < 3; i++ {
		raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(5 * time.Second))
		conn := UClient(raw, client.GetTLSConfig(), &utls.HelloChrome_Auto).(*UConn)
		if err := conn.WebsocketHandshakeContext(context.Background()); err != nil {
			t.Fatal(err)
		}
		var b [1]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			t.Fatal(err)
		}
		conn.Write([]byte{1})
		if conn.ConnectionState().DidResume != (i > 0) || conn.NegotiatedProtocol() != "http/1.1" {
			t.Fatal("websocket ALPN/resumption")
		}
	}
}

func TestResumptionOtherProfiles(t *testing.T) {
	for _, id := range []utls.ClientHelloID{utls.HelloFirefox_Auto, utls.HelloSafari_Auto, utls.HelloChrome_100_PSK, utls.HelloGolang} {
		t.Run(id.Str(), func(t *testing.T) {
			server, client := resumptionFixture(t, gotls.VersionTLS13)
			addr := resumptionServer(t, server)
			for i := 0; i < 2; i++ {
				raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				conn := UClient(raw, client.GetTLSConfig(), &id).(*UConn)
				if err := conn.HandshakeContext(context.Background()); err != nil {
					t.Fatal(err)
				}
				var b [1]byte
				if _, err := io.ReadFull(conn, b[:]); err != nil {
					t.Fatal(err)
				}
				conn.Write([]byte{1})
				// Presets without PSK may safely do another full handshake.
				if i == 0 && conn.ConnectionState().DidResume {
					t.Fatal("unexpected first resume")
				}
			}
		})
	}
}

func TestResumptionHandshakeCancellation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	raw, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	peer := <-accepted
	defer peer.Close()
	_, cfg := resumptionFixture(t, gotls.VersionTLS13)
	conn := UClient(raw, cfg.GetTLSConfig(), &utls.HelloChrome_Auto).(*UConn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := conn.HandshakeContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
}

func TestResumptionWorkload(t *testing.T) {
	if os.Getenv("TLS_RESUMPTION_WORKLOAD") == "" {
		t.Skip("explicit workload only")
	}
	count := 200
	if n, err := strconv.Atoi(os.Getenv("TLS_RESUMPTION_COUNT")); err == nil {
		count = n
	}
	server, client := resumptionFixture(t, gotls.VersionTLS13)
	addr := resumptionServer(t, server)
	start := time.Now()
	full, resumes := 0, 0
	for i := 0; i < count; i++ {
		begin := time.Now()
		r, wire, err := resumptionProbe(t, addr, client.GetTLSConfig(), "chrome", nil)
		if err != nil {
			t.Fatal(err)
		}
		if r {
			resumes++
		} else {
			full++
		}
		t.Logf("sample=%d resumed=%v elapsed_ns=%d client_wire_bytes=%d", i, r, time.Since(begin).Nanoseconds(), len(wire))
		if dir := os.Getenv("TLS_RESUMPTION_WIRE_DIR"); dir != "" && i < 3 {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("client-%d.bin", i)), wire, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Logf("SUMMARY connections=%d full=%d resumed=%d elapsed_ns=%d", count, full, resumes, time.Since(start).Nanoseconds())
}

func TestResumptionBaseline(t *testing.T) {
	for _, version := range []uint16{gotls.VersionTLS12, gotls.VersionTLS13} {
		for _, mode := range []string{"go", "chrome", "cache-only"} {
			t.Run(mode+"/"+gotls.VersionName(version), func(t *testing.T) {
				server, client := resumptionFixture(t, version)
				addr := resumptionServer(t, server)
				cache := utls.NewLRUClientSessionCache(8)
				for i := 0; i < 3; i++ {
					resumed, err := resumptionDial(t, addr, client.GetTLSConfig(), mode, cache)
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("connection=%d resumed=%v", i, resumed)
				}
			})
		}
	}
}
