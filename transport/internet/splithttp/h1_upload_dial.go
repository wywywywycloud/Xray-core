package splithttp

import (
	"context"
	gotls "crypto/tls"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// A private marker: this connection has write-progress handling below TLS.
// Plaintext/custom dialers retain the bounded plaintext-write fallback.
type h1UploadTLSConn struct{ net.Conn }

func dialH1Upload(ctx context.Context, dest xnet.Destination, settings *internet.MemoryStreamConfig, config *gotls.Config, fingerprint string) (net.Conn, error) {
	conn, err := internet.DialSystem(ctx, dest, settings.SocketSettings)
	if err != nil {
		return nil, err
	}
	if settings.TcpmaskManager != nil {
		masked, err := settings.TcpmaskManager.WrapConnClient(conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn = masked
	}
	if config == nil {
		return conn, nil
	}
	return secureH1Upload(ctx, conn, config, tls.GetFingerprint(fingerprint))
}

func secureH1Upload(ctx context.Context, raw net.Conn, config *gotls.Config, fingerprint *utls.ClientHelloID) (net.Conn, error) {
	progress := &h1TLSWriteProgress{Conn: raw}
	var conn tls.Interface
	if fingerprint != nil {
		conn = tls.UClient(progress, config, fingerprint).(tls.Interface)
	} else {
		conn = tls.Client(progress, config).(tls.Interface)
	}
	// The standard TLS client otherwise handshakes lazily in its first Write,
	// outside the upload dial context and potentially waiting on an unbounded Read.
	if err := conn.HandshakeContext(ctx); err != nil {
		progress.Close()
		return nil, err
	}
	progress.mu.Lock()
	progress.armed = true
	progress.mu.Unlock()
	return &h1UploadTLSConn{Conn: conn}, nil
}

// Observe lower-stream write completion, not remote delivery. With a buffering
// mask/proxy the lower stream may accept bytes before its own TCP write. Forward
// each ciphertext buffer intact so TLS retains control over record boundaries.
type h1TLSWriteProgress struct {
	net.Conn
	mu       sync.Mutex
	armed    bool
	external time.Time
	idle     time.Time
}

func (c *h1TLSWriteProgress) writeDeadline() time.Time {
	if c.idle.IsZero() || (!c.external.IsZero() && c.external.Before(c.idle)) {
		return c.external
	}
	return c.idle
}

func (c *h1TLSWriteProgress) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.external = t
	return c.Conn.SetWriteDeadline(c.writeDeadline())
}

func (c *h1TLSWriteProgress) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.external = t
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(c.writeDeadline())
}

func (c *h1TLSWriteProgress) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.armed {
		c.idle = time.Now().Add(h1WriteIdleTimeout)
		if err := c.Conn.SetWriteDeadline(c.writeDeadline()); err != nil {
			c.idle = time.Time{}
			c.mu.Unlock()
			return 0, err
		}
	}
	c.mu.Unlock()
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.idle = time.Time{}
	c.mu.Unlock()
	return n, err
}
