package tls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	utls "github.com/refraction-networking/utls"
	"google.golang.org/protobuf/proto"
)

var globalUTLSSessionCache = utls.NewLRUClientSessionCache(128)

// Keep the two libraries' opaque session states separate. Their serialization
// formats are not an interoperability contract. Both LRUs are bounded globally.
type scopedSessionCache struct {
	scope     string
	allowUTLS bool
}

func (c *scopedSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	return globalSessionCache.Get(c.scope + key)
}
func (c *scopedSessionCache) Put(key string, s *tls.ClientSessionState) {
	globalSessionCache.Put(c.scope+key, s)
}

type scopedUTLSSessionCache struct{ scope string }

func (c *scopedUTLSSessionCache) Get(key string) (*utls.ClientSessionState, bool) {
	return globalUTLSSessionCache.Get(c.scope + key)
}
func (c *scopedUTLSSessionCache) Put(key string, s *utls.ClientSessionState) {
	globalUTLSSessionCache.Put(c.scope+key, s)
}

func sessionScope(parts ...any) string {
	b, _ := json.Marshal(parts)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]) + ":"
}

func effectiveSessionScope(scope string, c *tls.Config) string {
	var names []string
	var pins [][]byte
	if carrier, ok := c.Rand.(*RandCarrier); ok {
		names, pins = carrier.VerifyPeerCertByName, carrier.PinnedPeerCertSha256
	}
	// RAW may resolve frommitm names and ALPN after GetTLSConfig returns.
	return sessionScope(scope, c.ServerName, c.NextProtos, c.InsecureSkipVerify, names, pins)
}

func configureSessionCache(source *Config, c *tls.Config) {
	if c.SessionTicketsDisabled {
		return
	}
	for _, cert := range source.Certificate {
		if cert.Usage != Certificate_AUTHORITY_VERIFY {
			// Serving/issuing certificate entries can be rewritten by hot reload.
			// They are not a stable client verification policy to cache against.
			c.ClientSessionCache = nil
			return
		}
	}
	// Include the complete configured policy, including pinning and trust anchors,
	// plus effective values changed by destination/ALPN options.
	policy, err := proto.MarshalOptions{Deterministic: true}.Marshal(source)
	if err != nil {
		c.ClientSessionCache = nil
		return
	}
	carrier, ok := c.Rand.(*RandCarrier)
	if !ok || c.RootCAs != carrier.RootCAs {
		// An arbitrary Option supplied a policy outside the serializable Xray
		// configuration. Do not reuse sessions across that unknown policy.
		c.ClientSessionCache = nil
		return
	}
	c.ClientSessionCache = &scopedSessionCache{
		scope: sessionScope(policy, c.ServerName, c.NextProtos, c.InsecureSkipVerify, carrier.destination),
		// A crypto/tls VerifyConnection callback cannot be faithfully converted
		// to uTLS (including its unexported key exporter). Retain full handshakes.
		allowUTLS: c.VerifyConnection == nil && len(c.EncryptedClientHelloConfigList) == 0,
	}
	previous := c.VerifyConnection
	c.VerifyConnection = func(s tls.ConnectionState) error {
		if s.DidResume {
			if err := verifyResumedPeer(c, s.PeerCertificates, s.VerifiedChains); err != nil {
				return err
			}
		}
		if previous != nil {
			return previous(s)
		}
		return nil
	}
}

// VerifyPeerCertificate is skipped by TLS on resumption. Revalidate both normal
// trust and Xray's pin/name policy using the authenticated cached certificate.
func verifyResumedPeer(c *tls.Config, peers []*x509.Certificate, chains [][]*x509.Certificate) error {
	if len(peers) == 0 {
		return errors.New("tls: resumed session has no peer certificate")
	}
	if !c.InsecureSkipVerify {
		now := time.Now()
		if c.Time != nil {
			now = c.Time()
		}
		opts := x509.VerifyOptions{Roots: c.RootCAs, DNSName: c.ServerName, CurrentTime: now, Intermediates: x509.NewCertPool()}
		for _, cert := range peers[1:] {
			opts.Intermediates.AddCert(cert)
		}
		var err error
		chains, err = peers[0].Verify(opts)
		if err != nil {
			return err
		}
	}
	if c.VerifyPeerCertificate != nil {
		raw := make([][]byte, len(peers))
		for i, cert := range peers {
			raw[i] = cert.Raw
		}
		return c.VerifyPeerCertificate(raw, chains)
	}
	return nil
}
