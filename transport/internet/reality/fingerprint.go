package reality

import (
	"crypto/ecdh"
	"slices"
	"sync"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/errors"
)

var fingerprintChecks sync.Map

// ValidateFingerprint checks the key-share requirement of UClient without dialing.
// Unseeded randomized profiles vary on every connection and cannot be rejected
// based on a single sample. They remain subject to UClient's runtime checks.
func ValidateFingerprint(fingerprint *utls.ClientHelloID) error {
	if fingerprint == nil {
		return errors.New("missing REALITY fingerprint")
	}
	switch fingerprint.Client {
	case utls.HelloRandomized.Client, utls.HelloRandomizedALPN.Client, utls.HelloRandomizedNoALPN.Client:
		if fingerprint.Seed == nil {
			return nil
		}
	}
	// uTLS requires Seed and Weights to be immutable once set. Config names
	// resolve to a finite set of IDs, so generate keys only once per profile,
	// even when a subscription contains many nodes with the same fingerprint.
	id := *fingerprint
	if check, ok := fingerprintChecks.Load(id); ok {
		return check.(func() error)()
	}
	check, _ := fingerprintChecks.LoadOrStore(id, sync.OnceValue(func() error {
		return checkFingerprint(id)
	}))
	return check.(func() error)()
}

func checkFingerprint(fingerprint utls.ClientHelloID) error {
	uConn := utls.UClient(nil, &utls.Config{
		ServerName:             "example.com",
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}, fingerprint)
	if err := uConn.BuildHandshakeState(); err != nil {
		return errors.New("cannot build REALITY ClientHello").Base(err)
	}
	return validateKeyShare(uConn)
}

func validateKeyShare(uConn *utls.UConn) error {
	// Match UClient's preference: an ordinary key takes precedence over ML-KEM.
	ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		ecdhe = uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
	}
	if !slices.Contains(uConn.HandshakeState.Hello.SupportedVersions, utls.VersionTLS13) ||
		ecdhe == nil || ecdhe.Curve() != ecdh.X25519() {
		return errors.New("REALITY requires a TLS 1.3 ClientHello with an X25519 authentication key share; choose a compatible fingerprint such as chrome")
	}
	return nil
}
