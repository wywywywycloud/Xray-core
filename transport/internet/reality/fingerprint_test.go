package reality

import (
	"crypto/ecdh"
	"slices"
	"sync"
	"testing"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestValidateFingerprint(t *testing.T) {
	for _, name := range []string{"", "chrome", "firefox", "random", "randomized", "randomizednoalpn", "hellorandomized", "hellorandomizedalpn", "hellorandomizednoalpn"} {
		t.Run(name, func(t *testing.T) {
			fp := tls.GetFingerprint(name)
			before := *fp
			var seed utls.PRNGSeed
			var weights utls.Weights
			if fp.Seed != nil {
				seed = *fp.Seed
			}
			if fp.Weights != nil {
				weights = *fp.Weights
			}
			if err := ValidateFingerprint(fp); err != nil {
				t.Fatal(err)
			}
			if *fp != before {
				t.Fatal("modified global fingerprint")
			}
			if fp.Seed != nil && *fp.Seed != seed || fp.Weights != nil && *fp.Weights != weights {
				t.Fatal("modified global seed or weights")
			}
		})
	}
	for _, name := range []string{"android", "360", "hellochrome_58", "hellofirefox_55"} {
		if err := ValidateFingerprint(tls.GetFingerprint(name)); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	if ValidateFingerprint(nil) == nil {
		t.Fatal("accepted nil")
	}
}

func TestFingerprintMatchesUClientKeyShare(t *testing.T) {
	for _, profiles := range []map[string]*utls.ClientHelloID{tls.PresetFingerprints, tls.ModernFingerprints, tls.OtherFingerprints} {
		for name, fp := range profiles {
			if fp == nil || name == "hellogolang" {
				continue
			}
			if fp.Seed == nil && (fp.Client == utls.HelloRandomized.Client || fp.Client == utls.HelloRandomizedALPN.Client || fp.Client == utls.HelloRandomizedNoALPN.Client) {
				continue
			}
			u := utls.UClient(nil, &utls.Config{ServerName: "example.com", SessionTicketsDisabled: true, InsecureSkipVerify: true}, *fp)
			err := u.BuildHandshakeState()
			compatible := false
			if err == nil {
				key := u.HandshakeState.State13.KeyShareKeys.Ecdhe
				if key == nil {
					key = u.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
				}
				public, _ := ecdh.X25519().NewPublicKey([]byte{9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
				if key != nil {
					secret, err := key.ECDH(public)
					compatible = err == nil && len(secret) == 32 && slices.Contains(u.HandshakeState.Hello.SupportedVersions, utls.VersionTLS13)
				}
			}
			validation := ValidateFingerprint(fp)
			if (validation == nil) != compatible {
				t.Errorf("%s: compatible=%v validation=%v build=%v", name, compatible, validation, err)
			}
			t.Logf("%s compatible=%v", name, compatible)
		}
	}
}

func TestTLS13KeyShareRequirement(t *testing.T) {
	for _, tc := range []struct {
		name   string
		groups []utls.CurveID
		valid  bool
	}{
		{"x25519", []utls.CurveID{utls.X25519}, true},
		{"p256", []utls.CurveID{utls.CurveP256}, false},
		{"p256-before-x25519", []utls.CurveID{utls.CurveP256, utls.X25519}, false},
		{"mlkem", []utls.CurveID{utls.X25519MLKEM768}, true},
		{"mlkem-and-p256", []utls.CurveID{utls.X25519MLKEM768, utls.CurveP256}, false},
		{"missing", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
			if err != nil {
				t.Fatal(err)
			}
			for _, ext := range spec.Extensions {
				if ks, ok := ext.(*utls.KeyShareExtension); ok {
					ks.KeyShares = nil
					for _, group := range tc.groups {
						ks.KeyShares = append(ks.KeyShares, utls.KeyShare{Group: group})
					}
				}
			}
			u := utls.UClient(nil, &utls.Config{ServerName: "example.com", SessionTicketsDisabled: true, InsecureSkipVerify: true}, utls.HelloCustom)
			if err := u.ApplyPreset(&spec); err != nil {
				t.Fatal(err)
			}
			if err := u.BuildHandshakeState(); err != nil {
				t.Fatal(err)
			}
			if err := validateKeyShare(u); (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}

func TestSeededRandomizedFingerprint(t *testing.T) {
	for _, tls13 := range []bool{false, true} {
		for _, p256 := range []bool{false, true} {
			weights := utls.DefaultWeights
			weights.TLSVersMax_Set_VersionTLS13 = 0
			weights.FirstKeyShare_Set_CurveP256 = 0
			if tls13 {
				weights.TLSVersMax_Set_VersionTLS13 = 1
			}
			if p256 {
				weights.FirstKeyShare_Set_CurveP256 = 1
			}
			fp := utls.HelloRandomizedALPN
			fp.Seed = new(utls.PRNGSeed)
			fp.Weights = &weights
			beforeSeed, beforeWeights := *fp.Seed, weights
			err := ValidateFingerprint(&fp)
			if (err == nil) != (tls13 && !p256) {
				t.Fatalf("tls13=%v p256=%v err=%v", tls13, p256, err)
			}
			if *fp.Seed != beforeSeed || weights != beforeWeights {
				t.Fatal("mutated random state")
			}
		}
	}
}

func TestFingerprintConcurrent(t *testing.T) {
	fp := utls.HelloRandomizedALPN
	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	fp.Seed = new(utls.PRNGSeed)
	fp.Weights = &weights
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 50 {
				if err := ValidateFingerprint(&fp); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
}

func BenchmarkFingerprintCached(b *testing.B) {
	fp := tls.GetFingerprint("chrome")
	if err := ValidateFingerprint(fp); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := ValidateFingerprint(fp); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFingerprintCold(b *testing.B) {
	fp := *tls.GetFingerprint("chrome")
	b.ReportAllocs()
	for b.Loop() {
		if err := checkFingerprint(fp); err != nil {
			b.Fatal(err)
		}
	}
}
