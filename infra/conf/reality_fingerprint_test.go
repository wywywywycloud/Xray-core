package conf_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"
)

func TestREALITYFingerprintBuild(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"chrome", ""}, {"ChRoMe", ""}, {"", ""}, {"random", ""}, {"randomized", ""}, {"randomizednoalpn", ""},
		{"hellorandomized", ""}, {"hellorandomizedalpn", ""}, {"hellorandomizednoalpn", ""},
		{"android", "X25519"}, {"360", "X25519"}, {"hellochrome_58", "X25519"}, {"not-a-fingerprint", `unknown "fingerprint"`},
		{"unsafe", `invalid "fingerprint"`}, {"hellogolang", `invalid "fingerprint"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &conf.REALITYConfig{Fingerprint: tc.name, PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
			_, err := c.Build()
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), tc.name) {
				t.Fatalf("want %q and fingerprint, got %v", tc.want, err)
			}
		})
	}
}

func TestREALITYJSONNodeError(t *testing.T) {
	for _, decoder := range []struct {
		name   string
		strict bool
	}{{"local", false}, {"remote", true}} {
		for _, fp := range []string{"chrome", "", "android", "unknown-profile", "hellorandomized"} {
			t.Run(decoder.name+"/"+fp, func(t *testing.T) {
				data := fmt.Sprintf(`{"outbounds":[{"tag":"node-office-17","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000001","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"fingerprint":%q,"serverName":"example.com","publicKey":"CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}}]}`, fp)
				decode := serial.DecodeJSONConfig
				if decoder.strict {
					decode = serial.DecodeJSONConfigStrict
				}
				c, err := decode(strings.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				_, err = c.Build()
				invalid := fp == "android" || fp == "unknown-profile"
				if !invalid {
					if err != nil {
						t.Fatal(err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), "node-office-17") || !strings.Contains(err.Error(), fp) {
					t.Fatalf("missing node/fingerprint error: %v", err)
				}
				t.Log(err)
			})
		}
	}
}

func TestTLSOnlyFingerprintUnaffected(t *testing.T) {
	if _, err := (&conf.TLSConfig{Fingerprint: "android"}).Build(); err != nil {
		t.Fatal(err)
	}
}
