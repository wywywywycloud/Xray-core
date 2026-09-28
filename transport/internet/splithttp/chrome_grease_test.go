package splithttp

import (
	"testing"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

func TestChrome133SettingsGREASESelection(t *testing.T) {
	for _, tc := range []struct {
		fp   string
		want bool
	}{{"", true}, {"chrome", true}, {"hellochrome_auto", true}, {"hellochrome_133", true}, {"hellochrome_131", false}, {"hellochrome_120", false}, {"firefox", false}, {"unsafe", false}, {"randomized", false}} {
		t.Run(tc.fp, func(t *testing.T) {
			for _, useReality := range []bool{false, true} {
				cfg := &internet.MemoryStreamConfig{ProtocolName: "splithttp", ProtocolSettings: &Config{}, SecurityType: "tls", SecuritySettings: &tls.Config{Fingerprint: tc.fp}}
				if useReality {
					cfg.SecurityType = "reality"
					cfg.SecuritySettings = &reality.Config{Fingerprint: tc.fp}
				}
				c := createHTTPClient(net.TCPDestination(net.LocalHostIP, 443), cfg).(*DefaultDialerClient)
				tr := c.client.Transport.(*http2.Transport)
				if tr.EnableInitialSettingsGREASE != tc.want {
					t.Errorf("reality=%v enabled=%v want%v", useReality, tr.EnableInitialSettingsGREASE, tc.want)
				}
				if tr.MaxHeaderListSize != 0 || tr.MaxDecoderHeaderTableSize != 0 || tr.MaxEncoderHeaderTableSize != 0 || tr.MaxReadFrameSize != 0 {
					t.Fatal("unrelated limits changed")
				}
			}
		})
	}
	original := tls.PresetFingerprints["chrome"]
	future := utls.HelloChrome_133
	future.Version = "154"
	tls.PresetFingerprints["chrome"] = &future
	defer func() { tls.PresetFingerprints["chrome"] = original }()
	if useChrome133SettingsGREASE(&tls.Config{Fingerprint: "chrome"}, nil) {
		t.Fatal("future Chrome alias incorrectly enabled")
	}
	originalAuto := utls.HelloChrome_Auto
	utls.HelloChrome_Auto = future
	defer func() { utls.HelloChrome_Auto = originalAuto }()
	for _, name := range []string{"", "hellochrome_auto"} {
		if useChrome133SettingsGREASE(&tls.Config{Fingerprint: name}, nil) {
			t.Fatalf("future Auto profile incorrectly enabled for %q", name)
		}
	}
	if useChrome133SettingsGREASE(nil, nil) {
		t.Fatal("enabled without TLS/REALITY")
	}
	if useChrome133SettingsGREASE(&tls.Config{Fingerprint: "hellochrome_133"}, &reality.Config{Fingerprint: "firefox"}) {
		t.Fatal("TLS fingerprint overrode selected REALITY fingerprint")
	}
	for _, alpn := range []string{"http/1.1", "h3"} {
		cfg := &internet.MemoryStreamConfig{ProtocolName: "splithttp", ProtocolSettings: &Config{}, SecurityType: "tls", SecuritySettings: &tls.Config{Fingerprint: "hellochrome_133", NextProtocol: []string{alpn}}}
		c := createHTTPClient(net.TCPDestination(net.LocalHostIP, 443), cfg).(*DefaultDialerClient)
		if _, ok := c.client.Transport.(*http2.Transport); ok {
			t.Fatalf("unexpected H2 for %s", alpn)
		}
	}
}
