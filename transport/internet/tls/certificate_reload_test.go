package tls_test

import (
	"bytes"
	gotls "crypto/tls"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
	. "github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

func TestCertificateReloadKeepsConfigImmutable(t *testing.T) {
	first, _ := cert.MustGenerate(nil, cert.CommonName("first.test"), cert.DNSNames("first.test"))
	next, _ := cert.MustGenerate(nil, cert.CommonName("next.test"), cert.DNSNames("next.test"))
	entry := ParseCertificate(first)
	entry.CertificatePath = filepath.Join(t.TempDir(), "certificate.pem")
	entry.KeyPath = filepath.Join(t.TempDir(), "key.pem")
	certPEM, keyPEM := next.ToPEM()
	if err := os.WriteFile(entry.CertificatePath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry.KeyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	config := &Config{Certificate: []*Certificate{entry}}
	before := proto.Clone(config)
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			listener := config.GetTLSConfig()
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				current, err := listener.GetCertificate(&gotls.ClientHelloInfo{ServerName: "next.test"})
				if err != nil {
					t.Error(err)
					return
				}
				if _, err := proto.Marshal(config); err != nil {
					t.Error(err)
					return
				}
				if bytes.Equal(current.Certificate[0], next.Certificate) {
					return
				}
				time.Sleep(time.Millisecond)
			}
			t.Error("certificate file update was not published")
		}()
	}
	workers.Wait()
	if !proto.Equal(config, before) {
		t.Fatal("reload worker changed caller-owned configuration")
	}
}
