package dns_test

import (
	"context"
	"errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"testing"
)

type legacy struct{ called int }

func (*legacy) Type() interface{} { return dns.ClientType() }
func (*legacy) Start() error      { return nil }
func (*legacy) Close() error      { return nil }
func (c *legacy) LookupIP(string, dns.IPOption) ([]net.IP, uint32, error) {
	c.called++
	return []net.IP{{192, 0, 2, 1}}, 60, nil
}
func TestContextualLegacyCompatibility(t *testing.T) {
	c := new(legacy)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := dns.LookupIPContext(ctx, c, "unused.test", dns.IPOption{}); !errors.Is(err, context.Canceled) || c.called != 0 {
		t.Fatal(err, c.called)
	}
	ips, ttl, err := dns.LookupIPContext(context.Background(), c, "unused.test", dns.IPOption{})
	if err != nil || ttl != 60 || len(ips) != 1 || c.called != 1 {
		t.Fatal(ips, ttl, err, c.called)
	}
}
