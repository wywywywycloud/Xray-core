package internet

import (
	"context"
	"errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"testing"
)

type cancelDNS struct {
	calls  int
	cancel context.CancelFunc
	legacy bool
}

func (*cancelDNS) Type() interface{} { return dns.ClientType() }
func (*cancelDNS) Start() error      { return nil }
func (*cancelDNS) Close() error      { return nil }
func (c *cancelDNS) LookupIP(string, dns.IPOption) ([]net.IP, uint32, error) {
	c.legacy = true
	return nil, 0, errors.New("legacy called")
}
func (c *cancelDNS) LookupIPContext(ctx context.Context, _ string, _ dns.IPOption) ([]net.IP, uint32, error) {
	c.calls++
	c.cancel()
	return nil, 0, ctx.Err()
}
func TestContextualLookupStopsStrategyFallback(t *testing.T) {
	previous := dnsClient
	defer func() { dnsClient = previous }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &cancelDNS{cancel: cancel}
	dnsClient = c
	_, err := LookupForIPContext(ctx, "cancel.test", DomainStrategy_USE_IP46, nil)
	if !errors.Is(err, context.Canceled) || c.calls != 1 || c.legacy {
		t.Fatalf("err=%v calls=%d legacy=%v", err, c.calls, c.legacy)
	}
}
