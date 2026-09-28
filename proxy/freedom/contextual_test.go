package freedom

import (
	"context"
	"errors"
	stdnet "net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type blockedResolver struct {
	calls   int
	started chan struct{}
	ended   chan struct{}
}

type cancelAfterDial struct {
	cancel context.CancelFunc
	conn   stat.Connection
}

func (d cancelAfterDial) Dial(context.Context, net.Destination) (stat.Connection, error) {
	d.cancel()
	return d.conn, nil
}
func (cancelAfterDial) DestIpAddress() net.IP                                 { return nil }
func (cancelAfterDial) SetOutboundGateway(context.Context, *session.Outbound) {}

type closeObservedConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *closeObservedConn) Close() error { c.closes.Add(1); return c.Conn.Close() }

func TestContextualFreedomClosesDialResultOnCancellation(t *testing.T) {
	client, peer := stdnet.Pipe()
	defer client.Close()
	defer peer.Close()
	conn := &closeObservedConn{Conn: client}
	h := &Handler{config: &Config{}}
	ctx, cancel := context.WithCancel(session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 443)}}))
	defer cancel()
	err := h.Process(ctx, &transport.Link{}, cancelAfterDial{cancel: cancel, conn: conn})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("returned dial connection Close calls: got %d, want 1", got)
	}
}

func TestContextualUDPDomainFamilyPreference(t *testing.T) {
	ipv6 := net.ParseIP("2001:db8::1")
	ipv6Second := net.ParseIP("2001:db8::2")
	ipv4 := net.ParseIP("192.0.2.1")
	ipv4Second := net.ParseIP("192.0.2.2")
	for _, test := range []struct {
		name string
		ips  []net.IP
		want net.IP
	}{
		{"IPv6-first-dual-stack", []net.IP{ipv6, ipv4, ipv4Second}, ipv4},
		{"IPv6-only-first-address", []net.IP{ipv6, ipv6Second}, ipv6},
		{"IPv4-first-preserved", []net.IP{ipv4, ipv6, ipv4Second}, ipv4},
		{"IPv4-mapped-after-IPv6", []net.IP{ipv6, net.ParseIP("::ffff:192.0.2.2")}, ipv4Second},
		{"empty", nil, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := udpDomainIP(test.ips)
			if !got.Equal(test.want) {
				t.Fatalf("UDP domain selection: got %v, want %v", got, test.want)
			}
		})
	}
}

func (*blockedResolver) Type() interface{} { return dns.ClientType() }
func (*blockedResolver) Start() error      { return nil }
func (*blockedResolver) Close() error      { return nil }
func (*blockedResolver) LookupIP(string, dns.IPOption) ([]net.IP, uint32, error) {
	panic("legacy lookup used")
}
func (r *blockedResolver) LookupIPContext(ctx context.Context, _ string, _ dns.IPOption) ([]net.IP, uint32, error) {
	r.calls++
	close(r.started)
	<-ctx.Done()
	close(r.ended)
	return nil, 0, ctx.Err()
}

type noDial struct{ testing *testing.T }

func (d noDial) Dial(context.Context, net.Destination) (stat.Connection, error) {
	d.testing.Error("dial after DNS cancellation")
	return nil, errors.New("unexpected dial")
}
func (noDial) DestIpAddress() net.IP                                 { return nil }
func (noDial) SetOutboundGateway(context.Context, *session.Outbound) {}
func TestContextualFreedomNoResolutionRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &blockedResolver{started: make(chan struct{}), ended: make(chan struct{})}
		internet.InitSystemDialer(r, nil)
		defer internet.InitSystemDialer(nil, nil)
		h := &Handler{config: &Config{DomainStrategy: internet.DomainStrategy_USE_IP}}
		ctx, cancel := context.WithCancel(session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.TCPDestination(net.DomainAddress("cancel.test"), 443)}}))
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- h.Process(ctx, &transport.Link{}, noDial{t}) }()
		<-r.started
		cancel()
		synctest.Wait()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("lost cancellation: %v", err)
		}
		<-r.ended
		time.Sleep(6100 * time.Millisecond)
		if r.calls != 1 {
			t.Fatalf("retry count=%d", r.calls)
		}
	})
}
