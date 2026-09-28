package dns

import (
	"context"
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	fdns "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

var v4 = fdns.IPOption{IPv4Enable: true}
var both = fdns.IPOption{IPv4Enable: true, IPv6Enable: true}

type capturedQuery struct {
	ctx  context.Context
	reqs []*dnsRequest
}
type controlledServer struct {
	cache *CacheController
	sent  chan capturedQuery
}

func newControlled(disable bool) *controlledServer {
	return &controlledServer{NewCacheController("fixture", disable, false, 0), make(chan capturedQuery, 20)}
}
func (s *controlledServer) getCacheController() *CacheController { return s.cache }
func (s *controlledServer) Name() string                         { return "fixture" }
func (s *controlledServer) IsDisableCache() bool                 { return s.cache.disableCache }
func (s *controlledServer) QueryIP(ctx context.Context, name string, opt fdns.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, name, opt)
}
func (s *controlledServer) sendQuery(ctx context.Context, errs chan<- error, name string, opt fdns.IPOption) {
	reqs, err := buildReqMsgs(name, opt, func() uint16 { return 1 }, nil)
	if err != nil {
		panic(err)
	}
	for _, r := range reqs {
		r.flight = ctx.Value(flightKey{}).(*queryFlight)
	}
	s.sent <- capturedQuery{ctx, reqs}
}
func answer(s *controlledServer, q capturedQuery) {
	for _, r := range q.reqs {
		ip := net.IP{192, 0, 2, 1}
		if r.reqType == dnsmessage.TypeAAAA {
			ip = net.ParseIP("2001:db8::1")
		}
		s.cache.updateRecord(r, &IPRecord{IP: []net.IP{ip}, Expire: time.Now().Add(time.Minute)})
	}
}
func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(2 * time.Second):
		t.Fatal("fixture timed out")
		var zero T
		return zero
	}
}
func lookup(s Server, ctx context.Context, name string, opt fdns.IPOption) <-chan result {
	ctx = context.WithValue(ctx, core.XrayKey(1), new(core.Instance))
	ch := make(chan result, 1)
	go func() { ips, ttl, err := s.QueryIP(ctx, name, opt); ch <- result{ips, ttl, err} }()
	return ch
}
func joined(t *testing.T, c *CacheController, key string, n int) *queryFlight {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.flightsMu.Lock()
		f := c.flights[key]
		ok := f != nil && f.waiters+f.backgroundOwners == n
		c.flightsMu.Unlock()
		if ok {
			return f
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("waiter count did not converge")
	return nil
}
func canceled(t *testing.T, ch <-chan result) {
	t.Helper()
	if r := receive(t, ch); !errors.Is(r.error, context.Canceled) {
		t.Fatalf("wanted cancellation, got %+v", r)
	}
}
func succeeded(t *testing.T, ch <-chan result, count int) {
	t.Helper()
	r := receive(t, ch)
	if r.error != nil || len(r.ips) != count || r.ttl == 0 {
		t.Fatalf("wanted healthy answer+TTL: %+v", r)
	}
}

func TestContextualSharedOwners(t *testing.T) {
	for _, opt := range []fdns.IPOption{v4, {IPv6Enable: true}, both} {
		for _, leader := range []bool{true, false} {
			t.Run(fmt.Sprintf("v4=%v-v6=%v-cancelLeader=%v", opt.IPv4Enable, opt.IPv6Enable, leader), func(t *testing.T) {
				s := newControlled(false)
				c1, stop1 := context.WithCancel(context.Background())
				defer stop1()
				c2, stop2 := context.WithCancel(context.Background())
				defer stop2()
				a := lookup(s, c1, "shared.test", opt)
				q := receive(t, s.sent)
				b := lookup(s, c2, "shared.test", opt)
				key := "shared.test.4"
				if opt.IPv6Enable {
					key = "shared.test.6"
					if opt.IPv4Enable {
						key = "shared.test.46"
					}
				}
				f := joined(t, s.cache, key, 2)
				if leader {
					stop1()
					canceled(t, a)
				} else {
					stop2()
					canceled(t, b)
				}
				if q.ctx.Err() != nil {
					t.Fatal("canceled another owner's producer")
				}
				answer(s, q)
				if leader {
					succeeded(t, b, len(q.reqs))
				} else {
					succeeded(t, a, len(q.reqs))
				}
				receive(t, f.done)
				succeeded(t, lookup(s, context.Background(), "shared.test", opt), len(q.reqs))
				select {
				case <-s.sent:
					t.Fatal("cache miss after surviving query")
				default:
				}
			})
		}
	}
}

func TestContextualGenerationAndProducerCleanup(t *testing.T) {
	s := newControlled(true)
	ctx, stop := context.WithCancel(context.Background())
	a := lookup(s, ctx, "generation.test", v4)
	old := receive(t, s.sent)
	f := joined(t, s.cache, "generation.test.4", 1)
	stop()
	canceled(t, a)
	b := lookup(s, context.Background(), "generation.test", v4)
	fresh := receive(t, s.sent)
	receive(t, f.done)
	answer(s, old)
	select {
	case r := <-b:
		t.Fatalf("old generation delivered %+v", r)
	default:
	}
	answer(s, fresh)
	succeeded(t, b, 1)
	s.cache.flightsMu.Lock()
	n := len(s.cache.flights)
	s.cache.flightsMu.Unlock()
	if n != 0 {
		t.Fatalf("flights retained: %d", n)
	}
}

func TestContextualPreCancelAndShortLeaderDeadline(t *testing.T) {
	s := newControlled(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled(t, lookup(s, ctx, "pre.test", v4))
	if len(s.sent) != 0 {
		t.Fatal("pre-cancel sent query")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	a := lookup(s, ctx, "deadline.test", v4)
	q := receive(t, s.sent)
	b := lookup(s, context.Background(), "deadline.test", v4)
	joined(t, s.cache, "deadline.test.4", 2)
	if r := receive(t, a); !errors.Is(r.error, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", r.error)
	}
	if q.ctx.Err() != nil {
		t.Fatal("producer inherited leader deadline")
	}
	answer(s, q)
	succeeded(t, b, 1)
}

func TestContextualBackgroundOwnerAndShutdown(t *testing.T) {
	service, stopService := context.WithCancel(context.Background())
	defer stopService()
	s := newControlled(false)
	s.cache.serveStale = true
	s.cache.ips["stale.test."] = &record{A: &IPRecord{IP: []net.IP{{192, 0, 2, 9}}, Expire: time.Now().Add(-time.Second)}}
	caller, cancel := context.WithCancel(context.WithValue(context.Background(), queryScopeKey{}, queryScope{service: service}))
	succeeded(t, lookup(s, caller, "stale.test", v4), 1)
	q := receive(t, s.sent)
	f := joined(t, s.cache, "stale.test.4", 1)
	s.cache.flightsMu.Lock()
	owners := f.backgroundOwners
	s.cache.flightsMu.Unlock()
	if owners != 1 {
		t.Fatal("refresh is not explicit background owner")
	}
	cancel()
	if q.ctx.Err() != nil {
		t.Fatal("stale refresh tied to foreground")
	}
	foreground, stopForeground := context.WithCancel(context.WithValue(context.Background(), queryScopeKey{}, queryScope{service: service}))
	joinedResult := make(chan result, 1)
	go func() {
		ips, ttl, err := fetch(foreground, s, "stale.test.", v4)
		joinedResult <- result{ips, ttl, err}
	}()
	joined(t, s.cache, "stale.test.4", 2)
	stopForeground()
	canceled(t, joinedResult)
	if q.ctx.Err() != nil {
		t.Fatal("foreground canceled explicit refresh owner")
	}
	stopService()
	receive(t, f.done)
	if !errors.Is(q.ctx.Err(), context.Canceled) {
		t.Fatal("refresh survived service shutdown")
	}
}

func makeDNS(t *testing.T, parallel bool, servers ...Server) *DNS {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	hosts, _ := NewStaticHosts(nil)
	d := &DNS{ctx: context.WithValue(ctx, core.XrayKey(1), new(core.Instance)), cancel: cancel, hosts: hosts, ipOption: &both, enableParallelQuery: parallel}
	for _, s := range servers {
		d.clients = append(d.clients, &Client{server: s, ipOption: &both, timeoutMs: 4 * time.Second})
	}
	t.Cleanup(func() { d.Close() })
	return d
}
func dnsLookup(d *DNS, ctx context.Context) <-chan result {
	ch := make(chan result, 1)
	go func() { ips, ttl, err := d.LookupIPContext(ctx, "chain.test", v4); ch <- result{ips, ttl, err} }()
	return ch
}
func TestContextualSerialParallelAndCacheFill(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		for _, cache := range []bool{false, true} {
			t.Run(fmt.Sprintf("parallel=%v-cache=%v", parallel, cache), func(t *testing.T) {
				a, b := newControlled(!cache), newControlled(!cache)
				d := makeDNS(t, parallel, a, b)
				ctx, cancel := context.WithCancel(context.Background())
				out := dnsLookup(d, ctx)
				qa := receive(t, a.sent)
				var qb capturedQuery
				if parallel {
					qb = receive(t, b.sent)
				}
				fa := joined(t, a.cache, "chain.test.4", 1)
				cancel()
				canceled(t, out)
				if parallel && cache {
					if qa.ctx.Err() != nil || qb.ctx.Err() != nil {
						t.Fatal("existing cache fill policy lost")
					}
					d.Close()
				}
				receive(t, fa.done)
				if !parallel {
					select {
					case <-b.sent:
						t.Fatal("fallback after cancellation")
					default:
					}
				}
			})
		}
	}
}

func TestContextualTCPReadAndDoHBodyCanceled(t *testing.T) {
	t.Run("dedicated-TCP", func(t *testing.T) {
		server, client := stdnet.Pipe()
		defer server.Close()
		s := &TCPNameServer{cacheController: NewCacheController("tcp", true, false, 0), dial: func(context.Context) (net.Conn, error) { return client, nil }}
		read := make(chan struct{})
		ended := make(chan struct{})
		go func() { b := make([]byte, 1024); server.Read(b); close(read); server.Read(b); close(ended) }()
		ctx, cancel := context.WithCancel(context.Background())
		out := lookup(s, ctx, "tcp.test", v4)
		receive(t, read)
		f := joined(t, s.cacheController, "tcp.test.4", 1)
		cancel()
		canceled(t, out)
		receive(t, f.done)
		receive(t, ended)
	})
	t.Run("DoH-response-body", func(t *testing.T) {
		started, ended := make(chan struct{}), make(chan struct{})
		fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			close(started)
			<-r.Context().Done()
			close(ended)
		}))
		defer fixture.Close()
		s := &DoHNameServer{cacheController: NewCacheController("doh", true, false, 0), httpClient: fixture.Client(), dohURL: fixture.URL}
		ctx, cancel := context.WithCancel(context.Background())
		out := lookup(s, ctx, "doh.test", v4)
		receive(t, started)
		f := joined(t, s.cacheController, "doh.test.4", 1)
		cancel()
		canceled(t, out)
		receive(t, f.done)
		receive(t, ended)
	})
}

func TestContextualOldFlightCannotRemoveReplacement(t *testing.T) {
	c := NewCacheController("barrier", true, false, 0)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	a := make(chan result, 1)
	go func() {
		a <- c.fetchShared(ctx, "key", func(ctx context.Context) result {
			calls.Add(1)
			close(entered)
			<-ctx.Done()
			<-release
			return result{error: ctx.Err()}
		})
	}()
	receive(t, entered)
	old := joined(t, c, "key", 1)
	cancel()
	canceled(t, a)
	healthy, healthyRelease := make(chan struct{}), make(chan struct{})
	b := make(chan result, 1)
	go func() {
		b <- c.fetchShared(context.Background(), "key", func(context.Context) result {
			calls.Add(1)
			close(healthy)
			<-healthyRelease
			return result{ttl: 1, ips: []net.IP{{192, 0, 2, 1}}}
		})
	}()
	receive(t, healthy)
	fresh := joined(t, c, "key", 1)
	close(release)
	receive(t, old.done)
	c.flightsMu.Lock()
	current := c.flights["key"]
	c.flightsMu.Unlock()
	if current != fresh {
		t.Fatal("old cleanup removed replacement")
	}
	close(healthyRelease)
	succeeded(t, b, 1)
	if calls.Load() != 2 {
		t.Fatal("wrong producer count")
	}
}
