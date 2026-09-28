package dns

import (
	"context"
	"fmt"
	"io"
	stdnet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"golang.org/x/net/dns/dnsmessage"
)

// The production UDP dispatcher is exercised through one real loopback socket.
// Only the routing dispatcher is replaced; DNS bytes travel over the host UDP stack.
type loopbackDispatcher struct {
	mu    sync.Mutex
	conns []net.Conn
	calls atomic.Int32
}

func (d *loopbackDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *loopbackDispatcher) Start() error      { return nil }
func (d *loopbackDispatcher) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.conns {
		c.Close()
	}
	return nil
}
func (d *loopbackDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	c, err := (&stdnet.Dialer{}).DialContext(ctx, "udp", dest.NetAddr())
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.conns = append(d.conns, c)
	d.mu.Unlock()
	d.calls.Add(1)
	rw := &datagramRW{c}
	return &transport.Link{Reader: rw, Writer: rw}, nil
}
func (d *loopbackDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return fmt.Errorf("unused")
}

type datagramRW struct{ net.Conn }

func (r *datagramRW) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	_, err := b.ReadFrom(r.Conn)
	if err != nil {
		b.Release()
		return nil, err
	}
	return buf.MultiBuffer{b}, nil
}
func (r *datagramRW) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		if _, err := r.Conn.Write(b.Bytes()); err != nil {
			return err
		}
	}
	return nil
}
func (r *datagramRW) Interrupt() { r.Close() }

type wireQuery struct {
	msg  dnsmessage.Message
	peer *stdnet.UDPAddr
}
type udpFixture struct {
	conn    *stdnet.UDPConn
	queries chan wireQuery
	count   atomic.Int32
	done    chan struct{}
}

func newUDPFixture(t *testing.T) (*udpFixture, *ClassicNameServer, *loopbackDispatcher) {
	t.Helper()
	c, err := stdnet.ListenUDP("udp4", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := &udpFixture{conn: c, queries: make(chan wireQuery, 50), done: make(chan struct{})}
	go func() {
		defer close(f.done)
		for {
			b := make([]byte, 2048)
			n, peer, err := c.ReadFromUDP(b)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(b[:n]) != nil {
				return
			}
			f.count.Add(1)
			f.queries <- wireQuery{m, peer}
		}
	}()
	d := &loopbackDispatcher{}
	s := NewClassicNameServer(net.UDPDestination(net.IPAddress([]byte{127, 0, 0, 1}), net.Port(c.LocalAddr().(*stdnet.UDPAddr).Port)), d, true, false, 0, nil)
	t.Cleanup(func() { s.udpServer.RemoveRay(); d.Close(); s.requestsCleanup.Close(); c.Close(); receive(t, f.done) })
	return f, s, d
}
func (f *udpFixture) reply(t *testing.T, q wireQuery, truncated bool) {
	t.Helper()
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.msg.ID, Response: true, Truncated: truncated}, Questions: q.msg.Questions}
	if !truncated {
		question := q.msg.Questions[0]
		h := dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 60}
		var body dnsmessage.ResourceBody = &dnsmessage.AResource{A: [4]byte{192, 0, 2, 11}}
		if question.Type == dnsmessage.TypeAAAA {
			body = &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}
		}
		m.Answers = []dnsmessage.Resource{{Header: h, Body: body}}
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.conn.WriteToUDP(b, q.peer); err != nil {
		t.Fatal(err)
	}
}
func pending(s *ClassicNameServer) int { s.RLock(); defer s.RUnlock(); return len(s.requests) }

func TestContextualUDPNoRetryAfterCancellation(t *testing.T) {
	f, s, d := newUDPFixture(t)
	dns := makeDNS(t, false, s)
	ctx, cancel := context.WithCancel(context.Background())
	out := dnsLookup(dns, ctx)
	q := receive(t, f.queries)
	flight := joined(t, s.cacheController, "chain.test.4", 1)
	if pending(s) != 1 {
		t.Fatal("query not pending before cancel")
	}
	begin := time.Now()
	cancel()
	canceled(t, out)
	receive(t, flight.done)
	if pending(s) != 0 {
		t.Fatal("pending UDP transaction retained")
	}
	f.reply(t, q, true) // late truncated response must not initiate an EDNS retry
	time.Sleep(6100 * time.Millisecond)
	if f.count.Load() != 1 || pending(s) != 0 {
		t.Fatalf("queries=%d pending=%d after 6.1s", f.count.Load(), pending(s))
	}
	if d.calls.Load() != 1 {
		t.Fatal("unexpected dispatcher count")
	}
	t.Logf("after %s: wire_queries=%d pending=%d producer_done=true shared_socket_count=%d", time.Since(begin), f.count.Load(), pending(s), d.calls.Load())
}

func TestContextualUDPSharedSocketGenerationAndTruncation(t *testing.T) {
	f, s, d := newUDPFixture(t)
	aCtx, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	a := lookup(s, aCtx, "same.test", v4)
	old := receive(t, f.queries)
	oldFlight := joined(t, s.cacheController, "same.test.4", 1)
	healthy := lookup(s, context.Background(), "independent.test", v4)
	other := receive(t, f.queries)
	cancelA()
	canceled(t, a)
	receive(t, oldFlight.done)
	// Force the allocator back across the canceled ID; quarantine must prevent reuse.
	atomic.StoreUint32(&s.reqID, uint32(old.msg.ID)-1)
	fresh := lookup(s, context.Background(), "same.test", v4)
	newQ := receive(t, f.queries)
	if newQ.msg.ID == old.msg.ID {
		t.Fatal("reused canceled transaction ID")
	}
	f.reply(t, old, false)
	f.reply(t, old, true)
	f.reply(t, other, false)
	succeeded(t, healthy, 1)
	select {
	case r := <-fresh:
		t.Fatalf("late reply completed fresh generation: %+v", r)
	default:
	}
	f.reply(t, newQ, true)
	edns := receive(t, f.queries)
	if len(edns.msg.Additionals) != 1 {
		t.Fatal("healthy truncated reply did not retain EDNS fallback")
	}
	f.reply(t, edns, false)
	succeeded(t, fresh, 1)
	if d.calls.Load() != 1 || f.count.Load() != 4 || pending(s) != 0 {
		t.Fatalf("socket=%d wire=%d pending=%d", d.calls.Load(), f.count.Load(), pending(s))
	}
	t.Log("one shared socket; canceled late/truncated replies ignored; healthy EDNS retry succeeds")
}

func TestContextualUDPHealthyCoWaiter(t *testing.T) {
	for _, cancelLeader := range []bool{true, false} {
		t.Run(fmt.Sprint(cancelLeader), func(t *testing.T) {
			f, s, _ := newUDPFixture(t)
			aCtx, stopA := context.WithCancel(context.Background())
			defer stopA()
			bCtx, stopB := context.WithCancel(context.Background())
			defer stopB()
			a := lookup(s, aCtx, "cowait.test", both)
			qa, qb := receive(t, f.queries), receive(t, f.queries)
			b := lookup(s, bCtx, "cowait.test", both)
			flight := joined(t, s.cacheController, "cowait.test.46", 2)
			if cancelLeader {
				stopA()
				canceled(t, a)
			} else {
				stopB()
				canceled(t, b)
			}
			if pending(s) != 2 {
				t.Fatal("healthy co-waiter lost pending IDs")
			}
			f.reply(t, qa, false)
			f.reply(t, qb, false)
			if cancelLeader {
				succeeded(t, b, 2)
			} else {
				succeeded(t, a, 2)
			}
			receive(t, flight.done)
			if pending(s) != 0 || f.count.Load() != 2 {
				t.Fatal("pending or extra query")
			}
		})
	}
}

var _ io.Closer = (*datagramRW)(nil)
