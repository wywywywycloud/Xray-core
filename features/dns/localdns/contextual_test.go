package localdns

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

func TestContextualLocalResolverCancellation(t *testing.T) {
	saved := net.DefaultResolver
	defer func() { net.DefaultResolver = saved }()
	started := make(chan struct{}, 10)
	var active atomic.Int32
	net.DefaultResolver = &stdnet.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (stdnet.Conn, error) {
		a, b := stdnet.Pipe()
		active.Add(1)
		go func() {
			defer active.Add(-1)
			defer b.Close()
			buffer := make([]byte, 1024)
			if _, err := b.Read(buffer); err == nil {
				started <- struct{}{}
			}
			io.Copy(io.Discard, b)
		}()
		return a, nil
	}}
	c := New()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := c.LookupIPContext(ctx, "only-fixture.invalid", dns.IPOption{IPv4Enable: true})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("query not started")
	}
	secondCtx, secondCancel := context.WithCancel(context.Background())
	defer secondCancel()
	secondDone := make(chan error, 1)
	go func() {
		_, _, err := c.LookupIPContext(secondCtx, "only-fixture.invalid", dns.IPOption{IPv4Enable: true})
		secondDone <- err
	}()
	joinLimit := time.Now().Add(time.Second)
	var flight *localLookup
	for time.Now().Before(joinLimit) {
		c.mu.Lock()
		flight = c.flights["only-fixture.invalid"]
		joined := flight != nil && flight.owners == 2
		c.mu.Unlock()
		if joined {
			break
		}
		time.Sleep(time.Millisecond)
	}
	c.mu.Lock()
	joined := flight != nil && flight.owners == 2
	c.mu.Unlock()
	if !joined {
		t.Fatal("local co-owner did not join")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("caller retained")
	}
	if flight.ctx.Err() != nil || active.Load() == 0 {
		t.Fatal("leader canceled healthy local co-owner")
	}
	secondCancel()
	select {
	case err := <-secondDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("second caller retained")
	}
	select {
	case <-flight.done:
	case <-time.After(time.Second):
		t.Fatal("local producer retained")
	}
	limit := time.Now().Add(time.Second)
	for active.Load() != 0 && time.Now().Before(limit) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 {
		t.Fatal("resolver connections still active", active.Load())
	}
}

func TestContextualLocalResolverUDPFraming(t *testing.T) {
	server, err := stdnet.ListenUDP("udp4", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	finished := make(chan struct{})
	queries := make(chan dnsmessage.Message, 10)
	go func() {
		defer close(finished)
		for {
			b := make([]byte, 2048)
			n, peer, err := server.ReadFromUDP(b)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(b[:n]) != nil {
				return
			}
			queries <- m
			m.Response = true
			if m.Questions[0].Type == dnsmessage.TypeA {
				m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Class: dnsmessage.ClassINET, Type: dnsmessage.TypeA, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 77}}}}
			}
			reply, _ := m.Pack()
			server.WriteToUDP(reply, peer)
		}
	}()
	saved := net.DefaultResolver
	defer func() { net.DefaultResolver = saved }()
	net.DefaultResolver = &stdnet.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (stdnet.Conn, error) {
		return (&stdnet.Dialer{}).DialContext(ctx, "udp4", server.LocalAddr().String())
	}}
	c := New()
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ips, _, err := c.LookupIPContext(ctx, "wire.invalid", dns.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 || !ips[0].Equal(stdnet.IPv4(192, 0, 2, 77)) {
		t.Fatal(ips, err)
	}
	if len(queries) != 2 {
		t.Fatal("expected real A and AAAA datagrams", len(queries))
	}
	server.Close()
	<-finished
}
