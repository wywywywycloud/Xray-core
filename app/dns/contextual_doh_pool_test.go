package dns

import (
	"context"
	"crypto/tls"
	"io"
	stdnet "net"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"
)

func TestContextualDoHPoolSharedHandshake(t *testing.T) {
	started, release, serverDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var dials atomic.Int32
	tr := &http2.Transport{DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (stdnet.Conn, error) {
		dials.Add(1)
		close(started)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
		}
		client, server := stdnet.Pipe()
		go func() {
			defer close(serverDone)
			(&http2.Server{}).ServeConn(server, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				bytes, _ := io.ReadAll(r.Body)
				var m dnsmessage.Message
				m.Unpack(bytes)
				m.Response = true
				m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Class: dnsmessage.ClassINET, Type: dnsmessage.TypeA, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 22}}}}
				body, _ := m.Pack()
				w.Write(body)
			})})
		}()
		return client, nil
	}}
	pool := &dohConnPool{transport: tr}
	tr.ConnPool = pool
	s := &DoHNameServer{cacheController: NewCacheController("doh-pool", true, false, 0), httpClient: &http.Client{Transport: tr}, dohURL: "https://fixture.test/dns-query", pool: pool}
	defer pool.close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := lookup(s, ctx, "leader.test", v4)
	receive(t, started)
	b := lookup(s, context.Background(), "follower.test", v4)
	handshake := joined(t, &pool.dials, "fixture.test:443", 2)
	flight := joined(t, s.cacheController, "leader.test.4", 1)
	cancel()
	canceled(t, a)
	receive(t, flight.done)
	if handshake.ctx.Err() != nil {
		t.Fatal("healthy owner's shared handshake canceled")
	}
	close(release)
	succeeded(t, b, 1)
	succeeded(t, lookup(s, context.Background(), "reuse.test", v4), 1)
	if dials.Load() != 1 {
		t.Fatalf("dial count=%d", dials.Load())
	}
	pool.close()
	receive(t, serverDone)
}

func TestContextualDoHPoolLastHandshakeOwner(t *testing.T) {
	started, ended := make(chan struct{}), make(chan struct{})
	tr := &http2.Transport{DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(ended)
		return nil, ctx.Err()
	}}
	pool := &dohConnPool{transport: tr}
	tr.ConnPool = pool
	defer pool.close()
	s := &DoHNameServer{cacheController: NewCacheController("doh-pool", true, false, 0), httpClient: &http.Client{Transport: tr}, dohURL: "https://fixture.test/dns-query", pool: pool}
	ctx, cancel := context.WithCancel(context.Background())
	a := lookup(s, ctx, "only.test", v4)
	receive(t, started)
	handshake := joined(t, &pool.dials, "fixture.test:443", 1)
	cancel()
	canceled(t, a)
	receive(t, ended)
	receive(t, handshake.done)
}
