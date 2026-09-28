package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	stdnet "net"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"golang.org/x/net/dns/dnsmessage"
)

func TestContextualQUICCloseBeforePublication(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	cert := certServer.TLS.Certificates[0]
	certServer.Close()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{NextProtoDQ}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan *quic.Conn, 1)
	go func() {
		peer, err := listener.Accept(ctx)
		if err == nil {
			accepted <- peer
		}
	}()
	conn, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{NextProtoDQ}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "fixture cleanup")
	peer := receive(t, accepted)
	defer peer.CloseWithError(0, "fixture cleanup")
	s := &QUICNameServer{}
	d := makeDNS(t, false, s)
	ready, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		// A real handshake has completed. Pause at the exact publication
		// operation used after getConnection's flight/context checks.
		close(ready)
		<-release
		done <- s.publishConnection(conn)
	}()
	receive(t, ready)
	if !isActive(conn) {
		t.Fatal("handshake connection not live before shutdown")
	}
	d.Close()
	close(release)
	if err := receive(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("late publication returned %v, want cancellation", err)
	}
	receive(t, conn.Context().Done())
	receive(t, peer.Context().Done())
	s.RLock()
	retained := s.connection
	s.RUnlock()
	if retained != nil {
		t.Fatal("connection installed after DNS.Close")
	}
	if got, err := s.getConnection(context.Background()); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("post-Close getConnection: conn=%v err=%v", got, err)
	}
}

func TestContextualQUICStreamIndependent(t *testing.T) {
	// Use httptest's ephemeral certificate and a fixture-only trust override.
	certServer := httptest.NewTLSServer(nil)
	cert := certServer.TLS.Certificates[0]
	certServer.Close()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{NextProtoDQ}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	lifetime, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	opened, streamEnded := make(chan string, 3), make(chan struct{}, 3)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept(lifetime)
		if err != nil {
			return
		}
		for {
			stream, err := conn.AcceptStream(lifetime)
			if err != nil {
				return
			}
			go func() {
				defer stream.CancelRead(0)
				defer stream.Close()
				var size [2]byte
				if _, err := io.ReadFull(stream, size[:]); err != nil {
					return
				}
				payload := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(stream, payload); err != nil {
					return
				}
				var m dnsmessage.Message
				m.Unpack(payload)
				name := m.Questions[0].Name.String()
				opened <- name
				if name == "blocked.test." {
					<-stream.Context().Done()
					streamEnded <- struct{}{}
					return
				}
				m.Response = true
				m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Class: dnsmessage.ClassINET, Type: dnsmessage.TypeA, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 42}}}}
				response, _ := m.Pack()
				binary.BigEndian.PutUint16(size[:], uint16(len(response)))
				stream.Write(append(size[:], response...))
			}()
		}
	}()
	conn, err := quic.DialAddr(lifetime, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{NextProtoDQ}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	u, _ := url.Parse("quic+local://" + listener.Addr().String())
	s, err := NewQUICNameServer(u, true, false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.connection = conn
	ctx, cancel := context.WithCancel(lifetime)
	a := lookup(s, ctx, "blocked.test", v4)
	if receive(t, opened) != "blocked.test." {
		t.Fatal("wrong stream")
	}
	flight := joined(t, s.cacheController, "blocked.test.4", 1)
	b := lookup(s, lifetime, "healthy.test", v4)
	receive(t, opened)
	cancel()
	canceled(t, a)
	receive(t, flight.done)
	receive(t, streamEnded)
	succeeded(t, b, 1)
	succeeded(t, lookup(s, lifetime, "reuse.test", v4), 1)
	receive(t, opened)
	if !isActive(conn) {
		t.Fatal("canceled stream closed shared connection")
	}
	conn.CloseWithError(0, "")
	listener.Close()
	receive(t, serverDone)
}

func TestContextualQUICHandshakeOwners(t *testing.T) {
	blackhole, err := stdnet.ListenUDP("udp4", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	u, _ := url.Parse("quic+local://" + blackhole.LocalAddr().String())
	s, err := NewQUICNameServer(u, true, false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	aCtx, aStop := context.WithCancel(context.Background())
	bCtx, bStop := context.WithCancel(context.Background())
	defer aStop()
	defer bStop()
	a, b := make(chan result, 1), make(chan result, 1)
	go func() { _, err := s.getConnection(aCtx); a <- result{error: err} }()
	f := joined(t, &s.connectionFlights, "connection", 1)
	go func() { _, err := s.getConnection(bCtx); b <- result{error: err} }()
	joined(t, &s.connectionFlights, "connection", 2)
	aStop()
	canceled(t, a)
	if f.ctx.Err() != nil {
		t.Fatal("leader canceled shared QUIC handshake")
	}
	bStop()
	canceled(t, b)
	receive(t, f.done)
}
