package dns

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"

	"github.com/xtls/xray-core/common/net"
	"golang.org/x/net/http2"
)

// http2's default pool waits unconditionally for the first request's dial.
// A DNS pool needs independently cancelable owners for that shared handshake.
type dohConnPool struct {
	mu          sync.Mutex
	transport   *http2.Transport
	connections map[string][]*http2.ClientConn
	dials       CacheController
	closed      bool
}

func (p *dohConnPool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	ctx := req.Context()
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, context.Canceled
		}
		for _, c := range p.connections[addr] {
			if c.ReserveNewRequest() {
				p.mu.Unlock()
				return c, nil
			}
		}
		p.mu.Unlock()
		ret := p.dials.fetchShared(ctx, addr, func(ctx context.Context) result {
			// Another dial may have become available after this caller checked the pool.
			p.mu.Lock()
			for _, c := range p.connections[addr] {
				if c.CanTakeNewRequest() {
					p.mu.Unlock()
					return result{}
				}
			}
			closed := p.closed
			p.mu.Unlock()
			if closed {
				return result{error: context.Canceled}
			}
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return result{error: err}
			}
			conn, err := p.transport.DialTLSContext(ctx, "tcp", addr, &tls.Config{ServerName: host})
			if err != nil {
				return result{error: err}
			}
			stop := context.AfterFunc(ctx, func() { conn.Close() })
			cc, err := p.transport.NewClientConn(conn)
			if err != nil {
				stop()
				conn.Close()
				return result{error: err}
			}
			p.dials.flightsMu.Lock()
			if p.dials.flights[addr] != ctx.Value(flightKey{}) || ctx.Err() != nil || !stop() {
				p.dials.flightsMu.Unlock()
				cc.Close()
				return result{error: context.Canceled}
			}
			p.mu.Lock()
			if p.closed {
				p.mu.Unlock()
				p.dials.flightsMu.Unlock()
				cc.Close()
				return result{error: context.Canceled}
			}
			if p.connections == nil {
				p.connections = make(map[string][]*http2.ClientConn)
			}
			p.connections[addr] = append(p.connections[addr], cc)
			p.mu.Unlock()
			p.dials.flightsMu.Unlock()
			return result{}
		})
		if ret.error != nil {
			return nil, ret.error
		}
	}
}

func (p *dohConnPool) MarkDead(dead *http2.ClientConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, conns := range p.connections {
		for i, c := range conns {
			if c == dead {
				conns = append(conns[:i], conns[i+1:]...)
				break
			}
		}
		if len(conns) == 0 {
			delete(p.connections, addr)
		} else {
			p.connections[addr] = conns
		}
	}
}
func (p *dohConnPool) close() {
	p.mu.Lock()
	p.closed = true
	var conns []*http2.ClientConn
	for _, cs := range p.connections {
		conns = append(conns, cs...)
	}
	p.connections = nil
	p.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}
