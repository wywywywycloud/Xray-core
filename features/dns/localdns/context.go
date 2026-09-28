package localdns

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

type localLookup struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	owners int
	ips    []net.IP
	err    error
}

// Go's resolver singleflight remembers that a query was ever shared, rather
// than its remaining owners. Own the lookup so the last caller can cancel it.
// Native OS resolver work (e.g. libc) may remain non-interruptible.
func (c *Client) lookup(ctx context.Context, host string) ([]net.IP, error) {
	c.mu.Lock()
	if ctx.Err() != nil {
		c.mu.Unlock()
		return nil, ctx.Err()
	}
	if c.flights == nil {
		c.flights = make(map[string]*localLookup)
	}
	f := c.flights[host]
	if f == nil || f.ctx.Err() != nil {
		service := c.ctx
		if service == nil {
			service = context.Background()
		}
		producer, cancel := context.WithTimeout(service, 16*time.Second)
		f = &localLookup{ctx: producer, cancel: cancel, done: make(chan struct{})}
		c.flights[host] = f
		source := net.DefaultResolver
		if len(internet.Controllers) > 0 {
			source = c.r
		}
		// Do not copy Resolver's internal mutex/group or force PreferGo. A fresh
		// resolver avoids a canceled generation joining its predecessor internally.
		resolver := &net.Resolver{PreferGo: source.PreferGo, StrictErrors: source.StrictErrors}
		dial := source.Dial
		if dial == nil {
			dial = (&net.Dialer{}).DialContext
		}
		resolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dial(ctx, network, address)
			if err != nil {
				return nil, err
			}
			wrapped := &lookupConn{Conn: conn}
			wrapped.stop = context.AfterFunc(ctx, func() { conn.Close() })
			if packet, ok := conn.(net.PacketConn); ok {
				return &lookupPacketConn{lookupConn: wrapped, PacketConn: packet}, nil
			}
			return wrapped, nil
		}
		go func(f *localLookup) {
			f.ips, f.err = resolver.LookupIP(producer, "ip", host)
			if producer.Err() != nil {
				f.ips = nil
				f.err = producer.Err()
			}
			f.cancel()
			c.mu.Lock()
			if c.flights[host] == f {
				delete(c.flights, host)
			}
			close(f.done)
			c.mu.Unlock()
		}(f)
	}
	f.owners++
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		f.owners--
		if f.owners == 0 {
			if c.flights[host] == f {
				delete(c.flights, host)
			}
			f.cancel()
		}
		c.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.done:
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return f.ips, f.err
	}
}

type lookupConn struct {
	net.Conn
	stop func() bool
	once sync.Once
}

func (c *lookupConn) Close() error { c.once.Do(func() { c.stop() }); return c.Conn.Close() }

// Resolver uses PacketConn to choose datagram framing. Do not hide that
// capability when adding cancellation to a UDP connection.
type lookupPacketConn struct {
	*lookupConn
	net.PacketConn
}

func (c *lookupPacketConn) Close() error                      { return c.lookupConn.Close() }
func (c *lookupPacketConn) LocalAddr() net.Addr               { return c.lookupConn.LocalAddr() }
func (c *lookupPacketConn) SetDeadline(t time.Time) error     { return c.lookupConn.SetDeadline(t) }
func (c *lookupPacketConn) SetReadDeadline(t time.Time) error { return c.lookupConn.SetReadDeadline(t) }
func (c *lookupPacketConn) SetWriteDeadline(t time.Time) error {
	return c.lookupConn.SetWriteDeadline(t)
}
