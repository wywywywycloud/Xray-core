package splithttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

// Bound outstanding H1 acknowledgements independently of the number of POSTs.
// Thirty matches the default server reorder window; this is a client hard cap,
// not a promise that a remote peer has that many available slots.
const h1MaxConcurrentUploads = 30

// Dial and each bounded socket write have independent budgets. Queueing and
// continued progress must not consume a total request deadline.
const h1DialTimeout = 30 * time.Second
const h1WriteIdleTimeout = 30 * time.Second
const h1WriteChunkSize = 16 * 1024

// A socket Write may only enqueue the body locally. Until the peer responds,
// slow consumption and a stalled ACK are indistinguishable. Use the existing
// connection idle policy for response silence; callers may set an earlier
// deadline. This is refreshed on response progress, not a total POST limit.
const h1ResponseIdleTimeout = xnet.ConnIdleTimeout

type h1UploadPool struct {
	mu         sync.Mutex
	done       chan struct{}
	slots      chan struct{}
	idle       []*H1Conn
	idleTimers map[*H1Conn]*time.Timer
	conns      map[*H1Conn]struct{}
	closed     bool
}

func newH1UploadPool() *h1UploadPool {
	return &h1UploadPool{done: make(chan struct{}), slots: make(chan struct{}, h1MaxConcurrentUploads), conns: make(map[*H1Conn]struct{}), idleTimers: make(map[*H1Conn]*time.Timer)}
}

func (c *DefaultDialerClient) h1Uploads() *h1UploadPool {
	c.h1Once.Do(func() { c.h1Pool = newH1UploadPool() })
	return c.h1Pool
}

func (p *h1UploadPool) isClosed() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *h1UploadPool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.done)
	conns := make([]*H1Conn, 0, len(p.conns))
	for conn := range p.conns {
		conns = append(conns, conn)
	}
	p.idle = nil
	for conn, timer := range p.idleTimers {
		timer.Stop()
		delete(p.idleTimers, conn)
	}
	p.conns = make(map[*H1Conn]struct{})
	p.mu.Unlock()
	for _, conn := range conns {
		conn.Close()
	}
	return nil
}

func (p *h1UploadPool) get(ctx context.Context, dial func(context.Context) (net.Conn, error)) (*H1Conn, bool, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, false, io.ErrClosedPipe
	}
	if n := len(p.idle); n > 0 {
		conn := p.idle[n-1]
		p.idleTimers[conn].Stop()
		delete(p.idleTimers, conn)
		p.idle[n-1] = nil
		p.idle = p.idle[:n-1]
		p.mu.Unlock()
		return conn, true, nil
	}
	p.mu.Unlock()
	raw, err := dial(ctx)
	if err != nil {
		return nil, false, err
	}
	conn := NewH1Conn(raw)
	p.mu.Lock()
	if p.closed || ctx.Err() != nil {
		p.mu.Unlock()
		conn.Close()
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, false, io.ErrClosedPipe
	}
	p.conns[conn] = struct{}{}
	p.mu.Unlock()
	return conn, false, nil
}

func (p *h1UploadPool) put(conn *H1Conn, reusable bool) {
	p.mu.Lock()
	if p.closed || !reusable {
		delete(p.conns, conn)
		p.mu.Unlock()
		conn.Close()
		return
	}
	p.idle = append(p.idle, conn)
	var timer *time.Timer
	timer = time.AfterFunc(xnet.ConnIdleTimeout, func() {
		p.mu.Lock()
		if p.idleTimers[conn] != timer {
			p.mu.Unlock()
			return
		}
		delete(p.idleTimers, conn)
		delete(p.conns, conn)
		for i, c := range p.idle {
			if c == conn {
				p.idle = append(p.idle[:i], p.idle[i+1:]...)
				break
			}
		}
		p.mu.Unlock()
		conn.Close()
	})
	p.idleTimers[conn] = timer
	p.mu.Unlock()
}

func (c *DefaultDialerClient) postH1Packet(ctx context.Context, req *http.Request, payload buf.MultiBuffer) error {
	defer buf.ReleaseMulti(payload)
	p := c.h1Uploads()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// A cancellable pool context also covers dialing and callers waiting for a
	// slot. The goroutine exits on every return, including a successful POST.
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-p.done:
			cancel()
		case <-watchDone:
		}
	}()
	select {
	case p.slots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-p.slots }()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	requestBuff := new(bytes.Buffer)
	requestBuff.Grow(512 + int(req.ContentLength))
	// Request.Write reports WroteRequest even for a memory-only writer.
	if err := req.WithContext(context.Background()).Write(requestBuff); err != nil {
		return err
	}
	for {
		dialCtx, dialCancel := context.WithTimeout(ctx, h1DialTimeout)
		conn, reused, err := p.get(dialCtx, c.dialUploadConn)
		dialCancel()
		if err != nil {
			return err
		}
		canceled := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { conn.Close(); close(canceled) })
		finish := func(reusable bool) {
			if !stop() {
				<-canceled
				reusable = false
			}
			if ctx.Err() != nil {
				reusable = false
			}
			if reusable {
				if err := conn.SetDeadline(time.Time{}); err != nil {
					reusable = false
				}
			}
			p.put(conn, reusable)
		}
		remaining := requestBuff.Bytes()
		if _, ok := conn.Conn.(*h1UploadTLSConn); ok {
			// TLS chooses its own record partition across the complete request.
			// The lower-stream decorator renews deadlines per ciphertext Write.
			var n int
			n, err = conn.Write(remaining)
			if err == nil && n != len(remaining) {
				err = io.ErrShortWrite
			}
			remaining = nil
		}
		for len(remaining) > 0 {
			if err = conn.SetWriteDeadline(time.Now().Add(h1WriteIdleTimeout)); err != nil {
				break
			}
			chunk := remaining[:min(len(remaining), h1WriteChunkSize)]
			var n int
			n, err = conn.Write(chunk)
			if err == nil && n != len(chunk) {
				err = io.ErrShortWrite
			}
			if err != nil {
				break
			}
			remaining = remaining[n:]
		}
		if err != nil {
			finish(false)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if reused {
				continue
			}
			return err
		}
		if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.WroteRequest != nil {
			trace.WroteRequest(httptrace.WroteRequestInfo{})
		}
		resp, err := http.ReadResponse(conn.RespBufReader, req)
		if err != nil {
			finish(false)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("error while reading response: %w", err)
		}
		_, readErr := io.Copy(io.Discard, resp.Body)
		if readErr != nil {
			// Body.Close may try to drain again. Do not grant a failed read
			// another idle interval just to dispose of its response body.
			conn.Close()
		}
		closeErr := resp.Body.Close()
		reusable := readErr == nil && closeErr == nil && resp.StatusCode == http.StatusOK && !resp.Close
		finish(reusable)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("got non-200 error response code: %d", resp.StatusCode)
		}
		return nil
	}
}
