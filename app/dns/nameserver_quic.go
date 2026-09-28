package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/url"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

// NextProtoDQ - During connection establishment, DNS/QUIC support is indicated
// by selecting the ALPN token "dq" in the crypto handshake.
const NextProtoDQ = "doq"

const handshakeTimeout = time.Second * 8

// QUICNameServer implemented DNS over QUIC
type QUICNameServer struct {
	sync.RWMutex
	cacheController   *CacheController
	destination       *net.Destination
	connection        *quic.Conn
	closed            bool
	connectionFlights CacheController
	clientIP          net.IP
}

// NewQUICNameServer creates DNS-over-QUIC client object for local resolving
func NewQUICNameServer(url *url.URL, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) (*QUICNameServer, error) {
	var err error
	port := net.Port(853)
	if url.Port() != "" {
		port, err = net.PortFromString(url.Port())
		if err != nil {
			return nil, err
		}
	}
	dest := net.UDPDestination(net.ParseAddress(url.Hostname()), port)

	s := &QUICNameServer{
		cacheController: NewCacheController(url.String(), disableCache, serveStale, serveExpiredTTL),
		destination:     &dest,
		clientIP:        clientIP,
	}

	errors.LogInfo(context.Background(), "DNS: created Local DNS-over-QUIC client for ", url.String())
	return s, nil
}

// Name implements Server.
func (s *QUICNameServer) Name() string {
	return s.cacheController.name
}

// IsDisableCache implements Server.
func (s *QUICNameServer) IsDisableCache() bool {
	return s.cacheController.disableCache
}

func (s *QUICNameServer) newReqID() uint16 {
	return 0
}

// getCacheController implements CachedNameServer.
func (s *QUICNameServer) getCacheController() *CacheController { return s.cacheController }

// sendQuery implements CachedNameServer.
func (s *QUICNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns_feature.IPOption) {
	errors.LogInfo(ctx, s.Name(), " querying: ", fqdn)

	reqs, err := buildReqMsgs(fqdn, option, s.newReqID, genEDNS0Options(s.clientIP, 0))
	if err != nil {
		errors.LogErrorInner(ctx, err, "failed to build dns query for ", fqdn)
		if noResponseErrCh != nil {
			if option.IPv4Enable {
				noResponseErrCh <- err
			}
			if option.IPv6Enable {
				noResponseErrCh <- err
			}
		}
		return
	}

	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	} else {
		deadline = time.Now().Add(time.Second * 5)
	}

	for _, req := range reqs {
		req.flight, _ = ctx.Value(flightKey{}).(*queryFlight)
		if ctx.Err() != nil {
			return
		}
		if req.flight != nil {
			req.flight.workers.Add(1)
		}
		go func(r *dnsRequest) {
			if r.flight != nil {
				defer r.flight.workers.Done()
			}
			if ctx.Err() != nil {
				return
			}
			// generate new context for each req, using same context
			// may cause reqs all aborted if any one encounter an error
			dnsCtx := ctx

			// reserve internal dns server requested Inbound
			if inbound := session.InboundFromContext(ctx); inbound != nil {
				dnsCtx = session.ContextWithInbound(dnsCtx, inbound)
			}

			dnsCtx = session.ContextWithContent(dnsCtx, &session.Content{
				Protocol:       "quic",
				SkipDNSResolve: true,
			})

			var cancel context.CancelFunc
			dnsCtx, cancel = context.WithDeadline(dnsCtx, deadline)
			defer cancel()

			b, err := dns.PackMessage(r.msg)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to pack dns query")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}

			dnsReqBuf := buf.New()
			err = binary.Write(dnsReqBuf, binary.BigEndian, uint16(b.Len()))
			if err != nil {
				errors.LogErrorInner(ctx, err, "binary write failed")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			_, err = dnsReqBuf.Write(b.Bytes())
			if err != nil {
				errors.LogErrorInner(ctx, err, "buffer write failed")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			b.Release()

			conn, err := s.openStream(dnsCtx)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to open quic connection")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}

			stopStream := context.AfterFunc(dnsCtx, func() { conn.CancelRead(0); conn.CancelWrite(0) })
			defer stopStream()
			defer conn.CancelRead(0)
			defer conn.CancelWrite(0)
			defer dnsReqBuf.Release()
			_, err = conn.Write(dnsReqBuf.Bytes())
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to send query")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}

			_ = conn.Close()

			respBuf := buf.New()
			defer respBuf.Release()
			n, err := respBuf.ReadFullFrom(conn, 2)
			if err != nil && n == 0 {
				errors.LogErrorInner(ctx, err, "failed to read response length")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			var length uint16
			err = binary.Read(bytes.NewReader(respBuf.Bytes()), binary.BigEndian, &length)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to parse response length")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			respBuf.Clear()
			n, err = respBuf.ReadFullFrom(conn, int32(length))
			if err != nil && n == 0 {
				errors.LogErrorInner(ctx, err, "failed to read response length")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}

			rec, err := parseResponse(respBuf.Bytes())
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to handle response")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			s.cacheController.updateRecord(r, rec)
		}(req)
	}
}

// QueryIP implements Server.
func (s *QUICNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}

func isActive(s *quic.Conn) bool {
	select {
	case <-s.Context().Done():
		return false
	default:
		return true
	}
}

func (s *QUICNameServer) getConnection(ctx context.Context) (*quic.Conn, error) {
	s.RLock()
	if s.closed {
		s.RUnlock()
		return nil, context.Canceled
	}
	conn := s.connection
	s.RUnlock()
	if conn != nil && isActive(conn) {
		return conn, nil
	}
	scope := scopeFromContext(ctx)
	scope.timeout = handshakeTimeout
	ctx = context.WithValue(ctx, queryScopeKey{}, scope)
	ret := s.connectionFlights.fetchShared(ctx, "connection", func(ctx context.Context) result {
		s.RLock()
		if s.closed {
			s.RUnlock()
			return result{error: context.Canceled}
		}
		current := s.connection
		s.RUnlock()
		if current != nil && isActive(current) {
			return result{}
		}
		conn, err := s.openConnection(ctx)
		if err != nil && ctx.Err() == nil {
			conn, err = s.openConnection(ctx)
		}
		if err != nil {
			return result{error: err}
		}
		if ctx.Err() != nil {
			conn.CloseWithError(0, "")
			return result{error: ctx.Err()}
		}
		s.connectionFlights.flightsMu.Lock()
		if s.connectionFlights.flights["connection"] != ctx.Value(flightKey{}) || ctx.Err() != nil {
			s.connectionFlights.flightsMu.Unlock()
			conn.CloseWithError(0, "")
			return result{error: context.Canceled}
		}
		err = s.publishConnection(conn)
		s.connectionFlights.flightsMu.Unlock()
		return result{error: err}
	})
	if ret.error != nil {
		return nil, ret.error
	}
	s.RLock()
	conn = s.connection
	closed := s.closed
	s.RUnlock()
	if closed {
		return nil, context.Canceled
	}
	return conn, nil
}

func (s *QUICNameServer) publishConnection(conn *quic.Conn) error {
	s.Lock()
	if s.closed {
		s.Unlock()
		conn.CloseWithError(0, "DNS shutdown")
		return context.Canceled
	}
	s.connection = conn
	s.Unlock()
	return nil
}

// Publication and shutdown use the same lock; a completed handshake cannot
// install a connection after shutdown has closed the previous generation.
func (s *QUICNameServer) close() {
	s.Lock()
	s.closed = true
	conn := s.connection
	s.connection = nil
	s.Unlock()
	if conn != nil {
		conn.CloseWithError(0, "DNS shutdown")
	}
}

func (s *QUICNameServer) openConnection(ctx context.Context) (*quic.Conn, error) {
	tlsConfig := tls.Config{}
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
	}
	tlsConfig.ServerName = s.destination.Address.String()
	conn, err := quic.DialAddr(ctx, s.destination.NetAddr(), tlsConfig.GetTLSConfig(tls.WithNextProto("http/1.1", http2.NextProtoTLS, NextProtoDQ)), quicConfig)
	log.Record(&log.AccessMessage{
		From:   "DNS",
		To:     s.destination,
		Status: log.AccessAccepted,
		Detour: "local",
	})
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (s *QUICNameServer) openStream(ctx context.Context) (*quic.Stream, error) {
	conn, err := s.getConnection(ctx)
	if err != nil {
		return nil, err
	}

	// open a new stream
	return conn.OpenStreamSync(ctx)
}
