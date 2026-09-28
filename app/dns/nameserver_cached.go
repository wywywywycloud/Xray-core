package dns

import (
	"context"
	go_errors "errors"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

type CachedNameserver interface {
	getCacheController() *CacheController

	sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns.IPOption)
}

// queryIP is called from dns.Server->queryIPTimeout
func queryIP(ctx context.Context, s CachedNameserver, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	if ctx.Err() != nil {
		return nil, 0, ctx.Err()
	}
	fqdn := Fqdn(domain)

	cache := s.getCacheController()
	if !cache.disableCache {
		if rec := cache.findRecords(fqdn); rec != nil {
			ips, ttl, err := merge(option, rec.A, rec.AAAA)
			if !go_errors.Is(err, errRecordNotFound) {
				if ttl > 0 {
					errors.LogDebugInner(ctx, err, cache.name, " cache HIT ", fqdn, " -> ", ips)
					log.Record(&log.DNSLog{Server: cache.name, Domain: fqdn, Result: ips, Status: log.DNSCacheHit, Elapsed: 0, Error: err})
					return ips, uint32(ttl), err
				}
				if cache.serveStale && (cache.serveExpiredTTL == 0 || cache.serveExpiredTTL < ttl) {
					errors.LogDebugInner(ctx, err, cache.name, " cache OPTIMISTE ", fqdn, " -> ", ips)
					log.Record(&log.DNSLog{Server: cache.name, Domain: fqdn, Result: ips, Status: log.DNSCacheOptimiste, Elapsed: 0, Error: err})
					go pull(ctx, s, fqdn, option)
					return ips, 1, err
				}
			}
		}
	} else {
		errors.LogDebug(ctx, "DNS cache is disabled. Querying IP for ", fqdn, " at ", cache.name)
	}

	return fetch(ctx, s, fqdn, option)
}

func pull(ctx context.Context, s CachedNameserver, fqdn string, option dns.IPOption) {
	nctx, cancel := backgroundQueryContext(ctx, 8*time.Second)
	defer cancel()

	fetch(nctx, s, fqdn, option)
}

func fetch(ctx context.Context, s CachedNameserver, fqdn string, option dns.IPOption) ([]net.IP, uint32, error) {
	key := fqdn
	switch {
	case option.IPv4Enable && option.IPv6Enable:
		key = key + "46"
	case option.IPv4Enable:
		key = key + "4"
	case option.IPv6Enable:
		key = key + "6"
	}

	ret := s.getCacheController().fetchShared(ctx, key, func(ctx context.Context) result {
		return doFetch(ctx, s, fqdn, option)
	})

	return ret.ips, ret.ttl, ret.error
}

type result struct {
	ips []net.IP
	ttl uint32
	error
}

func doFetch(ctx context.Context, s CachedNameserver, fqdn string, option dns.IPOption) result {
	flight := ctx.Value(flightKey{}).(*queryFlight)
	defer func() {
		flight.cancel()
		if udp, ok := s.(*ClassicNameServer); ok {
			udp.cancelRequests(ctx)
		}
		flight.workers.Wait()
		// Synchronize a response already admitted before cancellation/completion.
		flight.deliveryMu.Lock()
		flight.deliveryMu.Unlock()
	}()
	noResponseErrCh := make(chan error, 2)
	start := time.Now()
	if ctx.Err() != nil {
		return result{error: ctx.Err()}
	}
	s.sendQuery(ctx, noResponseErrCh, fqdn, option)
	var rec4, rec6 *IPRecord
	var err4, err6 error
	remaining := 0
	if option.IPv4Enable {
		remaining++
	}
	if option.IPv6Enable {
		remaining++
	}
	for remaining > 0 {
		select {
		case <-ctx.Done():
			return result{error: ctx.Err()}
		case err := <-noResponseErrCh:
			if err4 == nil {
				err4 = err
			} else {
				err6 = err
			}
			remaining--
		case answer := <-flight.answers:
			if answer.family == dnsmessage.TypeA {
				rec4 = answer.record
			} else {
				rec6 = answer.record
			}
			remaining--
		}
	}
	if ctx.Err() != nil {
		return result{error: ctx.Err()}
	}

	var errs []error
	if err4 != nil {
		errs = append(errs, err4)
	}
	if err6 != nil {
		errs = append(errs, err6)
	}

	ips, ttl, err := merge(option, rec4, rec6, errs...)
	var rTTL uint32
	if ttl > 0 {
		rTTL = uint32(ttl)
	} else if ttl == 0 && go_errors.Is(err, errRecordNotFound) {
		rTTL = 0
	} else { // edge case: where a fast rep's ttl expires during the rtt of a slower, parallel query
		rTTL = 1
	}

	log.Record(&log.DNSLog{Server: s.getCacheController().name, Domain: fqdn, Result: ips, Status: log.DNSQueried, Elapsed: time.Since(start), Error: err})
	return result{ips, rTTL, err}
}

func merge(option dns.IPOption, rec4 *IPRecord, rec6 *IPRecord, errs ...error) ([]net.IP, int32, error) {
	var allIPs []net.IP
	var rTTL int32 = dns.DefaultTTL

	mergeReq := option.IPv4Enable && option.IPv6Enable

	if option.IPv4Enable {
		ips, ttl, err := rec4.getIPs() // it's safe
		if !mergeReq || go_errors.Is(err, errRecordNotFound) {
			return ips, ttl, err
		}
		if ttl < rTTL {
			rTTL = ttl
		}
		if len(ips) > 0 {
			allIPs = append(allIPs, ips...)
		} else {
			errs = append(errs, err)
		}
	}

	if option.IPv6Enable {
		ips, ttl, err := rec6.getIPs() // it's safe
		if !mergeReq || go_errors.Is(err, errRecordNotFound) {
			return ips, ttl, err
		}
		if ttl < rTTL {
			rTTL = ttl
		}
		if len(ips) > 0 {
			allIPs = append(allIPs, ips...)
		} else {
			errs = append(errs, err)
		}
	}

	if len(allIPs) > 0 {
		return allIPs, rTTL, nil
	}
	if len(errs) == 2 && go_errors.Is(errs[0], errs[1]) {
		return nil, rTTL, errs[0]
	}
	return nil, rTTL, errors.Combine(errs...)
}
