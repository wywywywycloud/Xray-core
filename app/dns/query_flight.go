package dns

import (
	"context"
	"golang.org/x/net/dns/dnsmessage"
	"sync"
	"time"
)

// Caller deadlines govern only their subscription. Values and the lifetime of
// background owners come from the DNS service, never an arbitrary first caller.
type serviceValues struct {
	context.Context
	service context.Context
}

func (c serviceValues) Value(key any) any { return c.service.Value(key) }

type queryScopeKey struct{}
type queryScope struct {
	service    context.Context
	timeout    time.Duration
	background bool
}

func scopeFromContext(ctx context.Context) queryScope {
	scope, _ := ctx.Value(queryScopeKey{}).(queryScope)
	if scope.service == nil {
		scope.service = context.Background()
	}
	if scope.timeout <= 0 {
		scope.timeout = 4 * time.Second
	}
	return scope
}
func backgroundQueryContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	scope := scopeFromContext(ctx)
	scope.background = true
	scope.timeout = timeout
	background, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	stop := context.AfterFunc(scope.service, cancel)
	if scope.service.Err() != nil {
		cancel()
	}
	return context.WithValue(background, queryScopeKey{}, scope), func() { stop(); cancel() }
}

type flightKey struct{}
type flightAnswer struct {
	family dnsmessage.Type
	record *IPRecord
}
type queryFlight struct {
	ctx                       context.Context
	cancel                    context.CancelFunc
	done                      chan struct{}
	answers                   chan flightAnswer
	deliveryMu                sync.Mutex
	workers                   sync.WaitGroup
	waiters, backgroundOwners int    // protected by CacheController.flightsMu
	result                    result // published by closing done
}

func (c *CacheController) fetchShared(ctx context.Context, key string, produce func(context.Context) result) result {
	if ctx.Err() != nil {
		return result{error: ctx.Err()}
	}
	scope := scopeFromContext(ctx)
	c.flightsMu.Lock()
	if c.flights == nil {
		c.flights = make(map[string]*queryFlight)
	}
	f := c.flights[key]
	if f == nil || f.ctx.Err() != nil {
		producer, cancel := context.WithTimeout(context.WithoutCancel(ctx), scope.timeout)
		stop := context.AfterFunc(scope.service, cancel)
		if scope.service.Err() != nil {
			cancel()
		}
		f = &queryFlight{ctx: producer, cancel: func() { stop(); cancel() }, done: make(chan struct{}), answers: make(chan flightAnswer, 2)}
		c.flights[key] = f
		go func(f *queryFlight) {
			f.result = produce(context.WithValue(producer, flightKey{}, f))
			f.cancel()
			c.flightsMu.Lock()
			if c.flights[key] == f {
				delete(c.flights, key)
			}
			close(f.done)
			c.flightsMu.Unlock()
		}(f)
	}
	if scope.background {
		f.backgroundOwners++
	} else {
		f.waiters++
	}
	c.flightsMu.Unlock()
	defer func() {
		c.flightsMu.Lock()
		if scope.background {
			f.backgroundOwners--
		} else {
			f.waiters--
		}
		if f.waiters == 0 && f.backgroundOwners == 0 {
			if c.flights[key] == f {
				delete(c.flights, key)
			}
			f.cancel()
		}
		c.flightsMu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return result{error: ctx.Err()}
	case <-f.done:
		if ctx.Err() != nil {
			return result{error: ctx.Err()}
		}
		return f.result
	}
}
