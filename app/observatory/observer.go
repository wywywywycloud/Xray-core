package observatory

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
	"google.golang.org/protobuf/proto"
)

type Observer struct {
	config *Config
	ctx    context.Context

	statusLock sync.Mutex
	status     []*OutboundStatus

	lifecycleLock sync.Mutex
	cancel        context.CancelFunc
	finished      chan struct{}

	ohm        outbound.Manager
	dispatcher routing.Dispatcher
}

func (o *Observer) GetObservation(ctx context.Context) (proto.Message, error) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	// Callers marshal and retain results after this lock is released.
	return proto.Clone(&ObservationResult{Status: o.status}), nil
}

func (o *Observer) Type() interface{} {
	return extension.ObservatoryType()
}

func (o *Observer) Start() error {
	o.lifecycleLock.Lock()
	defer o.lifecycleLock.Unlock()
	if o.cancel != nil || o.config == nil || len(o.config.SubjectSelector) == 0 {
		return nil
	}
	ctx, cancel := context.WithCancel(o.ctx)
	o.cancel = cancel
	o.finished = make(chan struct{})
	go func() {
		defer close(o.finished)
		o.background(ctx)
	}()
	return nil
}

func (o *Observer) Close() error {
	o.lifecycleLock.Lock()
	defer o.lifecycleLock.Unlock()
	if o.cancel != nil {
		o.cancel()
		<-o.finished
		o.cancel = nil
	}
	return nil
}

func (o *Observer) background(ctx context.Context) {
	sleepTime := time.Second * 10
	if o.config.ProbeInterval != 0 {
		sleepTime = time.Duration(o.config.ProbeInterval)
	}
	wait := func() bool {
		timer := time.NewTimer(sleepTime)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		}
	}
	for ctx.Err() == nil {
		hs, ok := o.ohm.(outbound.HandlerSelector)
		if !ok {
			errors.LogInfo(ctx, "outbound.Manager is not a HandlerSelector")
			return
		}
		outbounds := hs.Select(o.config.SubjectSelector)
		o.clearRemovedOutbounds(outbounds)
		if !o.config.EnableConcurrency {
			sort.Strings(outbounds)
			for _, v := range outbounds {
				if ctx.Err() != nil {
					return
				}
				result := o.probe(ctx, v)
				if ctx.Err() != nil {
					return
				}
				o.updateStatusForResult(v, &result)
				if !wait() {
					return
				}
			}
			// An empty selector result must not spin until a handler is added.
			if len(outbounds) == 0 && !wait() {
				return
			}
			continue
		}
		var probes sync.WaitGroup
		for _, v := range outbounds {
			if ctx.Err() != nil {
				break
			}
			probes.Add(1)
			go func(v string) {
				defer probes.Done()
				result := o.probe(ctx, v)
				if ctx.Err() == nil {
					o.updateStatusForResult(v, &result)
				}
			}(v)
		}
		probes.Wait()
		if !wait() {
			return
		}
	}
}

func (o *Observer) clearRemovedOutbounds(outbounds []string) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	if len(o.status) == 0 {
		return
	}
	var pruned []*OutboundStatus
	for _, status := range o.status {
		if slices.Contains(outbounds, status.OutboundTag) {
			pruned = append(pruned, status)
		}
	}
	o.status = pruned
}

func (o *Observer) probe(ctx context.Context, outbound string) ProbeResult {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	errorCollectorForRequest := newErrorCollector()

	httpTransport := http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return nil, nil
		},
		DisableKeepAlives: true,
		DialContext: func(_ context.Context, network string, addr string) (net.Conn, error) {
			dest, err := v2net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, errors.New("cannot understand address").Base(err)
			}
			// Each probe owns its transport. Preserve its exact context because
			// net/http detaches cancellation from the context passed to DialContext.
			trackedCtx := session.TrackedConnectionError(ctx, errorCollectorForRequest)
			return tagged.Dialer(trackedCtx, o.dispatcher, dest, outbound)
		},
		TLSHandshakeTimeout: time.Second * 5,
	}
	defer httpTransport.CloseIdleConnections()
	httpClient := &http.Client{
		Transport: &httpTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar:     nil,
		Timeout: time.Second * 5,
	}
	var GETTime time.Duration
	err := func() error {
		startTime := time.Now()
		probeURL := "https://www.google.com/generate_204"
		if o.config.ProbeUrl != "" {
			probeURL = o.config.ProbeUrl
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			return err
		}
		utils.TryDefaultHeadersWith(req.Header, "nav")
		response, err := httpClient.Do(req)
		if err != nil {
			return errors.New("outbound failed to relay connection").Base(err)
		}
		if response.Body != nil {
			response.Body.Close()
		}
		endTime := time.Now()
		GETTime = endTime.Sub(startTime)
		return nil
	}()
	if err != nil {
		errorMessage := "the outbound " + outbound + " is dead: GET request failed:" + err.Error() + "with outbound handler report underlying connection failed"
		errors.LogInfoInner(o.ctx, errorCollectorForRequest.UnderlyingError(), errorMessage)
		return ProbeResult{Alive: false, LastErrorReason: errorMessage}
	}
	errors.LogInfo(o.ctx, "the outbound ", outbound, " is alive:", GETTime.Seconds())
	return ProbeResult{Alive: true, Delay: GETTime.Milliseconds()}
}

func (o *Observer) updateStatusForResult(outbound string, result *ProbeResult) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	var status *OutboundStatus
	if location := o.findStatusLocationLockHolderOnly(outbound); location != -1 {
		status = o.status[location]
	} else {
		status = &OutboundStatus{}
		o.status = append(o.status, status)
	}

	status.LastTryTime = time.Now().Unix()
	status.OutboundTag = outbound
	status.Alive = result.Alive
	if result.Alive {
		status.Delay = result.Delay
		status.LastSeenTime = status.LastTryTime
		status.LastErrorReason = ""
	} else {
		status.LastErrorReason = result.LastErrorReason
		status.Delay = 99999999
	}
}

func (o *Observer) findStatusLocationLockHolderOnly(outbound string) int {
	for i, v := range o.status {
		if v.OutboundTag == outbound {
			return i
		}
	}
	return -1
}

func New(ctx context.Context, config *Config) (*Observer, error) {
	var outboundManager outbound.Manager
	var dispatcher routing.Dispatcher
	err := core.RequireFeatures(ctx, func(om outbound.Manager, rd routing.Dispatcher) {
		outboundManager = om
		dispatcher = rd
	})
	if err != nil {
		return nil, errors.New("Cannot get depended features").Base(err)
	}
	return &Observer{
		config:     config,
		ctx:        ctx,
		ohm:        outboundManager,
		dispatcher: dispatcher,
	}, nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
