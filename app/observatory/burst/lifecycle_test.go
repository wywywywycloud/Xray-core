package burst

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

// These tests use the real tagged dialer, dispatcher and freedom outbound.
type lifecycleServer struct {
	*httptest.Server
	requests    atomic.Int64
	active      atomic.Int64
	connections atomic.Int64
	bytes       atomic.Int64
	started     chan struct{}
}

func newLifecycleServer(t *testing.T, mode string) *lifecycleServer {
	t.Helper()
	s := &lifecycleServer{started: make(chan struct{}, 100)}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		s.active.Add(1)
		defer s.active.Add(-1)
		if mode == "body" || mode == "stream" || mode == "partial" {
			w.Header().Set("Content-Length", "1000000")
			w.WriteHeader(200)
			n, _ := w.Write([]byte("partial"))
			s.bytes.Add(int64(n))
			w.(http.Flusher).Flush()
		}
		s.started <- struct{}{}
		switch mode {
		case "headers", "body":
			<-r.Context().Done()
		case "stream":
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-r.Context().Done():
					return
				case <-tick.C:
					n, err := w.Write(make([]byte, 512))
					s.bytes.Add(int64(n))
					w.(http.Flusher).Flush()
					if err != nil {
						return
					}
				}
			}
		case "partial":
			return
		case "error":
			time.Sleep(2 * time.Millisecond)
			w.WriteHeader(503)
		case "success":
			time.Sleep(2 * time.Millisecond)
			fmt.Fprint(w, "complete response")
		}
	}))
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			s.connections.Add(1)
		case http.StateClosed, http.StateHijacked:
			s.connections.Add(-1)
		}
	}
	s.Start()
	t.Cleanup(func() { s.CloseClientConnections(); s.Close() })
	return s
}

func realObserver(t *testing.T, url, method string, timeout time.Duration) *Observer {
	t.Helper()
	v, err := core.New(&core.Config{
		App:      []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})},
		Outbound: []*core.OutboundHandlerConfig{{Tag: "probe", ProxySettings: serial.ToTypedMessage(&freedom.Config{})}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	obj, err := core.CreateObject(v, &Config{SubjectSelector: []string{"probe"}, PingConfig: &HealthPingConfig{
		Destination: url, HttpMethod: method, Timeout: int64(timeout), Interval: int64(time.Hour), SamplingCount: 1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	o := obj.(*Observer)
	t.Cleanup(func() { o.Close(); o.hp.cancelCtx() })
	return o
}

func waitLifecycle(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !f() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !f() {
		t.Fatalf("%s did not settle within 1s", what)
	}
}

func TestRealScheduleCancellation(t *testing.T) {
	for _, mode := range []string{"headers", "body", "stream"} {
		t.Run(mode, func(t *testing.T) {
			s := newLifecycleServer(t, mode)
			o := realObserver(t, s.URL, "GET", 4*time.Second)
			fallback := newLifecycleServer(t, "success")
			o.hp.Settings.Connectivity = fallback.URL
			ctx, cancel := context.WithCancel(o.ctx)
			defer cancel()
			done := make(chan struct{})
			go func() { o.hp.doCheck(ctx, []string{"probe"}, 0, 1); close(done) }()
			select {
			case <-s.started:
			case <-time.After(3 * time.Second):
				t.Fatal("no request")
			}
			start := time.Now()
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("check did not return")
			}
			waitLifecycle(t, "server request and TCP connection", func() bool { return s.active.Load() == 0 && s.connections.Load() == 0 })
			elapsed := time.Since(start)
			bytes, requests := s.bytes.Load(), s.requests.Load()
			time.Sleep(100 * time.Millisecond)
			if s.bytes.Load() != bytes || s.requests.Load() != requests || fallback.requests.Load() != 0 {
				t.Fatal("activity after cancellation")
			}
			t.Logf("cancel_settle=%s requests=%d active=%d connections=%d server_bytes=%d fallback=%d", elapsed, requests, s.active.Load(), s.connections.Load(), bytes, fallback.requests.Load())
		})
	}
}

func TestRealTimeoutAndResults(t *testing.T) {
	for _, mode := range []string{"headers", "body", "partial", "error", "success"} {
		t.Run(mode, func(t *testing.T) {
			s := newLifecycleServer(t, mode)
			o := realObserver(t, s.URL, "GET", 150*time.Millisecond)
			start := time.Now()
			o.hp.Check([]string{"probe"})
			if time.Since(start) > time.Second {
				t.Fatal("deadline exceeded 1s")
			}
			waitLifecycle(t, "server cleanup", func() bool { return s.active.Load() == 0 && s.connections.Load() == 0 })
			if s.requests.Load() != 1 {
				t.Fatalf("server requests=%d, want 1", s.requests.Load())
			}
			result := o.hp.Results["probe"]
			if result == nil {
				t.Fatal("no recorded result")
			}
			stats := result.Get()
			wantFail := 0
			if mode == "headers" || mode == "body" || mode == "partial" {
				wantFail = 1
			}
			if stats.All != 1 || stats.Fail != wantFail {
				t.Fatalf("stats=%+v want fail=%d", stats, wantFail)
			}
			t.Logf("elapsed=%s fail=%d requests=%d active=%d connections=%d", time.Since(start), stats.Fail, s.requests.Load(), s.active.Load(), s.connections.Load())
		})
	}
}

func TestRealObserverRepeatedStartClose(t *testing.T) {
	s := newLifecycleServer(t, "headers")
	before := runtime.NumGoroutine()
	for i := 0; i < 10; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			o := realObserver(t, s.URL, "HEAD", 4*time.Second)
			if err := o.Start(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-s.started:
			case <-time.After(3 * time.Second):
				t.Fatal("no request")
			}
			o.Close()
			waitLifecycle(t, "observer close", func() bool { return s.active.Load() == 0 && s.connections.Load() == 0 })
		})
	}
	requests := s.requests.Load()
	time.Sleep(150 * time.Millisecond)
	if s.requests.Load() != requests {
		t.Fatal("new request after close")
	}
	t.Logf("cycles=10 requests=%d active=%d connections=%d goroutines_before=%d after=%d", requests, s.active.Load(), s.connections.Load(), before, runtime.NumGoroutine())
}

func TestRealObserverCloseManualCheck(t *testing.T) {
	s := newLifecycleServer(t, "headers")
	o := realObserver(t, s.URL, "HEAD", 4*time.Second)
	o.config.SubjectSelector = nil
	o.Start()
	done := make(chan struct{})
	go func() { o.Check([]string{"probe"}); close(done) }()
	select {
	case <-s.started:
	case <-time.After(time.Second):
		t.Fatal("no request")
	}
	o.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("manual check survives Close")
	}
	waitLifecycle(t, "manual check connection", func() bool { return s.active.Load() == 0 && s.connections.Load() == 0 })
}

func TestRealConnectivityCanceled(t *testing.T) {
	s := newLifecycleServer(t, "partial")
	fallback := newLifecycleServer(t, "headers")
	o := realObserver(t, s.URL, "GET", 4*time.Second)
	o.hp.Settings.Connectivity = fallback.URL
	ctx, cancel := context.WithCancel(o.ctx)
	defer cancel()
	done := make(chan struct{})
	go func() { o.hp.doCheck(ctx, []string{"probe"}, 0, 1); close(done) }()
	select {
	case <-fallback.started:
	case <-time.After(time.Second):
		t.Fatal("no fallback request")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("check survives cancel")
	}
	waitLifecycle(t, "fallback connection", func() bool { return fallback.active.Load() == 0 && fallback.connections.Load() == 0 })
}

func TestRealCancelDoesNotAffectOtherCheck(t *testing.T) {
	s := newLifecycleServer(t, "headers")
	o := realObserver(t, s.URL, "HEAD", 4*time.Second)
	ctx1, cancel1 := context.WithCancel(o.ctx)
	ctx2, cancel2 := context.WithCancel(o.ctx)
	defer cancel1()
	defer cancel2()
	go o.hp.doCheck(ctx1, []string{"probe"}, 0, 1)
	go o.hp.doCheck(ctx2, []string{"probe"}, 0, 1)
	for i := 0; i < 2; i++ {
		select {
		case <-s.started:
		case <-time.After(time.Second):
			t.Fatal("no request")
		}
	}
	cancel1()
	waitLifecycle(t, "one surviving independent check", func() bool { return s.active.Load() == 1 && s.connections.Load() == 1 })
	cancel2()
	waitLifecycle(t, "both canceled checks", func() bool { return s.active.Load() == 0 && s.connections.Load() == 0 })
}

// Run alone under tcpdump to correlate cancellation with actual TCP payload.
// Server writes are application observations; the pcap is the wire evidence.
func TestWireCancellation(t *testing.T) {
	s := newLifecycleServer(t, "stream")
	o := realObserver(t, s.URL, "GET", 4*time.Second)
	ctx, cancel := context.WithCancel(o.ctx)
	defer cancel()
	done := make(chan struct{})
	go func() { o.hp.doCheck(ctx, []string{"probe"}, 0, 1); close(done) }()
	select {
	case <-s.started:
	case <-time.After(time.Second):
		t.Fatal("no request")
	}
	time.Sleep(200 * time.Millisecond)
	t.Logf("wire_destination=%s cancel_unix_ns=%d server_bytes=%d active=%d connections=%d", s.URL, time.Now().UnixNano(), s.bytes.Load(), s.active.Load(), s.connections.Load())
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("check survives cancel")
	}
	time.Sleep(100 * time.Millisecond)
	bytes := s.bytes.Load()
	t.Logf("grace_end_unix_ns=%d server_bytes=%d active=%d connections=%d", time.Now().UnixNano(), bytes, s.active.Load(), s.connections.Load())
	time.Sleep(time.Second)
	t.Logf("window_end_unix_ns=%d server_bytes=%d active=%d connections=%d requests=%d", time.Now().UnixNano(), s.bytes.Load(), s.active.Load(), s.connections.Load(), s.requests.Load())
	if s.active.Load() != 0 || s.connections.Load() != 0 || s.bytes.Load() != bytes {
		t.Fatal("network activity survives cancellation grace period")
	}
}
