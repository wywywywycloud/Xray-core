package observatory

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"google.golang.org/protobuf/proto"
)

func TestOrdinaryConcurrentBatchLifecycle(t *testing.T) {
	var active, connections, requests atomic.Int64
	var healthy atomic.Bool
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		active.Add(1)
		defer active.Add(-1)
		if healthy.Load() {
			w.WriteHeader(204)
			return
		}
		<-r.Context().Done()
	}))
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
		if state == http.StateClosed || state == http.StateHijacked {
			connections.Add(-1)
		}
	}
	s.Start()
	t.Cleanup(func() { s.CloseClientConnections(); s.Close() })
	cfg := &core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})}}
	for i := 0; i < 2; i++ {
		cfg.Outbound = append(cfg.Outbound, &core.OutboundHandlerConfig{Tag: fmt.Sprint("probe", i), ProxySettings: serial.ToTypedMessage(&freedom.Config{})})
	}
	v, err := core.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	if err = v.Start(); err != nil {
		t.Fatal(err)
	}
	obj, err := core.CreateObject(v, &Config{SubjectSelector: []string{"probe"}, ProbeUrl: s.URL, ProbeInterval: int64(time.Hour), EnableConcurrency: true})
	if err != nil {
		t.Fatal(err)
	}
	o := obj.(*Observer)
	t.Cleanup(func() { o.Close() })
	wait := func(what string, f func() bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for !f() && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if !f() {
			t.Fatal(what)
		}
	}
	if err = o.Start(); err != nil {
		t.Fatal(err)
	}
	wait("both real tagged probes must be in flight", func() bool { return active.Load() == 2 && connections.Load() == 2 })
	o.Close()
	wait("both real probes must cancel naturally", func() bool { return active.Load() == 0 && connections.Load() == 0 })
	var wg sync.WaitGroup
	barrier := make(chan struct{})
	// Start and Close serialize in either order. A final Close is the quiescent boundary.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-barrier
			for j := 0; j < 8; j++ {
				if (i+j)%2 == 0 {
					o.Start()
				} else {
					o.Close()
				}
			}
		}(i)
	}
	close(barrier)
	wg.Wait()
	o.Close()
	wait("mixed calls left active probes", func() bool { return active.Load() == 0 && connections.Load() == 0 })
	before := requests.Load()
	time.Sleep(100 * time.Millisecond)
	if requests.Load() != before {
		t.Fatal("request after final Close")
	}
	healthy.Store(true)
	o.Start()
	wait("both tags recover", func() bool {
		m, _ := o.GetObservation(o.ctx)
		r := m.(*ObservationResult)
		return len(r.Status) == 2 && r.Status[0].Alive && r.Status[1].Alive
	})
	o.Close()
	retained, _ := o.GetObservation(o.ctx)
	serialized, err := proto.Marshal(retained)
	if err != nil {
		t.Fatal(err)
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			o.updateStatusForResult("probe0", &ProbeResult{Alive: i%2 == 0, Delay: int64(i)})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			m, _ := o.GetObservation(o.ctx)
			proto.Marshal(m)
			proto.Marshal(retained)
		}
	}()
	wg.Wait()
	after, err := proto.Marshal(retained)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(serialized, after) {
		t.Fatal("retained observation changed")
	}
	// Invalid URLs must report a failed probe, not panic or leave a worker alive.
	o.config.ProbeUrl = "://invalid"
	o.Start()
	wait("invalid URL was not reported", func() bool {
		m, _ := o.GetObservation(o.ctx)
		r := m.(*ObservationResult)
		return len(r.Status) == 2 && !r.Status[0].Alive && !r.Status[1].Alive
	})
	o.Close()
	o.config.SubjectSelector = []string{"absent"}
	o.Start()
	time.Sleep(30 * time.Millisecond)
	o.Close()
	if requests.Load() != before+2 {
		t.Fatalf("unexpected request from invalid/empty selector or duplicate worker: %d vs %d", requests.Load(), before+2)
	}
	wait("final natural cleanup", func() bool { return active.Load() == 0 && connections.Load() == 0 })
}
