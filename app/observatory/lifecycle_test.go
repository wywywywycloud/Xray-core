package observatory

import (
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
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

func TestOrdinaryCloseAndRestartRealTagged(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		t.Run(fmt.Sprint(concurrent), func(t *testing.T) {
			var active, connections, requests atomic.Int64
			var healthy atomic.Bool
			started := make(chan struct{}, 32)
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				active.Add(1)
				defer active.Add(-1)
				started <- struct{}{}
				if healthy.Load() {
					w.WriteHeader(http.StatusNoContent)
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
			v, err := core.New(&core.Config{
				App:      []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})},
				Outbound: []*core.OutboundHandlerConfig{{Tag: "probe", ProxySettings: serial.ToTypedMessage(&freedom.Config{})}},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { v.Close() })
			if err = v.Start(); err != nil {
				t.Fatal(err)
			}
			obj, err := core.CreateObject(v, &Config{SubjectSelector: []string{"probe"}, ProbeUrl: s.URL, ProbeInterval: int64(time.Hour), EnableConcurrency: concurrent})
			if err != nil {
				t.Fatal(err)
			}
			o := obj.(*Observer)
			t.Cleanup(func() { o.Close() })
			settle := func() {
				t.Helper()
				deadline := time.Now().Add(time.Second)
				for time.Now().Before(deadline) && (active.Load() != 0 || connections.Load() != 0) {
					time.Sleep(5 * time.Millisecond)
				}
				if active.Load() != 0 || connections.Load() != 0 {
					t.Fatalf("natural cleanup: active=%d connections=%d", active.Load(), connections.Load())
				}
			}
			closeConcurrent := func() {
				t.Helper()
				done := make(chan struct{})
				go func() {
					var wg sync.WaitGroup
					for i := 0; i < 8; i++ {
						wg.Add(1)
						go func() { defer wg.Done(); o.Close() }()
					}
					wg.Wait()
					close(done)
				}()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("Close failed to stop worker promptly")
				}
			}
			for cycle := 0; cycle < 3; cycle++ {
				before := requests.Load()
				if err = o.Start(); err != nil {
					t.Fatal(err)
				}
				if err = o.Start(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-started:
				case <-time.After(2 * time.Second):
					t.Fatal("no active request")
				}
				if active.Load() != 1 {
					t.Fatal("phase not in flight")
				}
				closeConcurrent()
				settle()
				if requests.Load() != before+1 {
					t.Fatal("duplicate schedule")
				}
			}
			healthy.Store(true)
			if err = o.Start(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				m, e := o.GetObservation(o.ctx)
				if e != nil {
					t.Fatal(e)
				}
				r := m.(*ObservationResult)
				if len(r.Status) == 1 && r.Status[0].Alive {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			m, _ := o.GetObservation(o.ctx)
			if len(m.(*ObservationResult).Status) != 1 || !m.(*ObservationResult).Status[0].Alive {
				t.Fatal("restart failed to recover")
			}
			// A worker sleeping for the one-hour interval must also stop promptly.
			closeConcurrent()
			settle()
		})
	}
}
