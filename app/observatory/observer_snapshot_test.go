package observatory

import (
	"context"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestObservationSnapshot(t *testing.T) {
	o := &Observer{}
	o.updateStatusForResult("direct", &ProbeResult{Alive: true, Delay: 10})
	snapshot, err := o.GetObservation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	o.updateStatusForResult("direct", &ProbeResult{Alive: false, LastErrorReason: "offline"})
	status := snapshot.(*ObservationResult).Status[0]
	if !status.Alive || status.Delay != 10 || status.LastErrorReason != "" {
		t.Fatalf("a later probe changed a retained snapshot: %v", status)
	}
	status.OutboundTag = "caller-owned"
	fresh, _ := o.GetObservation(context.Background())
	if fresh.(*ObservationResult).Status[0].OutboundTag != "direct" {
		t.Fatal("caller modified observer state")
	}
}

func TestObservationConcurrentSnapshot(t *testing.T) {
	o := &Observer{}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for i := 0; i < 500; i++ {
			o.updateStatusForResult("direct", &ProbeResult{Alive: true, Delay: int64(i)})
			if i%7 == 0 {
				o.clearRemovedOutbounds(nil)
			}
		}
	}()
	go func() {
		defer workers.Done()
		for i := 0; i < 500; i++ {
			snapshot, err := o.GetObservation(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := proto.Marshal(snapshot); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	workers.Wait()
}
