package observatory

import (
	"context"
	goErrors "errors"
	"strings"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/session"
)

func TestErrorCollectorSnapshotAfterDelayedFeedback(t *testing.T) {
	e := newErrorCollector()
	first, late := goErrors.New("first failure"), goErrors.New("late cancellation failure")
	e.SubmitError(first)
	previous := e.UnderlyingError()
	before := previous.Error()
	ctx := session.TrackedConnectionError(context.Background(), e)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				session.SubmitOutboundErrorToOriginator(ctx, late)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = e.UnderlyingError().Error()
				_ = previous.Error()
			}
		}()
	}
	wg.Wait()
	if previous.Error() != before {
		t.Fatal("published report mutated after asynchronous feedback")
	}
	report := e.UnderlyingError()
	if !goErrors.Is(report, first) || !goErrors.Is(report, late) {
		t.Fatal("lost error causes")
	}
	if strings.Count(report.Error(), "late cancellation failure") != 80 {
		t.Fatal("lost concurrent feedback")
	}
}
