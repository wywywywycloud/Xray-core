package retry_test

import (
	"context"
	"errors"
	"github.com/xtls/xray-core/common/retry"
	"testing"
	"testing/synctest"
	"time"
)

func TestContextualRetryBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := 0
		done := make(chan error, 1)
		go func() {
			done <- retry.OnContext(ctx, retry.Timed(5, 4000), func() error { calls++; return errors.New("retry") })
		}()
		synctest.Wait()
		if calls != 1 {
			t.Fatal(calls)
		}
		cancel()
		synctest.Wait()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		time.Sleep(6100 * time.Millisecond)
		if calls != 1 {
			t.Fatalf("retry after cancel: %d", calls)
		}
	})
}

func TestContextualRetryPreCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := retry.OnContext(ctx, retry.ExponentialBackoff(5, 100), func() error { t.Fatal("called after cancel"); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
