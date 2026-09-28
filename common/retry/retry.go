package retry // import "github.com/xtls/xray-core/common/retry"

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

var ErrRetryFailed = errors.New("all retry attempts failed")

// Strategy is a way to retry on a specific function.
type Strategy interface {
	// On performs a retry on a specific function, until it doesn't return any error.
	On(func() error) error
}

type retryer struct {
	totalAttempt int
	nextDelay    func() uint32
}

// On implements Strategy.On.
func (r *retryer) On(method func() error) error {
	return r.OnContext(context.Background(), method)
}

// OnContext keeps retry delays interruptible without changing Strategy.
func OnContext(ctx context.Context, strategy Strategy, method func() error) error {
	if contextual, ok := strategy.(interface {
		OnContext(context.Context, func() error) error
	}); ok {
		return contextual.OnContext(ctx, method)
	}
	return strategy.On(func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return method()
	})
}

func (r *retryer) OnContext(ctx context.Context, method func() error) error {
	attempt := 0
	accumulatedError := make([]error, 0, r.totalAttempt)
	for attempt < r.totalAttempt {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := method()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			return nil
		}
		numErrors := len(accumulatedError)
		if numErrors == 0 || err.Error() != accumulatedError[numErrors-1].Error() {
			accumulatedError = append(accumulatedError, err)
		}
		delay := r.nextDelay()
		timer := time.NewTimer(time.Duration(delay) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		attempt++
	}
	return errors.New(accumulatedError).Base(ErrRetryFailed)
}

// Timed returns a retry strategy with fixed interval.
func Timed(attempts int, delay uint32) Strategy {
	return &retryer{
		totalAttempt: attempts,
		nextDelay: func() uint32 {
			return delay
		},
	}
}

func ExponentialBackoff(attempts int, delay uint32) Strategy {
	nextDelay := uint32(0)
	return &retryer{
		totalAttempt: attempts,
		nextDelay: func() uint32 {
			r := nextDelay
			nextDelay += delay
			return r
		},
	}
}
