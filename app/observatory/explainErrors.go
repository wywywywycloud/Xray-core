package observatory

import (
	goErrors "errors"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

type errorCollector struct {
	mu     sync.Mutex
	errors []error
}

func (e *errorCollector) SubmitError(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.errors = append(e.errors, errors.New("underlying connection error").Base(err))
}

func newErrorCollector() *errorCollector {
	return &errorCollector{}
}

func (e *errorCollector) UnderlyingError() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.errors) == 0 {
		return errors.New("failed to produce report")
	}
	// Join copies the slice; later submissions must not mutate a published report.
	return goErrors.Join(e.errors...)
}
