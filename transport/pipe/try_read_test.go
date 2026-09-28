package pipe_test

import (
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common/buf"
	. "github.com/xtls/xray-core/transport/pipe"
)

func TestTryReadMultiBuffer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, w := New(WithSizeLimit(0))
		defer w.Close()
		start := time.Now()
		if mb, err := r.TryReadMultiBuffer(); len(mb) != 0 || err != nil {
			t.Fatalf("empty: %v %v", mb, err)
		}
		if time.Since(start) != 0 {
			t.Fatal("empty read waited")
		}
		first, second := buf.New(), buf.New()
		first.WriteString("first")
		second.WriteString("second")
		if err := w.WriteMultiBuffer(buf.MultiBuffer{first}); err != nil {
			t.Fatal(err)
		}
		written := make(chan error, 1)
		go func() { written <- w.WriteMultiBuffer(buf.MultiBuffer{second}) }()
		synctest.Wait()
		if len(written) != 0 {
			t.Fatal("writer not blocked")
		}
		mb, err := r.TryReadMultiBuffer()
		if err != nil || len(mb) != 1 || mb[0] != first || mb.String() != "first" {
			t.Fatalf("first ownership: %v %v", mb, err)
		}
		buf.ReleaseMulti(mb)
		synctest.Wait()
		if err := <-written; err != nil {
			t.Fatal(err)
		}
		w.Close()
		mb, err = r.TryReadMultiBuffer()
		if err != nil || len(mb) != 1 || mb[0] != second || mb.String() != "second" {
			t.Fatalf("close drain: %v %v", mb, err)
		}
		buf.ReleaseMulti(mb)
		if mb, err = r.TryReadMultiBuffer(); len(mb) != 0 || err != io.EOF {
			t.Fatalf("EOF: %v %v", mb, err)
		}
	})
}

func TestTryReadMultiBufferErrors(t *testing.T) {
	r, w := New()
	want := errors.New("injected")
	r.ReturnAnError(want)
	if mb, err := r.TryReadMultiBuffer(); len(mb) != 0 || err != want {
		t.Fatalf("injected: %v %v", mb, err)
	}
	b := buf.New()
	b.WriteString("owned by pipe")
	w.WriteMultiBuffer(buf.MultiBuffer{b})
	r.Interrupt()
	if b.Len() != 0 {
		t.Fatal("interrupt did not release queued data")
	}
	if mb, err := r.TryReadMultiBuffer(); len(mb) != 0 || err != io.ErrClosedPipe {
		t.Fatalf("interrupt: %v %v", mb, err)
	}
}
