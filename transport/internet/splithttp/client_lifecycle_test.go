package splithttp

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countedResponse struct {
	io.ReadCloser
	closes      atomic.Int32
	readStarted chan struct{}
}

func (r *countedResponse) Read(p []byte) (int, error) {
	if r.readStarted != nil {
		close(r.readStarted)
	}
	return r.ReadCloser.Read(p)
}

func (r *countedResponse) Close() error {
	r.closes.Add(1)
	return r.ReadCloser.Close()
}

func TestWaitReadCloserPublicationAndClose(t *testing.T) {
	for _, order := range []string{"close-before-set", "set-before-close", "concurrent"} {
		t.Run(order, func(t *testing.T) {
			for i := 0; i < 50; i++ {
				left, right := net.Pipe()
				rc := &countedResponse{ReadCloser: left}
				w := &WaitReadCloser{Wait: make(chan struct{})}
				readDone := make(chan error, 1)
				go func() { _, err := w.Read(make([]byte, 1)); readDone <- err }()
				switch order {
				case "close-before-set":
					w.Close()
					w.Set(rc)
				case "set-before-close":
					w.Set(rc)
					written := make(chan error, 1)
					go func() { _, err := right.Write([]byte{42}); written <- err }()
					select {
					case err := <-written:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(3 * time.Second):
						t.Fatal("published reader did not receive bytes")
					}
					w.Close()
				case "concurrent":
					var workers sync.WaitGroup
					workers.Add(2)
					go func() { defer workers.Done(); w.Set(rc) }()
					go func() { defer workers.Done(); w.Close() }()
					workers.Wait()
				}
				w.Close()
				select {
				case <-readDone:
				case <-time.After(3 * time.Second):
					t.Fatal("reader remained blocked after close")
				}
				right.Close()
				if got := rc.closes.Load(); got != 1 {
					t.Fatalf("response closed %d times, want 1", got)
				}
			}
		})
	}
}

func TestWaitReadCloserInterruptsActiveRead(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	rc := &countedResponse{ReadCloser: left, readStarted: make(chan struct{})}
	w := &WaitReadCloser{Wait: make(chan struct{})}
	w.Set(rc)
	defer w.Close()
	readDone := make(chan error, 1)
	go func() { _, err := w.Read(make([]byte, 1)); readDone <- err }()
	select {
	case <-rc.readStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("read did not enter response body")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// The peer remains open: only closing our response can release this read.
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("blocked read unexpectedly succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not interrupt the response read")
	}
	if rc.closes.Load() != 1 {
		t.Fatal("response was not closed exactly once")
	}
}
