package splithttp

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

func packetBuffers(data []byte, segmentation int) buf.MultiBuffer {
	var mb buf.MultiBuffer
	for len(data) > 0 {
		n := min(len(data), segmentation, buf.Size)
		b := buf.New()
		b.Write(data[:n])
		mb = append(mb, b)
		data = data[n:]
	}
	return mb
}

func TestPacketUpExactSplit(t *testing.T) {
	for _, segmentation := range []int{17, 4093, buf.Size} {
		for _, size := range []int32{1, 127, 8191, 8192, 8193, 16385, 20001, 32767, 65537, 100003, 131071} {
			t.Run(fmt.Sprintf("segments=%d/size=%d", segmentation, size), func(t *testing.T) {
				want := make([]byte, 2*int(size)+31)
				for i := range want {
					want[i] = byte(i * 31)
				}
				mb := packetBuffers(want, segmentation)
				var got []byte
				for !mb.IsEmpty() {
					before := mb.Len()
					old := map[*buf.Buffer]bool{}
					for _, b := range mb {
						old[b] = true
					}
					var chunk buf.MultiBuffer
					mb, chunk = splitPacketUp(mb, size)
					if chunk.Len() != min(size, before) {
						t.Fatalf("got %d, want %d", chunk.Len(), min(size, before))
					}
					seen := map[*buf.Buffer]bool{}
					created := 0
					for _, part := range []buf.MultiBuffer{chunk, mb} {
						for _, b := range part {
							if seen[b] {
								t.Fatal("buffer has two owners")
							}
							seen[b] = true
							if !old[b] {
								created++
							}
						}
					}
					if created > 1 {
						t.Fatalf("created %d payload buffers", created)
					}
					for _, b := range chunk {
						got = append(got, b.Bytes()...)
					}
					buf.ReleaseMulti(chunk)
				}
				if !bytes.Equal(got, want) {
					t.Fatal("payload mismatch after releasing each chunk")
				}
			})
		}
	}
}

func TestPacketUpWriterOwnership(t *testing.T) {
	reader, writer := pipe.New(pipe.WithSizeLimit(32767))
	w := uploadWriter{writer, 32768}
	done := make(chan int, 1)
	go func() {
		total := 0
		for {
			mb, err := reader.ReadMultiBuffer()
			if err != nil {
				break
			}
			total += int(mb.Len())
			buf.ReleaseMulti(mb)
		}
		done <- total
	}()
	data := make([]byte, 1<<20)
	for i := 0; i < 8; i++ {
		if n, err := w.Write(data); n != len(data) || err != nil {
			t.Fatalf("write %d: %d %v", i, n, err)
		}
	}
	w.Close()
	if n := <-done; n != 8*len(data) {
		t.Fatalf("received %d bytes", n)
	}
	if n, err := w.Write(data); n != 0 || err != io.ErrClosedPipe {
		t.Fatalf("closed write: %d %v", n, err)
	}
}

func BenchmarkPacketUpSplit(b *testing.B) {
	for _, exact := range []bool{false, true} {
		b.Run(fmt.Sprintf("exact=%v", exact), func(b *testing.B) {
			data := make([]byte, 1<<20)
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				mb := packetBuffers(data, buf.Size)
				for !mb.IsEmpty() {
					var chunk buf.MultiBuffer
					if exact {
						mb, chunk = splitPacketUp(mb, 20001)
					} else {
						mb, chunk = buf.SplitSize(mb, 20001)
					}
					buf.ReleaseMulti(chunk)
				}
			}
		})
	}
}

func BenchmarkPacketUpClosedWriter(b *testing.B) {
	_, writer := pipe.New(pipe.WithSizeLimit(32767))
	w := uploadWriter{writer, 32768}
	w.Close()
	data := make([]byte, 1<<20)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if n, err := w.Write(data); n != 0 || err != io.ErrClosedPipe {
			b.Fatalf("closed write: %d %v", n, err)
		}
	}
}
