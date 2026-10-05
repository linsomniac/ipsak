package bandwidth

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func opts(direction string) Options {
	return Options{Duration: 20 * time.Millisecond, MaxDuration: time.Second, Direction: direction}
}
func TestPairedDirectionsAndSnapshots(t *testing.T) {
	for _, direction := range []string{"upload", "download", "both"} {
		t.Run(direction, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			type answer struct {
				r Result
				e error
			}
			done := make(chan answer, 1)
			go func() { r, e := Run(ctx, b, false, opts(direction), nil); done <- answer{r, e} }()
			var snaps []Result
			r, e := Run(ctx, a, true, opts(direction), func(r Result) { snaps = append(snaps, r) })
			peer := <-done
			if e != nil || peer.e != nil {
				t.Fatalf("client %v server %v", e, peer.e)
			}
			count := 1
			if direction == "both" {
				count = 2
			}
			if len(r.Phases) != count || len(peer.r.Phases) != count {
				t.Fatal("missing phases")
			}
			for i, p := range r.Phases {
				q := peer.r.Phases[i]
				if !p.Complete || !q.Complete || p.Bytes == 0 || p.Bytes != q.Bytes || p.Mbps <= 0 || p.Mbps != q.Mbps || p.ElapsedMS != q.ElapsedMS {
					t.Fatalf("disagree %+v %+v", p, q)
				}
			}
			if direction == "both" && len(snaps[0].Phases) != 1 {
				t.Fatal("snapshot grew after publication")
			}
		})
	}
}
func handshake(t *testing.T, c net.Conn, duration time.Duration) {
	t.Helper()
	header := make([]byte, 13)
	copy(header, magic)
	header[8] = 1
	binary.BigEndian.PutUint32(header[9:], uint32(duration.Milliseconds()))
	if e := writeAll(c, header); e != nil {
		t.Fatal(e)
	}
	if _, e := io.ReadFull(c, make([]byte, 13)); e != nil {
		t.Fatal(e)
	}
}
func TestMalformedAndPartialFrames(t *testing.T) {
	for _, kind := range []string{"oversized", "partial", "empty"} {
		t.Run(kind, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			type answer struct {
				r Result
				e error
			}
			done := make(chan answer, 1)
			go func() { defer b.Close(); r, e := Run(ctx, b, false, opts("upload"), nil); done <- answer{r, e} }()
			handshake(t, a, 20*time.Millisecond)
			var h [4]byte
			switch kind {
			case "oversized":
				binary.BigEndian.PutUint32(h[:], blockSize+1)
			case "partial":
				binary.BigEndian.PutUint32(h[:], 4096)
			}
			if e := writeAll(a, h[:]); e != nil {
				t.Fatal(e)
			}
			if kind == "partial" {
				if e := writeAll(a, make([]byte, 123)); e != nil {
					t.Fatal(e)
				}
				a.Close()
			}
			r := <-done
			if r.e == nil || len(r.r.Phases) != 1 || r.r.Phases[0].Complete {
				t.Fatalf("%+v %v", r.r, r.e)
			}
			if kind == "partial" && r.r.Phases[0].Bytes != 123 {
				t.Fatal("lost partial count")
			}
		})
	}
}
func TestReceiptValidation(t *testing.T) {
	for _, bad := range []string{"magic", "bytes", "zero-time", "long-time"} {
		t.Run(bad, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				defer b.Close()
				header := make([]byte, 13)
				if _, e := io.ReadFull(b, header); e != nil {
					done <- e
					return
				}
				if e := writeAll(b, header); e != nil {
					done <- e
					return
				}
				var total uint64
				var h [4]byte
				for {
					if _, e := io.ReadFull(b, h[:]); e != nil {
						done <- e
						return
					}
					n := binary.BigEndian.Uint32(h[:])
					if n == 0 {
						break
					}
					if _, e := io.CopyN(io.Discard, b, int64(n)); e != nil {
						done <- e
						return
					}
					total += uint64(n)
				}
				var ack [20]byte
				copy(ack[:4], "BWOK")
				binary.BigEndian.PutUint64(ack[4:12], total)
				binary.BigEndian.PutUint64(ack[12:], uint64(time.Millisecond))
				switch bad {
				case "magic":
					ack[0] = 'X'
				case "bytes":
					binary.BigEndian.PutUint64(ack[4:12], total+1)
				case "zero-time":
					binary.BigEndian.PutUint64(ack[12:], 0)
				case "long-time":
					binary.BigEndian.PutUint64(ack[12:], uint64(time.Hour))
				}
				done <- writeAll(b, ack[:])
			}()
			r, err := Run(ctx, a, true, opts("upload"), nil)
			if err == nil || r.Phases[0].Complete || r.Phases[0].Bytes == 0 {
				t.Fatalf("%+v %v", r, err)
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestNegotiationLimitsAndCancellation(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		defer b.Close()
		o := opts("both")
		o.MaxDuration = 10 * time.Millisecond
		_, e := Run(ctx, b, false, o, nil)
		done <- e
	}()
	header := make([]byte, 13)
	copy(header, magic)
	header[8] = 1
	binary.BigEndian.PutUint32(header[9:], 11)
	if e := writeAll(a, header); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e == nil {
		t.Fatal("accepted excessive peer duration")
	}
	a, b = net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel = context.WithCancel(context.Background())
	go func() { _, e := Run(ctx, b, false, opts("both"), nil); done <- e }()
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("stalled handshake did not cancel")
	}
}

func TestCancellationMidPhaseRetainsProgress(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type answer struct {
		r Result
		e error
	}
	done := make(chan answer, 1)
	go func() { r, e := Run(ctx, b, false, opts("upload"), nil); done <- answer{r, e} }()
	handshake(t, a, 20*time.Millisecond)
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], 4096)
	if e := writeAll(a, h[:]); e != nil {
		t.Fatal(e)
	}
	if e := writeAll(a, make([]byte, 123)); e != nil {
		t.Fatal(e)
	}
	cancel()
	select {
	case r := <-done:
		if !errors.Is(r.e, context.Canceled) || len(r.r.Phases) != 1 || r.r.Phases[0].Bytes != 123 || r.r.Phases[0].Complete {
			t.Fatalf("%+v %v", r.r, r.e)
		}
	case <-time.After(time.Second):
		t.Fatal("midphase did not cancel")
	}
}
