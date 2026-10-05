// Package bandwidth measures receiver-observed throughput between cooperating peers.
package bandwidth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const magic = "IPSBW1\r\n"
const blockSize = 64 * 1024

type Options struct {
	Duration, MaxDuration time.Duration
	Direction             string
}

func (o Options) Validate() error {
	if o.Duration < time.Millisecond || o.Duration > time.Minute || o.MaxDuration < time.Millisecond || o.MaxDuration > time.Minute {
		return fmt.Errorf("duration and max-duration must be 1ms–1m")
	}
	if o.Direction != "upload" && o.Direction != "download" && o.Direction != "both" {
		return fmt.Errorf("direction must be upload, download, or both")
	}
	return nil
}

type Phase struct {
	Direction   string  `json:"direction"`
	Bytes       uint64  `json:"bytes"`
	ElapsedMS   float64 `json:"elapsed_ms"`
	Mbps        float64 `json:"mbps"`
	Complete    bool    `json:"complete"`
	Measurement string  `json:"measurement"`
}
type Result struct {
	Role       string  `json:"role"`
	Peer       string  `json:"peer"`
	DurationMS int64   `json:"requested_duration_ms"`
	Direction  string  `json:"direction"`
	Phases     []Phase `json:"phases"`
	Streams    int     `json:"streams"`
	Encrypted  bool    `json:"encrypted"`
}

func (r Result) CompactLines() []string {
	lines := []string{r.Role + " · " + r.Peer, "One TCP stream · directions relative to connecting peer"}
	for _, p := range r.Phases {
		state := "measuring"
		if p.Complete {
			state = "complete"
		}
		lines = append(lines, fmt.Sprintf("%-8s %9.2f Mbps · %d bytes · %.2fs · %s", p.Direction, p.Mbps, p.Bytes, p.ElapsedMS/1000, state), "  "+p.Measurement)
	}
	return lines
}
func snapshot(r Result) Result { r.Phases = append([]Phase(nil), r.Phases...); return r }
func progress(p *Phase, elapsed time.Duration) {
	p.ElapsedMS = float64(elapsed) / float64(time.Millisecond)
	if elapsed > 0 {
		p.Mbps = float64(p.Bytes) * 8 / elapsed.Seconds() / 1e6
	}
}

// Run uses bounded frames and receipts on a single TCP connection. Both reports
// use the connecting peer's upload/download perspective. No authentication is
// provided; this is a controlled diagnostic between known endpoints.
func Run(ctx context.Context, conn net.Conn, client bool, o Options, emit func(Result)) (Result, error) {
	r := Result{Role: "listener", Peer: conn.RemoteAddr().String(), Streams: 1, Phases: []Phase{}}
	if client {
		r.Role = "connector"
	}
	if err := o.Validate(); err != nil {
		return r, err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { conn.Close(); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	normalize := func(err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return r, err
	}
	header := make([]byte, 13)
	copy(header, magic)
	flags := byte(3)
	if o.Direction == "upload" {
		flags = 1
	}
	if o.Direction == "download" {
		flags = 2
	}
	if client {
		header[8] = flags
		binary.BigEndian.PutUint32(header[9:], uint32(o.Duration.Milliseconds()))
		if err := writeAll(conn, header); err != nil {
			return r, normalize(err)
		}
		ack := make([]byte, len(header))
		if _, err := io.ReadFull(conn, ack); err != nil {
			return r, normalize(err)
		}
		if !bytes.Equal(ack, header) {
			return r, fmt.Errorf("peer rejected or corrupted bandwidth negotiation")
		}
	} else {
		if _, err := io.ReadFull(conn, header); err != nil {
			return r, normalize(err)
		}
		flags = header[8]
		duration := time.Duration(binary.BigEndian.Uint32(header[9:])) * time.Millisecond
		if string(header[:8]) != magic || flags < 1 || flags > 3 || duration < time.Millisecond || duration > o.MaxDuration {
			return r, fmt.Errorf("invalid bandwidth handshake or requested duration exceeds listener maximum")
		}
		o.Duration = duration
		if err := writeAll(conn, header); err != nil {
			return r, normalize(err)
		}
	}
	r.DurationMS = o.Duration.Milliseconds()
	r.Direction = map[byte]string{1: "upload", 2: "download", 3: "both"}[flags]
	for _, direction := range []string{"upload", "download"} {
		if direction == "upload" && flags&1 == 0 || direction == "download" && flags&2 == 0 {
			continue
		}
		p := Phase{Direction: direction, Measurement: "receiver payload timing"}
		r.Phases = append(r.Phases, p)
		update := func(p Phase) {
			r.Phases[len(r.Phases)-1] = p
			if emit != nil {
				emit(snapshot(r))
			}
		}
		if err := conn.SetDeadline(time.Now().Add(o.Duration + 5*time.Second)); err != nil {
			return r, err
		}
		send := client && direction == "upload" || !client && direction == "download"
		var err error
		if send {
			p, err = sendPhase(conn, p, o.Duration, update)
		} else {
			p, err = receivePhase(conn, p, o.Duration, update)
		}
		update(p)
		if err != nil {
			return r, normalize(err)
		}
	}
	return r, nil
}
func sendPhase(c net.Conn, p Phase, duration time.Duration, emit func(Phase)) (Phase, error) {
	p.Measurement = "sender progress; final rate requires receiver receipt"
	payload := make([]byte, blockSize)
	if _, err := rand.Read(payload); err != nil {
		return p, err
	}
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], blockSize)
	start := time.Now()
	next := start.Add(100 * time.Millisecond)
	for time.Since(start) < duration {
		if err := writeAll(c, head[:]); err != nil {
			return p, err
		}
		n, err := writeCount(c, payload)
		p.Bytes += uint64(n)
		progress(&p, time.Since(start))
		if err != nil {
			return p, err
		}
		if time.Now().After(next) {
			emit(p)
			next = time.Now().Add(100 * time.Millisecond)
		}
	}
	if err := writeAll(c, make([]byte, 4)); err != nil {
		return p, err
	}
	var receipt [20]byte
	if _, err := io.ReadFull(c, receipt[:]); err != nil {
		return p, err
	}
	nanos := binary.BigEndian.Uint64(receipt[12:])
	received := binary.BigEndian.Uint64(receipt[4:12])
	if string(receipt[:4]) != "BWOK" || received != p.Bytes || nanos == 0 || nanos > uint64(duration+5*time.Second) {
		return p, fmt.Errorf("invalid receiver receipt")
	}
	p.Measurement = "receiver payload timing"
	p.Complete = true
	progress(&p, time.Duration(nanos))
	return p, nil
}
func receivePhase(c net.Conn, p Phase, duration time.Duration, emit func(Phase)) (Phase, error) {
	buf := make([]byte, blockSize)
	var head [4]byte
	var start, last time.Time
	next := time.Now()
	for {
		if _, err := io.ReadFull(c, head[:]); err != nil {
			return p, err
		}
		n := binary.BigEndian.Uint32(head[:])
		if n == 0 {
			break
		}
		if n > blockSize {
			return p, fmt.Errorf("bandwidth frame exceeds 64 KiB")
		}
		if start.IsZero() {
			start = time.Now()
		}
		read, err := io.ReadFull(c, buf[:n])
		last = time.Now()
		p.Bytes += uint64(read)
		progress(&p, last.Sub(start))
		if err != nil {
			return p, err
		}
		if last.After(next) {
			emit(p)
			next = last.Add(100 * time.Millisecond)
		}
	}
	elapsed := last.Sub(start)
	if p.Bytes == 0 || elapsed <= 0 || elapsed > duration+5*time.Second {
		return p, fmt.Errorf("empty or invalid bandwidth phase")
	}
	var receipt [20]byte
	copy(receipt[:4], "BWOK")
	binary.BigEndian.PutUint64(receipt[4:12], p.Bytes)
	binary.BigEndian.PutUint64(receipt[12:], uint64(elapsed))
	if err := writeAll(c, receipt[:]); err != nil {
		return p, err
	}
	p.Complete = true
	return p, nil
}
func writeCount(w io.Writer, p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := w.Write(p)
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}
func writeAll(w io.Writer, p []byte) error { _, err := writeCount(w, p); return err }
