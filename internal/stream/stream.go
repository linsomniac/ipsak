// Package stream implements bounded TCP streams and verified ipsak transfers.
package stream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/muesli/cancelreader"
	"golang.org/x/term"
)

type Endpoint struct{ Listen, Connect string }

func ListenAddress(address string) (string, error) {
	if !strings.Contains(address, ":") {
		address = net.JoinHostPort("127.0.0.1", address)
	}
	return checkAddress(address, true)
}

func checkAddress(address string, listen bool) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("use host:port (IPv6: [address]:port): %w", err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 || (!listen && n == 0) {
		return "", fmt.Errorf("port must be %s", map[bool]string{true: "0–65535", false: "1–65535"}[listen])
	}
	if !listen && strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("connection host is required")
	}
	if strings.ContainsAny(host, "\x00\r\n\t ") {
		return "", fmt.Errorf("invalid endpoint host")
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

func (e Endpoint) Validate() error {
	if (e.Listen == "") == (e.Connect == "") {
		return fmt.Errorf("choose exactly one of --listen ADDRESS or --connect HOST:PORT")
	}
	if e.Listen != "" {
		_, err := ListenAddress(e.Listen)
		return err
	}
	_, err := checkAddress(e.Connect, false)
	return err
}

// Open accepts one connection or dials one peer. ready runs before Accept.
func Open(ctx context.Context, e Endpoint, ready func(string) error) (net.Conn, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.Connect != "" {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", e.Connect)
	}
	address, _ := ListenAddress(e.Listen)
	l, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	if ready != nil {
		if err := ready(l.Addr().String()); err != nil {
			return nil, err
		}
	}
	c, err := l.Accept()
	if ctx.Err() != nil {
		if c != nil {
			_ = c.Close()
		}
		return nil, ctx.Err()
	}
	return c, err
}

// ContextReader lets embedding callers supply input whose reads honor ctx.
// ReadContext must return promptly when ctx is canceled.
type ContextReader interface {
	ReadContext(context.Context, []byte) (int, error)
}

type input struct {
	reader  io.Reader
	cleanup func()
}
type contextInput struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextInput) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if cr, ok := r.reader.(ContextReader); ok {
		return cr.ReadContext(r.ctx, p)
	}
	return r.reader.Read(p)
}

// prepareInput does not take ownership of the caller's reader.
func prepareInput(ctx context.Context, r io.Reader) (input, error) {
	in := input{reader: contextInput{ctx, r}, cleanup: func() {}}
	if _, ok := r.(ContextReader); ok {
		return in, nil
	}
	switch r := r.(type) {
	case *bytes.Reader, *bytes.Buffer, *strings.Reader:
		return in, nil
	case *os.File:
		st, err := r.Stat()
		if err != nil {
			return input{}, err
		}
		if st.Mode().IsRegular() || immediateDevice(st) {
			return in, nil
		}
		if st.Mode()&os.ModeNamedPipe == 0 && !term.IsTerminal(int(r.Fd())) {
			return input{}, fmt.Errorf("input must be a regular file, pipe, or terminal")
		}
		cr, err := cancelreader.NewReader(r)
		if err != nil {
			return input{}, fmt.Errorf("prepare cancellable input: %w", err)
		}
		finished := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { cr.Cancel(); close(finished) })
		in.reader = cr
		in.cleanup = func() {
			if !stop() {
				<-finished
			}
			_ = cr.Close()
		}
		return in, nil
	default:
		return input{}, fmt.Errorf("custom input must implement stream.ContextReader for cancellation")
	}
}

// prepareOutput interrupts pipe writes without closing the caller's file.
func prepareOutput(ctx context.Context, w io.Writer) (io.Writer, func(), error) {
	f, ok := w.(*os.File)
	if !ok {
		return w, func() {}, nil
	}
	st, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if st.Mode().IsRegular() {
		return w, func() {}, nil
	}
	if immediateDevice(st) {
		return w, func() {}, nil
	}
	file, release, err := pollableOutput(f)
	if err != nil {
		return nil, nil, err
	}
	if err := file.SetWriteDeadline(time.Time{}); err != nil {
		release()
		return nil, nil, fmt.Errorf("output cannot support cancellation: %w", err)
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = file.SetWriteDeadline(time.Now()); close(done) })
	return file, func() {
		if !stop() {
			<-done
		}
		_ = file.SetWriteDeadline(time.Time{})
		release()
	}, nil
}

func immediateDevice(info os.FileInfo) bool {
	if info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	for _, name := range []string{os.DevNull, "/dev/full", "/dev/zero"} {
		if device, err := os.Stat(name); err == nil && os.SameFile(info, device) {
			return true
		}
	}
	return false
}

type Stats struct {
	Sent      int64  `json:"bytes_sent"`
	Received  int64  `json:"bytes_received"`
	SHA256    string `json:"sha256,omitempty"`
	Verified  bool   `json:"verified"`
	Committed bool   `json:"committed"`
}

func bindContext(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(done) })
	return func() {
		if !stop() {
			<-done
		}
	}
}

func contextError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func closeWrite(c net.Conn) error {
	if h, ok := c.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return fmt.Errorf("connection does not support TCP half-close")
}

// Duplex preserves independent TCP halves: EOF in either direction does not
// discard bytes from the other direction. Errors/cancellation stop and join both.
func Duplex(ctx context.Context, conn net.Conn, reader io.Reader, writer io.Writer) (Stats, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	in, err := prepareInput(ctx, reader)
	if err != nil {
		return Stats{}, err
	}
	defer in.cleanup()
	stop := bindContext(ctx, conn)
	defer stop()
	writer, cleanup, err := prepareOutput(ctx, writer)
	if err != nil {
		return Stats{}, err
	}
	defer cleanup()
	type result struct {
		n    int64
		err  error
		send bool
	}
	ch := make(chan result, 2)
	go func() {
		n, e := io.CopyBuffer(conn, struct{ io.Reader }{in.reader}, make([]byte, 65536))
		if e == nil {
			e = closeWrite(conn)
		}
		ch <- result{n, e, true}
	}()
	go func() {
		n, e := io.CopyBuffer(struct{ io.Writer }{writer}, struct{ io.Reader }{conn}, make([]byte, 65536))
		ch <- result{n, e, false}
	}()
	var stats Stats
	var first error
	for range 2 {
		r := <-ch
		if r.send {
			stats.Sent = r.n
		} else {
			stats.Received = r.n
		}
		if r.err != nil && first == nil {
			first = r.err
			cancel()
		}
	}
	// Internal cancellation is only used after recording an actual I/O error.
	if first != nil {
		return stats, first
	}
	return stats, contextError(ctx, nil)
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return fmt.Errorf("invalid write count")
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

var errTruncated = errors.New("truncated transfer")

// progress is called synchronously; returning an error aborts the transfer.
type Progress func(int64) error
