package stream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	a, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.Accept()
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a.(*net.TCPConn), b.(*net.TCPConn)
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestAddressAndCanceledAccept(t *testing.T) {
	for _, test := range []struct{ input, want string }{{"9000", "127.0.0.1:9000"}, {":0", ":0"}, {"[::1]:0", "[::1]:0"}} {
		got, err := ListenAddress(test.input)
		if err != nil || got != test.want {
			t.Fatalf("%q: %q %v", test.input, got, err)
		}
	}
	for _, e := range []Endpoint{{}, {Listen: "0", Connect: "localhost:1"}, {Listen: "-1"}, {Connect: ":1"}, {Connect: "localhost:0"}, {Connect: "[::1]:65536"}} {
		if e.Validate() == nil {
			t.Fatalf("accepted %+v", e)
		}
	}
	ctx, cancel := context.WithCancel(testContext(t))
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		_, err := Open(ctx, Endpoint{Listen: "0"}, func(a string) error { ready <- a; return nil })
		done <- err
	}()
	address := <-ready
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if c, err := net.DialTimeout("tcp", address, 50*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("listener leaked")
	}
}

func TestDuplexHalfCloseDrainsResponse(t *testing.T) {
	a, b := tcpPair(t)
	peer := make(chan error, 1)
	go func() {
		request, err := io.ReadAll(b)
		if err == nil && string(request) != "request" {
			err = errors.New("wrong request")
		}
		if err == nil {
			_, err = b.Write([]byte("response"))
		}
		_ = b.CloseWrite()
		peer <- err
	}()
	var output bytes.Buffer
	stats, err := Duplex(testContext(t), a, strings.NewReader("request"), &output)
	if err != nil || output.String() != "response" || stats.Sent != 7 || stats.Received != 8 {
		t.Fatal(stats, err, output.String())
	}
	if err := <-peer; err != nil {
		t.Fatal(err)
	}
}

type gatedInput struct {
	release <-chan struct{}
	sent    bool
}

func (g *gatedInput) Read([]byte) (int, error) { panic("ReadContext expected") }
func (g *gatedInput) ReadContext(ctx context.Context, p []byte) (int, error) {
	if g.sent {
		return 0, io.EOF
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-g.release:
		g.sent = true
		return copy(p, "after-fin"), nil
	}
}

type finConn struct {
	net.Conn
	observed chan struct{}
}

func (c *finConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err == io.EOF {
		close(c.observed)
	}
	return n, err
}
func (c *finConn) CloseWrite() error { return c.Conn.(*net.TCPConn).CloseWrite() }

func TestDuplexRemoteFINPreservesInput(t *testing.T) {
	a, b := tcpPair(t)
	fin := make(chan struct{})
	wrapped := &finConn{a, fin}
	if err := b.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	peer := make(chan []byte, 1)
	go func() { data, _ := io.ReadAll(b); peer <- data }()
	stats, err := Duplex(testContext(t), wrapped, &gatedInput{release: fin}, io.Discard)
	if err != nil || stats.Sent != 9 || string(<-peer) != "after-fin" {
		t.Fatal(stats, err)
	}
}

func TestDuplexCancellationDoesNotClosePipeInput(t *testing.T) {
	a, _ := tcpPair(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithCancel(testContext(t))
	done := make(chan error, 1)
	go func() { _, err := Duplex(ctx, a, r, io.Discard); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("missing cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("input pump stuck")
	}
	if _, err := w.Write([]byte("ok")); err != nil {
		t.Fatal("caller input closed", err)
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(r, p); err != nil || string(p) != "ok" {
		t.Fatal(err, string(p))
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("output failed") }

func TestDuplexOutputFailureJoinsBlockedInput(t *testing.T) {
	a, b := tcpPair(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	go func() { _, _ = b.Write([]byte("response")) }()
	_, err = Duplex(testContext(t), a, r, failedWriter{})
	if err == nil || !strings.Contains(err.Error(), "output failed") {
		t.Fatal(err)
	}
}

func TestVerifiedTransfersBothDirections(t *testing.T) {
	for _, senderListens := range []bool{false, true} {
		for _, payload := range [][]byte{nil, []byte("hello\x00world"), bytes.Repeat([]byte("ipsak"), 50000)} {
			t.Run(strings.Join([]string{map[bool]string{true: "sender-listens", false: "receiver-listens"}[senderListens], string(rune('a' + len(payload)%26))}, "/"), func(t *testing.T) {
				ctx := testContext(t)
				ready := make(chan string, 1)
				type result struct {
					stats Stats
					err   error
				}
				done := make(chan result, 1)
				var output bytes.Buffer
				go func() {
					c, err := Open(ctx, Endpoint{Listen: "0"}, func(a string) error { ready <- a; return nil })
					if err != nil {
						done <- result{err: err}
						return
					}
					defer c.Close()
					var s Stats
					if senderListens {
						s, err = Send(ctx, c, bytes.NewReader(payload), nil)
					} else {
						s, err = Receive(ctx, c, &output, 0, nil, nil)
					}
					done <- result{s, err}
				}()
				c, err := Open(ctx, Endpoint{Connect: <-ready}, nil)
				if err != nil {
					t.Fatal(err)
				}
				var stats Stats
				if senderListens {
					stats, err = Receive(ctx, c, &output, 0, nil, nil)
				} else {
					stats, err = Send(ctx, c, bytes.NewReader(payload), nil)
				}
				c.Close()
				other := <-done
				if err != nil || other.err != nil || !stats.Verified || !other.stats.Verified || !bytes.Equal(output.Bytes(), payload) {
					t.Fatalf("%+v %v; %+v %v output=%d", stats, err, other.stats, other.err, output.Len())
				}
			})
		}
	}
}

func transferWire(payload []byte) []byte {
	buf := bytes.NewBufferString(magic)
	if len(payload) > 0 {
		_ = binary.Write(buf, binary.BigEndian, uint32(len(payload)))
		buf.Write(payload)
	}
	_ = binary.Write(buf, binary.BigEndian, uint32(0))
	_ = binary.Write(buf, binary.BigEndian, uint64(len(payload)))
	sum := sha256.Sum256(payload)
	buf.Write(sum[:])
	return buf.Bytes()
}

func TestReceiveRejectsMalformedTruncatedAndOversize(t *testing.T) {
	valid := transferWire([]byte("payload"))
	hashBad := bytes.Clone(valid)
	hashBad[len(hashBad)-1] ^= 1
	countBad := bytes.Clone(valid)
	countBad[len(countBad)-33] ^= 1
	frameBad := []byte(magic)
	frameBad = binary.BigEndian.AppendUint32(frameBad, maxFrame+1)
	for _, test := range []struct {
		name  string
		wire  []byte
		limit int64
		want  string
	}{{"magic", []byte("notipsak"), 0, "protocol"}, {"hash", hashBad, 0, "SHA-256"}, {"count", countBad, 0, "count"}, {"truncated", valid[:len(valid)-1], 0, "truncated"}, {"extra", append(bytes.Clone(valid), 1), 0, "unexpected"}, {"frame", frameBad, 0, "frame exceeds"}, {"limit", valid, 3, "byte limit"}} {
		t.Run(test.name, func(t *testing.T) {
			a, b := tcpPair(t)
			go func() { _, _ = b.Write(test.wire); _ = b.CloseWrite() }()
			var output bytes.Buffer
			committed := false
			stats, err := Receive(testContext(t), a, &output, test.limit, func() error { committed = true; return nil }, nil)
			if err == nil || !strings.Contains(err.Error(), test.want) || committed || stats.Committed {
				t.Fatal(stats, err, committed)
			}
		})
	}
}

func TestReceiveCommitAndWriteFailuresNeverAcknowledge(t *testing.T) {
	for _, writeFails := range []bool{true, false} {
		t.Run(map[bool]string{true: "write", false: "commit"}[writeFails], func(t *testing.T) {
			a, b := tcpPair(t)
			ctx := testContext(t)
			done := make(chan error, 1)
			go func() { _, err := Send(ctx, b, strings.NewReader("hello"), nil); done <- err }()
			var output io.Writer = &bytes.Buffer{}
			if writeFails {
				output = failedWriter{}
			}
			stats, err := Receive(ctx, a, output, 0, func() error { return errors.New("commit failed") }, nil)
			a.Close()
			if err == nil || stats.Committed {
				t.Fatal(stats, err)
			}
			if err := <-done; err == nil {
				t.Fatal("sender accepted failed output")
			}
		})
	}
}

func TestReceiveCancellationAndSenderMissingACK(t *testing.T) {
	t.Run("receive", func(t *testing.T) {
		a, _ := tcpPair(t)
		ctx, cancel := context.WithCancel(testContext(t))
		cancel()
		_, err := Receive(ctx, a, io.Discard, 0, nil, nil)
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("send-ack", func(t *testing.T) {
		a, b := tcpPair(t)
		go func() { _, _ = io.Copy(io.Discard, b); b.Close() }()
		stats, err := Send(testContext(t), a, strings.NewReader("hello"), nil)
		if err == nil || stats.Verified {
			t.Fatal(stats, err)
		}
	})
	t.Run("send-input", func(t *testing.T) {
		a, _ := tcpPair(t)
		r, w, _ := os.Pipe()
		defer r.Close()
		defer w.Close()
		ctx, cancel := context.WithCancel(testContext(t))
		done := make(chan error, 1)
		go func() { _, err := Send(ctx, a, r, nil); done <- err }()
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("sender stuck")
		}
	})
}

func TestAtomicOutputNoOverwriteAndAbort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "received")
	output, err := NewOutput(path, false)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = output.File.WriteString("new")
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := output.Commit(); err == nil {
		t.Fatal("overwrote racing destination")
	}
	output.Abort()
	data, _ := os.ReadFile(path)
	if string(data) != "existing" {
		t.Fatal(string(data))
	}
	if _, err := NewOutput(path, false); err == nil {
		t.Fatal("accepted existing destination")
	}
	forced, err := NewOutput(path, true)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = forced.File.WriteString("replacement")
	if err := forced.Commit(); err != nil {
		t.Fatal(err)
	}
	forced.Abort()
	data, _ = os.ReadFile(path)
	if string(data) != "replacement" {
		t.Fatal(string(data))
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal(st, err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewOutput(link, true); err == nil {
		t.Fatal("accepted symlink")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".ipsak-") {
			t.Fatal("temporary file leaked", e.Name())
		}
	}
}
