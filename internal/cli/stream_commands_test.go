package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

type readyWriter struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	address chan string
	once    sync.Once
}

func newReadyWriter() *readyWriter { return &readyWriter{address: make(chan string, 1)} }
func (w *readyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, _ := w.buffer.Write(p)
	line := w.buffer.String()
	if i := strings.Index(line, " listening on "); i >= 0 {
		tail := line[i+len(" listening on "):]
		if j := strings.IndexByte(tail, '\n'); j >= 0 {
			w.once.Do(func() { w.address <- tail[:j] })
		}
	}
	return n, nil
}
func (w *readyWriter) String() string { w.mu.Lock(); defer w.mu.Unlock(); return w.buffer.String() }

func TestStreamJSONPreflightAndValidation(t *testing.T) {
	for _, args := range [][]string{{"connect", "127.0.0.1:1", "--json"}, {"listen", "0", "--json"}, {"receive", "--listen", "0", "--json"}, {"receive", "-", "--listen", "0", "--json"}, {"send"}, {"send", "--listen", "0", "--connect", "127.0.0.1:1"}, {"receive", "--listen", "0", "--max-bytes", "-1"}, {"connect", "localhost:0"}, {"listen", "0", "--force"}, {"serve", "0", "--duration", "-1s"}, {"serve", "0", "--status", "204", "--body", "x"}} {
		out, stderr, code := invoke(args...)
		if code != 2 || out != "" || stderr == "" {
			t.Fatalf("%v: %d %q %q", args, code, out, stderr)
		}
	}
}

func TestTransferCLIOptionalFilenameBothDirections(t *testing.T) {
	for _, sendListens := range []bool{false, true} {
		for _, files := range []bool{false, true} {
			t.Run(fmt.Sprintf("sender-listens=%v/files=%v", sendListens, files), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				dir := t.TempDir()
				source := filepath.Join(dir, "source")
				destination := filepath.Join(dir, "destination")
				payload := bytes.Repeat([]byte("stream\x00payload"), 15000)
				if err := os.WriteFile(source, payload, 0600); err != nil {
					t.Fatal(err)
				}
				listenName, dialName := "receive", "send"
				if sendListens {
					listenName, dialName = "send", "receive"
				}
				makeArgs := func(name, direction, address string) []string {
					args := []string{name}
					if files {
						if name == "send" {
							args = append(args, source)
						} else {
							args = append(args, destination)
						}
					}
					args = append(args, direction, address, "--plain")
					if name == "send" || files {
						args = append(args, "--json")
					}
					return args
				}
				listenerErr := newReadyWriter()
				var listenerOut bytes.Buffer
				done := make(chan int, 1)
				go func() {
					done <- Execute(ctx, makeArgs(listenName, "--listen", "0"), bytes.NewReader(payload), &listenerOut, listenerErr, "test")
				}()
				var address string
				select {
				case address = <-listenerErr.address:
				case <-ctx.Done():
					t.Fatal("no readiness", listenerErr.String())
				}
				var dialOut, dialErr bytes.Buffer
				code := Execute(ctx, makeArgs(dialName, "--connect", address), bytes.NewReader(payload), &dialOut, &dialErr, "test")
				other := <-done
				if code != 0 || other != 0 {
					t.Fatal(code, other, dialErr.String(), listenerErr.String())
				}
				receiveOut, sendOut := listenerOut.Bytes(), dialOut.Bytes()
				if sendListens {
					receiveOut, sendOut = dialOut.Bytes(), listenerOut.Bytes()
				}
				var report streamReport
				if err := json.Unmarshal(sendOut, &report); err != nil || report.Stream == nil || !report.Stream.Verified || report.Stream.Sent != int64(len(payload)) {
					t.Fatal(err, string(sendOut))
				}
				if files {
					if err := json.Unmarshal(receiveOut, &report); err != nil || report.Stream == nil || !report.Stream.Committed {
						t.Fatal(err, string(receiveOut))
					}
					data, err := os.ReadFile(destination)
					if err != nil || !bytes.Equal(data, payload) {
						t.Fatal(err, len(data))
					}
				} else if !bytes.Equal(receiveOut, payload) {
					t.Fatal("stdout payload changed", len(receiveOut))
				}
			})
		}
	}
}

func TestConnectCLIExactPayloadAndJSONCapture(t *testing.T) {
	for _, capture := range []bool{false, true} {
		t.Run(fmt.Sprint(capture), func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			done := make(chan error, 1)
			go func() {
				c, err := l.Accept()
				if err != nil {
					done <- err
					return
				}
				defer c.Close()
				data, err := io.ReadAll(c)
				if err == nil && string(data) != "request" {
					err = fmt.Errorf("wrong payload %q", data)
				}
				if err == nil {
					_, err = io.WriteString(c, "reply\x00bytes")
				}
				done <- err
			}()
			args := []string{"connect", l.Addr().String()}
			path := filepath.Join(t.TempDir(), "capture")
			if capture {
				args = append(args, "--json", "--output", path)
			}
			var out, stderr bytes.Buffer
			code := Execute(context.Background(), args, strings.NewReader("request"), &out, &stderr, "test")
			if code != 0 {
				t.Fatal(code, stderr.String())
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if capture {
				var report streamReport
				if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.Command != "connect" || !report.Stream.Committed {
					t.Fatal(err, out.String())
				}
				data, _ := os.ReadFile(path)
				if string(data) != "reply\x00bytes" {
					t.Fatal(string(data))
				}
			} else if out.String() != "reply\x00bytes" {
				t.Fatal(out.String())
			}
		})
	}
}

func TestListenCLIPayloadAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stderr := newReadyWriter()
	var out bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- Execute(ctx, []string{"listen", "0", "--plain"}, strings.NewReader("server"), &out, stderr, "test")
	}()
	address := <-stderr.address
	c, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "client")
	_ = c.(*net.TCPConn).CloseWrite()
	data, err := io.ReadAll(c)
	c.Close()
	if err != nil || string(data) != "server" {
		t.Fatal(string(data), err)
	}
	if code := <-done; code != 0 || out.String() != "client" {
		t.Fatal(code, out.String(), stderr.String())
	}
	stopCtx, stop := context.WithCancel(context.Background())
	stopErr := newReadyWriter()
	var stopOut bytes.Buffer
	go func() {
		done <- Execute(stopCtx, []string{"receive", filepath.Join(t.TempDir(), "dest"), "--listen", "0", "--json"}, strings.NewReader(""), &stopOut, stopErr, "test")
	}()
	<-stopErr.address
	stop()
	if code := <-done; code != 130 {
		t.Fatal(code, stopErr.String())
	}
	var report streamReport
	if err := json.Unmarshal(stopOut.Bytes(), &report); err != nil || report.Status != "interrupted" {
		t.Fatal(err, stopOut.String())
	}
}

func TestReceiveCLIFailurePreservesFileAndCleansTemporary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing")
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	out, _, code := invoke("receive", path, "--connect", "127.0.0.1:1", "--json")
	if code != 1 || !json.Valid([]byte(out)) {
		t.Fatal(code, out)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.WriteString(c, "IPSAK1\r\n")
	}()
	out, stderr, code := invoke("receive", path, "--connect", l.Addr().String(), "--force", "--json")
	if code != 1 || !json.Valid([]byte(out)) {
		t.Fatal(code, out, stderr)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "existing" {
		t.Fatal(string(data))
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("temporary leaked", entries)
	}
}

func TestSendCLIFIFOFileDoesNotBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := invoke("send", path, "--connect", "127.0.0.1:1")
	if code != 1 || !strings.Contains(stderr, "regular file") {
		t.Fatal(code, stderr)
	}
}

func TestServeCLIJSONDuration(t *testing.T) {
	out, stderr, code := invoke("serve", "0", "--duration", "20ms", "--json")
	if code != 0 {
		t.Fatal(code, stderr)
	}
	var report streamReport
	if err := json.Unmarshal([]byte(out), &report); err != nil || report.Server == nil || report.Server.Address == "" || report.Status != "ok" {
		t.Fatal(err, out)
	}
}

func TestStreamCanceledPreflight(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, args := range [][]string{{"connect", "127.0.0.1:1"}, {"listen", "0"}, {"send", "--listen", "0"}, {"receive", "--listen", "0"}, {"serve", "0"}} {
		var out, stderr bytes.Buffer
		if code := Execute(ctx, args, strings.NewReader(""), &out, &stderr, "test"); code != 130 || out.Len() != 0 {
			t.Fatal(args, code, out.String(), stderr.String())
		}
	}
}

func TestStreamSessionTimeoutDefaultAndPlacement(t *testing.T) {
	for _, name := range []string{"connect", "listen", "send", "receive"} {
		for _, tt := range []struct {
			args []string
			want time.Duration
		}{{[]string{name}, 0}, {[]string{name, "--timeout", "0"}, 0}, {[]string{name, "--timeout", ".25"}, 250 * time.Millisecond}, {[]string{"--timeout", "250ms", name}, 250 * time.Millisecond}} {
			root := New("test")
			cmd, _, err := root.Find([]string{name})
			if err != nil {
				t.Fatal(err)
			}
			cmd.Args = cobra.ArbitraryArgs
			cmd.RunE = func(cmd *cobra.Command, _ []string) error {
				got, err := cmd.Flags().GetDuration("timeout")
				if err != nil || got != tt.want {
					t.Fatal(tt.args, got, err)
				}
				return nil
			}
			root.SetArgs(tt.args)
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestStreamExpiredAndCanceledJSONPreflight(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprint(expired), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if expired {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			}
			cancel()
			for _, args := range [][]string{{"connect", "127.0.0.1:1", "--output", filepath.Join(t.TempDir(), "out")}, {"listen", "0", "--output", filepath.Join(t.TempDir(), "out")}, {"send", "--listen", "0"}, {"receive", filepath.Join(t.TempDir(), "out"), "--listen", "0"}, {"serve", "0"}} {
				var out, stderr bytes.Buffer
				code := Execute(ctx, append(args, "--json"), strings.NewReader(""), &out, &stderr, "test")
				wantCode, wantStatus := 130, "interrupted"
				if expired {
					wantCode, wantStatus = 1, "error"
				}
				var report streamReport
				if err := json.Unmarshal(out.Bytes(), &report); err != nil || code != wantCode || report.Status != wantStatus {
					t.Fatal(args, code, err, out.String(), stderr.String())
				}
			}
		})
	}
}

func TestStreamExplicitSessionDeadline(t *testing.T) {
	out, stderr, code := invoke("receive", filepath.Join(t.TempDir(), "out"), "--listen", "0", "--timeout", "20ms", "--json")
	var report streamReport
	if err := json.Unmarshal([]byte(out), &report); err != nil || code != 1 || report.Status != "error" || !strings.Contains(report.Error, "deadline") {
		t.Fatal(code, err, out, stderr)
	}
}
