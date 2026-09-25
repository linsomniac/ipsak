package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func serverOptions() ServerOptions {
	return ServerOptions{Address: "0", Status: 200, Timeout: time.Second, MaxBody: 65536, MaxConnections: 4}
}

func TestDiagnosticHandlerEchoAndLimits(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  int
		body    string
		bodySet bool
		payload string
		limit   int64
		want    int
	}{{"echo", 200, "", false, "hello\x00", 6, 200}, {"custom", 503, "maintenance", true, "", 0, 503}, {"empty-custom", 200, "", true, "", 0, 200}, {"oversized", 200, "", false, "xx", 1, 413}, {"zero-limit", 200, "", false, "x", 0, 413}, {"no-content", 204, "", false, "", 0, 204}} {
		t.Run(test.name, func(t *testing.T) {
			o := serverOptions()
			o.Status = test.status
			o.Body = test.body
			o.BodySet = test.bodySet
			o.MaxBody = test.limit
			counts := &serverCounters{}
			r := httptest.NewRequest("POST", "http://local/path?q=1", strings.NewReader(test.payload))
			r.Header.Set("X-Test", "present")
			w := httptest.NewRecorder()
			diagnosticHandler(o, counts).ServeHTTP(w, r)
			if w.Code != test.want {
				t.Fatal(w.Code, w.Body.String())
			}
			if test.name == "echo" {
				var echo map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &echo); err != nil {
					t.Fatal(err)
				}
				if echo["body_base64"] != "aGVsbG8A" || echo["uri"] != "/path?q=1" || echo["method"] != "POST" {
					t.Fatal(echo)
				}
			}
			if test.bodySet && w.Body.String() != test.body {
				t.Fatal(w.Body.String())
			}
			if test.want == 413 && counts.rejected.Load() != 1 {
				t.Fatal("missing rejection count")
			}
		})
	}
}

func TestServeNetworkAndGracefulStop(t *testing.T) {
	ctx, cancel := context.WithCancel(testContext(t))
	defer cancel()
	ready := make(chan string, 1)
	type result struct {
		stats ServerStats
		err   error
	}
	done := make(chan result, 1)
	o := serverOptions()
	go func() {
		stats, err := Serve(ctx, o, func(a string) error { ready <- a; return nil })
		done <- result{stats, err}
	}()
	address := <-ready
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Post("http://"+address+"/test", "application/octet-stream", bytes.NewReader([]byte{0, 1, 2}))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || !bytes.Contains(body, []byte(`"body_base64":"AAEC"`)) {
		t.Fatal(resp.StatusCode, string(body), err)
	}
	cancel()
	r := <-done
	if !errors.Is(r.err, context.Canceled) || r.stats.Requests != 1 || r.stats.Address != address {
		t.Fatal(r)
	}
	if c, err := net.DialTimeout("tcp", address, 50*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("server listener leaked")
	}
}

func TestServeCancellationDuringDelayedRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(testContext(t))
	defer cancel()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	o := serverOptions()
	o.Delay = 100 * time.Millisecond
	go func() { _, err := Serve(ctx, o, func(a string) error { ready <- a; return nil }); done <- err }()
	c, err := net.Dial("tcp", <-ready)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestServeSlowRequestAndConnectionLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(testContext(t))
	defer cancel()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	o := serverOptions()
	o.Timeout = 100 * time.Millisecond
	o.MaxConnections = 1
	go func() { _, err := Serve(ctx, o, func(a string) error { ready <- a; return nil }); done <- err }()
	address := <-ready
	first, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	_, _ = io.WriteString(first, "GET / HTTP/1.1\r\n")
	// The first admitted connection must time out, releasing the single slot.
	first.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 512)
	_, err = first.Read(buf)
	if err == nil {
		t.Fatal("slow incomplete request did not close")
	}
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get("http://" + address)
	if err != nil {
		t.Fatal("connection slot was not released", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestServerValidationAndReadyFailure(t *testing.T) {
	for _, mutate := range []func(*ServerOptions){func(o *ServerOptions) { o.Status = 100 }, func(o *ServerOptions) { o.Status = 204; o.BodySet = true; o.Body = "bad" }, func(o *ServerOptions) { o.MaxConnections = 0 }, func(o *ServerOptions) { o.MaxBody = -1 }, func(o *ServerOptions) { o.MaxBody = 17 << 20 }, func(o *ServerOptions) { o.Delay = o.Timeout }} {
		o := serverOptions()
		mutate(&o)
		if o.Validate() == nil {
			t.Fatal("accepted invalid config", o)
		}
	}
	var address string
	_, err := Serve(testContext(t), serverOptions(), func(a string) error { address = a; return errors.New("stderr failed") })
	if err == nil || !strings.Contains(err.Error(), "stderr failed") {
		t.Fatal(err)
	}
	if c, err := net.DialTimeout("tcp", address, 50*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("listener leaked after readiness error")
	}
}
