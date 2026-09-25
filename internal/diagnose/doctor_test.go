package diagnose

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linsomniac/ipsak/internal/lookup"
)

func collect(t *testing.T, e Endpoint, d Dependencies) map[string]lookup.Section {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := lookup.Run(ctx, Tasks(e, d))
	if err != nil {
		t.Fatal(err)
	}
	sections := map[string]lookup.Section{}
	for s := range ch {
		sections[s.Key] = s
	}
	return sections
}

func TestEndpointValidation(t *testing.T) {
	scoped, err := ParseEndpoint("https://[fe80::1%25eth0]")
	if err != nil || scoped.Host != "fe80::1%eth0" || scoped.serverName() != "fe80::1" {
		t.Fatalf("scope belongs to routing, not certificate identity: %+v %v", scoped, err)
	}
	for _, input := range []string{"https://user:pass@example.com", "ftp://example.com", "http://example.com/#secret", "http://example.com:0", "http://example.com:65536", "example.com:", "http://0.0.0.0", "http://224.0.0.1", "http://255.255.255.255", "10.0.0.0/24"} {
		if _, err := ParseEndpoint(input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
	for input, host := range map[string]string{"": "example.com", "::1": "::1", "http://[::1]:8080/path": "::1", "https://bücher.example": "xn--bcher-kva.example", "example.com:8443": "example.com"} {
		e, err := ParseEndpoint(input)
		if err != nil || e.Host != host {
			t.Errorf("%q: %+v %v", input, e, err)
		}
	}
}

func TestDoctorConcurrentPinnedChecksAndPartialRoute(t *testing.T) {
	var requestHost atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestHost.Store(r.Host)
		w.Header().Set("Location", "http://must-not-follow.invalid/")
		w.WriteHeader(302)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	e, _ := ParseEndpoint("http://service.invalid:" + u.Port() + "/check")
	var resolutions atomic.Int32
	started := make(chan struct{}, 3)
	release := make(chan struct{})
	gate := func(ctx context.Context) error {
		started <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	d := Dependencies{
		Interfaces: func(context.Context) (any, error) { return "local evidence", nil },
		Resolve: func(_ context.Context, target lookup.Target) (lookup.Target, error) {
			resolutions.Add(1)
			target.IP = netip.MustParseAddr("127.0.0.1")
			return target, nil
		},
		Route: func(ctx context.Context, ip netip.Addr) (any, error) {
			if err := gate(ctx); err != nil {
				return nil, err
			}
			return ip.String(), errors.New("no route inspector")
		},
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			if err := gate(ctx); err != nil {
				return nil, err
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		},
	}
	finished := make(chan map[string]lookup.Section, 1)
	go func() { finished <- collect(t, e, d) }()
	for range 3 {
		select {
		case <-started:
		case <-time.After(4 * time.Second):
			t.Fatal("dependent checks serialized instead of overlapping")
		}
	}
	close(release)
	s := <-finished
	if resolutions.Load() != 1 || s["route"].Status != "error" || s["route"].Data.(Check).Hint == "" || s["http"].Status != "ok" || s["tcp"].Status != "ok" || s["interfaces"].Status != "ok" {
		t.Fatalf("resolutions=%d sections=%+v", resolutions.Load(), s)
	}
	if requestHost.Load() != "service.invalid:"+u.Port() {
		t.Fatal("lost original HTTP Host:", requestHost.Load())
	}
}

func TestDoctorDNSFailurePreservesInterfaces(t *testing.T) {
	e, _ := ParseEndpoint("example.invalid")
	s := collect(t, e, Dependencies{
		Interfaces: func(context.Context) (any, error) { return "available", nil },
		Resolve: func(_ context.Context, target lookup.Target) (lookup.Target, error) {
			return target, errors.New("DNS failure")
		},
		Dial: func(context.Context, string) (net.Conn, error) {
			t.Error("dial after DNS failure")
			return nil, errors.New("unexpected")
		},
	})
	if s["interfaces"].Status != "ok" || s["dns"].Status != "error" || s["tcp"].Status != "skipped" || s["tls"].Status != "skipped" || s["http"].Status != "skipped" {
		t.Fatal(s)
	}
}

func TestDoctorTLSFailureAndHTTPBound(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsServer.Close()
	e, _ := ParseEndpoint(tlsServer.URL)
	s := collect(t, e, Dependencies{})
	if s["tls"].Status != "error" || s["tls"].Data.(Check).Details.(map[string]any)["verified"] != false || s["http"].Status != "error" || s["tcp"].Status != "ok" {
		t.Fatal(s)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", 128<<10))) }))
	defer srv.Close()
	e, _ = ParseEndpoint(srv.URL)
	s = collect(t, e, Dependencies{})
	data := s["http"].Data.(Check).Details.(map[string]any)
	if s["http"].Status != "ok" || data["read_bytes"] != int64(64<<10) || data["read_limit_reached"] != true {
		t.Fatal(s["http"])
	}
}
