// Package diagnose assembles independent connectivity checks with useful failure hints.
package diagnose

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/linsomniac/ipsak/internal/lookup"
)

type Endpoint struct {
	URL    string
	Host   string
	Port   string
	Secure bool
	Target lookup.Target
}

func (e Endpoint) serverName() string {
	if ip, err := netip.ParseAddr(e.Host); err == nil {
		return ip.WithZone("").String()
	}
	return e.Host
}

func ParseEndpoint(raw string) (Endpoint, error) {
	if _, err := netip.ParsePrefix(raw); err == nil {
		return Endpoint{}, fmt.Errorf("doctor requires one host or HTTP(S) URL, not a CIDR")
	}
	if raw == "" {
		raw = "https://example.com"
	}
	if !strings.Contains(raw, "://") {
		if ip, err := netip.ParseAddr(raw); err == nil && ip.Is6() {
			raw = "[" + strings.ReplaceAll(raw, "%", "%25") + "]"
		}
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Endpoint{}, fmt.Errorf("invalid diagnostic URL: %w", err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return Endpoint{}, fmt.Errorf("use an HTTP(S) URL or host, without credentials or a fragment")
	}
	t, err := lookup.ParseTarget(u.Hostname())
	if err != nil || t.Prefix.IsValid() {
		return Endpoint{}, fmt.Errorf("invalid diagnostic host %q", u.Hostname())
	}
	if t.IP.IsValid() && (t.IP.IsMulticast() || t.IP.IsUnspecified() || t.Class == "Limited broadcast") {
		return Endpoint{}, fmt.Errorf("doctor requires a unicast destination")
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return Endpoint{}, fmt.Errorf("port cannot be empty")
	}
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return Endpoint{}, fmt.Errorf("port must be between 1 and 65535")
	}
	u.Host = net.JoinHostPort(t.Name, port)
	if u.Path == "" {
		u.Path = "/"
	}
	return Endpoint{URL: u.String(), Host: t.Name, Port: port, Secure: u.Scheme == "https", Target: t}, nil
}

// Dependencies permit deterministic tests and reuse of native host inventory.
type Dependencies struct {
	Interfaces func(context.Context) (any, error)
	Route      func(context.Context, netip.Addr) (any, error)
	Resolve    func(context.Context, lookup.Target) (lookup.Target, error)
	Dial       func(context.Context, string) (net.Conn, error)
}

type Check struct {
	Summary string `json:"summary"`
	Details any    `json:"details,omitempty"`
	Hint    string `json:"hint,omitempty"`
}

func result(summary string, data any, hint string, err error) (any, error) {
	if err == nil {
		hint = ""
	}
	return Check{Summary: summary, Details: data, Hint: hint}, err
}

func Tasks(e Endpoint, d Dependencies) []lookup.Task {
	if d.Resolve == nil {
		d.Resolve = func(ctx context.Context, t lookup.Target) (lookup.Target, error) { return lookup.Resolve(ctx, t, "ip") }
	}
	if d.Dial == nil {
		d.Dial = func(ctx context.Context, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		}
	}
	resolved := func(deps map[string]lookup.Section) netip.Addr {
		return deps["dns"].Data.(Check).Details.(lookup.Target).IP
	}
	dial := func(ctx context.Context, deps map[string]lookup.Section) (net.Conn, error) {
		return d.Dial(ctx, net.JoinHostPort(resolved(deps).String(), e.Port))
	}
	tasks := []lookup.Task{
		{Key: "interfaces", Title: "Local interfaces", Source: "local system", Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) {
			if d.Interfaces == nil {
				return nil, lookup.Skip("interface inventory unavailable")
			}
			v, err := d.Interfaces(ctx)
			return result("Interface inventory (link state does not prove connectivity)", v, "Check that your intended Ethernet, Wi-Fi, or VPN interface is up and has an address.", err)
		}},
		{Key: "dns", Title: "Name resolution", Source: "system resolver", Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) {
			t, err := d.Resolve(ctx, e.Target)
			if err == nil && (!t.IP.IsValid() || t.IP.IsUnspecified() || t.IP.IsMulticast() || lookup.Classify(t.IP) == "Limited broadcast") {
				err = fmt.Errorf("resolver did not return a unicast address")
			}
			return result("Selected address for every service check", t, "Check your DNS server and VPN configuration; compare answers with ipsak dnscheck.", err)
		}},
		{Key: "route", Title: "Local route", Source: "local system", Depends: []string{"dns"}, Run: func(ctx context.Context, deps map[string]lookup.Section) (any, error) {
			if d.Route == nil {
				return nil, lookup.Skip("route inspection unavailable")
			}
			v, err := d.Route(ctx, resolved(deps))
			return result("Route selection (does not test gateway reachability)", v, "Inspect your default route and VPN routing with ipsak route.", err)
		}},
		{Key: "tcp", Title: "TCP connection", Source: net.JoinHostPort(e.Host, e.Port), Depends: []string{"dns"}, Run: func(ctx context.Context, deps map[string]lookup.Section) (any, error) {
			start := time.Now()
			conn, err := dial(ctx, deps)
			var data any
			if err == nil {
				data = map[string]any{"remote": conn.RemoteAddr().String(), "local": conn.LocalAddr().String(), "connect_ms": float64(time.Since(start)) / float64(time.Millisecond)}
				conn.Close()
			}
			return result("Connect to the service port", data, "Check the destination port, server listener, firewall, and routing; an ICMP reply alone does not prove this service is reachable.", err)
		}},
	}
	if e.Secure {
		tasks = append(tasks, lookup.Task{Key: "tls", Title: "TLS verification", Source: e.Host, Depends: []string{"dns"}, Run: func(ctx context.Context, deps map[string]lookup.Section) (any, error) {
			conn, err := dial(ctx, deps)
			if err != nil {
				return result("Verify the service certificate", nil, "Resolve the TCP connection failure before investigating TLS.", err)
			}
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { conn.Close() })
			defer stop()
			client := tls.Client(conn, &tls.Config{ServerName: e.serverName(), MinVersion: tls.VersionTLS12})
			start := time.Now()
			err = client.HandshakeContext(ctx)
			state := client.ConnectionState()
			data := map[string]any{"verified": err == nil, "handshake_ms": float64(time.Since(start)) / float64(time.Millisecond)}
			if state.HandshakeComplete {
				data["version"] = tls.VersionName(state.Version)
				data["cipher"] = tls.CipherSuiteName(state.CipherSuite)
			}
			certs := state.PeerCertificates
			var verifyErr *tls.CertificateVerificationError
			if errors.As(err, &verifyErr) {
				certs = verifyErr.UnverifiedCertificates
			}
			if len(certs) > 0 {
				data["subject"] = certs[0].Subject.String()
				data["expires"] = certs[0].NotAfter.UTC()
			}
			return result("Verify the certificate chain, hostname, and validity", data, "Inspect the certificate with ipsak tlscert; also check your clock and trust store.", err)
		}})
	}
	tasks = append(tasks, lookup.Task{Key: "http", Title: "HTTP response", Source: e.URL, Depends: []string{"dns"}, Run: func(ctx context.Context, deps map[string]lookup.Section) (any, error) {
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 64 << 10, TLSClientConfig: &tls.Config{ServerName: e.serverName(), MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, deps) }}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.URL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "ipsak/1 doctor")
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return result("Request the selected URL", nil, "Inspect the web endpoint with ipsak httpinfo and check earlier DNS, TCP, and TLS results.", err)
		}
		defer resp.Body.Close()
		n, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		data := map[string]any{"status": resp.StatusCode, "protocol": resp.Proto, "location": resp.Header.Get("Location"), "read_bytes": n, "read_limit_reached": n == 64<<10, "elapsed_ms": float64(time.Since(start)) / float64(time.Millisecond)}
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			err = fmt.Errorf("server returned %s", resp.Status)
		}
		if readErr != nil {
			err = readErr
		}
		return result("HTTP response (redirects are reported without following)", data, "The service may be reachable but unhealthy; check the HTTP status, application logs, and redirect destination.", err)
	}})
	return tasks
}
