package watch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/linsomniac/ipsak/internal/dnswire"
	"github.com/linsomniac/ipsak/internal/ping"
	"github.com/miekg/dns"
)

// NewChecker reuses HTTP connections between rounds; Close releases idle ones.
func NewChecker(resolver string) (Checker, func(), error) {
	if resolver == "" {
		cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err == nil && len(cfg.Servers) > 0 {
			resolver = net.JoinHostPort(cfg.Servers[0], cfg.Port)
		}
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 1 << 20, MaxIdleConns: 128, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	check := func(ctx context.Context, t Target) (result Check) {
		defer func() {
			if ctx.Err() == nil || result.Err == nil {
				return
			}
			var ne net.Error
			if errors.Is(result.Err, net.ErrClosed) || errors.As(result.Err, &ne) && ne.Timeout() {
				result.Err = ctx.Err()
			}
		}()
		switch t.Kind {
		case "http", "https":
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.Address, nil)
			if err != nil {
				return Check{Err: err}
			}
			req.Header.Set("User-Agent", "ipsak/watch")
			resp, err := client.Do(req)
			if err != nil {
				return Check{Err: err}
			}
			resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 400 {
				return Check{Detail: resp.Status, Err: fmt.Errorf("HTTP %s", resp.Status)}
			}
			return Check{Detail: resp.Status}
		case "tcp":
			c, err := (&net.Dialer{}).DialContext(ctx, "tcp", t.Address)
			if err != nil {
				return Check{Err: err}
			}
			peer := c.RemoteAddr().String()
			c.Close()
			return Check{Detail: "connected to " + peer}
		case "dns":
			if resolver == "" {
				return Check{Err: fmt.Errorf("no system DNS resolver; use --resolver")}
			}
			q := new(dns.Msg)
			q.SetQuestion(dns.Fqdn(t.Host), t.Qtype)
			q.SetEdns0(1232, false)
			r, err := dnswire.Exchange(ctx, q, resolver)
			if err != nil {
				return Check{Err: err}
			}
			if !r.Response || r.Truncated || r.Opcode != dns.OpcodeQuery || len(r.Question) != 1 || !strings.EqualFold(r.Question[0].Name, q.Question[0].Name) || r.Question[0].Qclass != dns.ClassINET || r.Question[0].Qtype != t.Qtype {
				return Check{Err: fmt.Errorf("invalid DNS response")}
			}
			if r.Rcode != dns.RcodeSuccess {
				return Check{Err: fmt.Errorf("DNS %s", dns.RcodeToString[r.Rcode])}
			}
			// Follow only an in-message CNAME chain; unrelated records cannot
			// make a target healthy. Separate queries belong in dns/dnstrace.
			owner := dns.Fqdn(t.Host)
			seen := map[string]bool{}
			for range 9 {
				if seen[owner] {
					break
				}
				seen[owner] = true
				next := ""
				for _, rr := range r.Answer {
					if rr.Header().Class != dns.ClassINET || !strings.EqualFold(rr.Header().Name, owner) {
						continue
					}
					if rr.Header().Rrtype == t.Qtype {
						return Check{Detail: rr.String()}
					}
					if a, ok := rr.(*dns.CNAME); ok {
						next = a.Target
					}
				}
				if next == "" {
					break
				}
				owner = next
			}
			return Check{Err: fmt.Errorf("DNS response has no matching %s answer", dns.TypeToString[t.Qtype])}
		case "icmp":
			return checkICMP(ctx, t.Host)
		}
		return Check{Err: fmt.Errorf("unknown check kind")}
	}
	return check, transport.CloseIdleConnections, nil
}
func checkICMP(ctx context.Context, host string) Check {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil {
			return Check{Err: e}
		}
		if len(ips) == 0 {
			return Check{Err: fmt.Errorf("no IP addresses")}
		}
		ip = ips[0]
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.Unmap() == netip.MustParseAddr("255.255.255.255") {
		return Check{Err: fmt.Errorf("ICMP requires a unicast destination")}
	}
	p, err := ping.Open(ip)
	if err != nil {
		return Check{Err: err}
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { p.Close(); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
		p.Close()
	}()
	if err = p.Send(1); err != nil {
		return Check{Err: err}
	}
	_, err = p.Receive()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return Check{Detail: ip.String(), Err: err}
}
