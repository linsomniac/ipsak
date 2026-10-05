// Package dnstrace follows DNS delegations without requesting recursion.
package dnstrace

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/linsomniac/ipsak/internal/dnswire"
	"github.com/miekg/dns"
)

var DefaultRoots = []string{"198.41.0.4:53", "199.9.14.201:53", "[2001:503:ba3e::2:30]:53", "[2001:500:200::b]:53"}

type Options struct {
	Roots        []string
	Type         uint16
	MaxHops      int
	QueryTimeout time.Duration
}

func (o Options) Validate() error {
	if len(o.Roots) < 1 || len(o.Roots) > 8 || o.MaxHops < 1 || o.MaxHops > 64 || o.QueryTimeout <= 0 || o.QueryTimeout > time.Minute {
		return fmt.Errorf("require 1–8 roots, 1–64 hops, and query-timeout in (0,1m]")
	}
	if _, ok := dns.TypeToString[o.Type]; !ok || o.Type == dns.TypeAXFR || o.Type == dns.TypeIXFR || o.Type == dns.TypeOPT || o.Type == dns.TypeANY {
		return fmt.Errorf("unsupported record type")
	}
	for _, s := range o.Roots {
		h, p, e := net.SplitHostPort(s)
		if e != nil {
			return fmt.Errorf("root must be IP:port: %s", s)
		}
		if _, e = netip.ParseAddr(h); e != nil {
			return fmt.Errorf("root must be a numeric IP")
		}
		if _, e = net.LookupPort("udp", p); e != nil || p == "0" {
			return fmt.Errorf("invalid root port")
		}
	}
	return nil
}

type Observation struct {
	Server string  `json:"server"`
	RTTMS  float64 `json:"rtt_ms"`
	Rcode  string  `json:"rcode,omitempty"`
	Status string  `json:"status"`
	Error  string  `json:"error,omitempty"`
}
type Hop struct {
	Name         string        `json:"name"`
	Zone         string        `json:"zone"`
	Server       string        `json:"selected_server,omitempty"`
	Status       string        `json:"status"`
	Delegation   string        `json:"delegation,omitempty"`
	Nameservers  []string      `json:"nameservers,omitempty"`
	Fallback     []string      `json:"system_resolver_fallback,omitempty"`
	Records      []string      `json:"records,omitempty"`
	Observations []Observation `json:"observations"`
}
type Result struct {
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	Status          string   `json:"status"`
	Hops            []Hop    `json:"hops"`
	Answers         []string `json:"answers"`
	DNSSECValidated bool     `json:"dnssec_validated"`
}

func (r Result) CompactLines() []string {
	lines := []string{fmt.Sprintf("%s %s · %s", r.Name, r.Type, r.Status)}
	for i, h := range r.Hops {
		lines = append(lines, fmt.Sprintf("%2d  %s → %s · %s", i+1, h.Zone, h.Server, h.Status))
		if h.Delegation != "" {
			lines = append(lines, "    delegation "+h.Delegation+" · "+strings.Join(h.Nameservers, ", "))
		}
		for _, s := range h.Fallback {
			lines = append(lines, "    system resolver: "+s)
		}
	}
	return append(lines, r.Answers...)
}

type Resolver struct {
	Exchange  func(context.Context, *dns.Msg, string) (*dns.Msg, error)
	ResolveNS func(context.Context, string) ([]netip.Addr, error)
}

func exchange(ctx context.Context, q *dns.Msg, s string) (*dns.Msg, error) {
	return dnswire.Exchange(ctx, q, s)
}
func canonical(s string) string { return strings.ToLower(dns.Fqdn(s)) }
func (x Resolver) Trace(ctx context.Context, name string, o Options) (Result, error) {
	r := Result{Name: canonical(name), Type: dns.TypeToString[o.Type], Status: "incomplete", Hops: []Hop{}, Answers: []string{}}
	if err := o.Validate(); err != nil {
		return r, err
	}
	if _, ok := dns.IsDomainName(r.Name); !ok {
		return r, fmt.Errorf("invalid DNS name")
	}
	if x.Exchange == nil {
		x.Exchange = exchange
	}
	if x.ResolveNS == nil {
		x.ResolveNS = func(ctx context.Context, n string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", n)
		}
	}
	qname, zone := r.Name, "."
	servers := append([]string(nil), o.Roots...)
	aliases := map[string]bool{qname: true}
	for range o.MaxHops {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		h, m, err := x.step(ctx, qname, zone, servers, o)
		r.Hops = append(r.Hops, h)
		if err != nil {
			return r, err
		}
		switch h.Status {
		case "answer", "nxdomain", "nodata":
			r.Status = h.Status
			for _, rr := range m.Answer {
				if rr.Header().Class == dns.ClassINET && canonical(rr.Header().Name) == qname && rr.Header().Rrtype == o.Type {
					r.Answers = append(r.Answers, rr.String())
				}
			}
			return r, nil
		case "alias":
			var next string
			for _, rr := range m.Answer {
				if c, ok := rr.(*dns.CNAME); ok && c.Hdr.Class == dns.ClassINET && canonical(c.Hdr.Name) == qname {
					next = canonical(c.Target)
					break
				}
			}
			if next == "" || aliases[next] || len(aliases) >= 9 {
				return r, fmt.Errorf("CNAME loop or alias limit reached")
			}
			aliases[next] = true
			qname, zone, servers = next, ".", append([]string(nil), o.Roots...)
		case "referral":
			servers, h.Fallback, err = x.addresses(ctx, m, h.Delegation, h.Nameservers, o.QueryTimeout)
			r.Hops[len(r.Hops)-1] = h
			if err != nil {
				return r, err
			}
			zone = h.Delegation
		}
	}
	return r, fmt.Errorf("delegation hop limit reached")
}

// classify accepts only information relevant to the exact question. This is
// structural validation, not DNSSEC authentication.
func classify(m *dns.Msg, qname, zone string, qt uint16) (status, delegation string, ns []string, err error) {
	if m == nil || !m.Response || m.Opcode != dns.OpcodeQuery || m.Truncated || len(m.Question) != 1 || canonical(m.Question[0].Name) != qname || m.Question[0].Qtype != qt || m.Question[0].Qclass != dns.ClassINET {
		return "", "", nil, fmt.Errorf("invalid DNS response/question")
	}
	soa := false
	for _, rr := range m.Ns {
		if s, ok := rr.(*dns.SOA); ok && s.Hdr.Class == dns.ClassINET && dns.IsSubDomain(canonical(s.Hdr.Name), qname) && dns.IsSubDomain(zone, canonical(s.Hdr.Name)) {
			soa = true
		}
	}
	if m.Rcode == dns.RcodeNameError {
		if m.Authoritative && soa {
			return "nxdomain", "", nil, nil
		}
		return "", "", nil, fmt.Errorf("NXDOMAIN lacks authoritative SOA")
	}
	if m.Rcode != dns.RcodeSuccess {
		return "", "", nil, fmt.Errorf("DNS %s", dns.RcodeToString[m.Rcode])
	}
	if m.Authoritative {
		for _, rr := range m.Answer {
			if rr.Header().Class == dns.ClassINET && canonical(rr.Header().Name) == qname && rr.Header().Rrtype == qt {
				return "answer", "", nil, nil
			}
		}
		for _, rr := range m.Answer {
			if c, ok := rr.(*dns.CNAME); ok && c.Hdr.Class == dns.ClassINET && canonical(c.Hdr.Name) == qname {
				if _, ok := dns.IsDomainName(c.Target); ok {
					return "alias", "", nil, nil
				}
			}
		}
	}
	for _, rr := range m.Ns {
		if n, ok := rr.(*dns.NS); ok && n.Hdr.Class == dns.ClassINET {
			d := canonical(n.Hdr.Name)
			if d != zone && dns.IsSubDomain(zone, d) && dns.IsSubDomain(d, qname) && (delegation == "" || len(d) > len(delegation)) {
				delegation = d
			}
		}
	}
	if delegation != "" {
		seen := map[string]bool{}
		for _, rr := range m.Ns {
			if n, ok := rr.(*dns.NS); ok && n.Hdr.Class == dns.ClassINET && canonical(n.Hdr.Name) == delegation {
				name := canonical(n.Ns)
				if _, valid := dns.IsDomainName(name); valid && !seen[name] && len(ns) < 8 {
					seen[name] = true
					ns = append(ns, name)
				}
			}
		}
		if len(ns) > 0 {
			return "referral", delegation, ns, nil
		}
	}
	if m.Authoritative && soa && len(m.Answer) == 0 {
		return "nodata", "", nil, nil
	}
	return "", "", nil, fmt.Errorf("no authoritative answer or progressing delegation")
}

func (x Resolver) step(ctx context.Context, name, zone string, servers []string, o Options) (Hop, *dns.Msg, error) {
	h := Hop{Name: name, Zone: zone, Status: "failed", Observations: make([]Observation, len(servers))}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	type response struct {
		i                  int
		m                  *dns.Msg
		obs                Observation
		status, delegation string
		ns                 []string
	}
	ch := make(chan response, len(servers))
	for i, s := range servers {
		go func(i int, s string) {
			qctx, stop := context.WithTimeout(work, o.QueryTimeout)
			defer stop()
			q := new(dns.Msg)
			q.SetQuestion(name, o.Type)
			q.RecursionDesired = false
			q.SetEdns0(1232, false)
			start := time.Now()
			m, e := x.Exchange(qctx, q, s)
			a := response{i: i, m: m, obs: Observation{Server: s, RTTMS: float64(time.Since(start)) / float64(time.Millisecond), Status: "error"}}
			if e == nil {
				a.status, a.delegation, a.ns, e = classify(m, name, zone, o.Type)
				if m != nil {
					a.obs.Rcode = dns.RcodeToString[m.Rcode]
				}
			}
			if e != nil {
				a.obs.Error = e.Error()
				if work.Err() != nil && ctx.Err() == nil {
					a.obs.Status = "canceled_after_answer"
				}
			} else {
				a.obs.Status = a.status
			}
			ch <- a
		}(i, s)
	}
	var selected *dns.Msg
	for range servers {
		a := <-ch
		h.Observations[a.i] = a.obs
		if selected == nil && a.obs.Error == "" {
			selected = a.m
			h.Server = a.obs.Server
			h.Status, h.Delegation, h.Nameservers = a.status, a.delegation, a.ns
			for _, rr := range append(append([]dns.RR{}, a.m.Answer...), a.m.Ns...) {
				if len(h.Records) < 128 {
					h.Records = append(h.Records, rr.String())
				}
			}
			cancel()
		}
	}
	if ctx.Err() != nil {
		return h, selected, ctx.Err()
	}
	if selected == nil {
		return h, nil, fmt.Errorf("no usable DNS response at %s", zone)
	}
	return h, selected, nil
}

func (x Resolver) addresses(ctx context.Context, m *dns.Msg, zone string, names []string, timeout time.Duration) ([]string, []string, error) {
	byName := make([][]string, len(names))
	fallback := make([]string, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		for _, rr := range m.Extra {
			if rr.Header().Class != dns.ClassINET || canonical(rr.Header().Name) != name || !dns.IsSubDomain(zone, name) {
				continue
			}
			var ip net.IP
			switch a := rr.(type) {
			case *dns.A:
				ip = a.A
			case *dns.AAAA:
				ip = a.AAAA
			}
			if a, ok := netip.AddrFromSlice(ip); ok && !a.IsUnspecified() && !a.IsMulticast() {
				byName[i] = append(byName[i], net.JoinHostPort(a.String(), "53"))
			}
		}
		if len(byName[i]) > 0 {
			continue
		}
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			ips, err := x.ResolveNS(c, name)
			fallback[i] = name
			if err != nil {
				fallback[i] += " · " + err.Error()
				return
			}
			for _, a := range ips {
				if a.IsValid() && !a.IsUnspecified() && !a.IsMulticast() {
					byName[i] = append(byName[i], net.JoinHostPort(a.String(), "53"))
					if len(byName[i]) >= 8 {
						break
					}
				}
			}
		}(i, name)
	}
	wg.Wait()
	var servers, notes []string
	seen := map[string]bool{}
	// Round-robin through names so a verbose server cannot monopolize the cap.
	for n := 0; n < 8; n++ {
		for _, list := range byName {
			if n < len(list) && !seen[list[n]] && len(servers) < 8 {
				seen[list[n]] = true
				servers = append(servers, list[n])
			}
		}
	}
	for _, s := range fallback {
		if s != "" {
			notes = append(notes, s)
		}
	}
	sort.Strings(notes)
	if ctx.Err() != nil {
		return servers, notes, ctx.Err()
	}
	if len(servers) == 0 {
		return nil, notes, fmt.Errorf("no usable addresses for delegation %s", zone)
	}
	return servers, notes, nil
}
