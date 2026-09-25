package probe

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/miekg/dns"
)

type DNSAnswer struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
}
type DNSQuery struct {
	Resolver          string      `json:"resolver"`
	Type              string      `json:"type"`
	RCode             string      `json:"rcode,omitempty"`
	Authoritative     bool        `json:"authoritative"`
	AuthenticatedData bool        `json:"authenticated_data"`
	Transport         string      `json:"transport"`
	DurationMS        float64     `json:"duration_ms"`
	Answers           []DNSAnswer `json:"answers"`
	Error             string      `json:"error,omitempty"`
	canonical         string
}
type DNSComparison struct {
	Type                string `json:"type"`
	Status              string `json:"status"`
	SuccessfulResolvers int    `json:"successful_resolvers"`
	DistinctAnswers     int    `json:"distinct_answers"`
}
type DNSResult struct {
	Name        string          `json:"name"`
	Queries     []DNSQuery      `json:"queries"`
	Comparisons []DNSComparison `json:"comparisons"`
	Note        string          `json:"note"`
}

func DNSOptions(name string, types, resolvers []string) (string, []uint16, []string, error) {
	if name == "" {
		return "", nil, nil, fmt.Errorf("DNS name must not be empty")
	}
	if len(types) > 8 || len(resolvers) > 8 {
		return "", nil, nil, fmt.Errorf("at most eight record types and resolvers are allowed")
	}
	if strings.ContainsAny(name, "/:@?#") {
		if _, err := netip.ParseAddr(name); err != nil {
			return "", nil, nil, fmt.Errorf("expected a DNS name or IP address")
		}
	}
	ip, ipErr := netip.ParseAddr(name)
	if ipErr == nil {
		var err error
		name, err = dns.ReverseAddr(ip.WithZone("").String())
		if err != nil {
			return "", nil, nil, err
		}
		if len(types) == 0 {
			types = []string{"PTR"}
		}
	} else {
		if strings.TrimSpace(name) != name || len(name) > 254 {
			return "", nil, nil, fmt.Errorf("invalid DNS name")
		}
		if _, ok := dns.IsDomainName(dns.Fqdn(name)); !ok {
			return "", nil, nil, fmt.Errorf("invalid DNS name")
		}
	}
	if len(types) == 0 {
		types = []string{"A", "AAAA"}
	}
	allowed := map[string]uint16{"A": dns.TypeA, "AAAA": dns.TypeAAAA, "CNAME": dns.TypeCNAME, "MX": dns.TypeMX, "NS": dns.TypeNS, "TXT": dns.TypeTXT, "SOA": dns.TypeSOA, "PTR": dns.TypePTR, "SRV": dns.TypeSRV, "CAA": dns.TypeCAA}
	qtypes := []uint16{}
	seen := map[uint16]bool{}
	for _, typ := range types {
		n, ok := allowed[strings.ToUpper(typ)]
		if !ok {
			return "", nil, nil, fmt.Errorf("unsupported DNS type %q", typ)
		}
		if !seen[n] {
			qtypes = append(qtypes, n)
			seen[n] = true
		}
	}
	if len(resolvers) == 0 {
		resolvers = lookup.SystemDNS().Servers
	}
	if len(resolvers) == 0 || len(resolvers) > 8 {
		return "", nil, nil, fmt.Errorf("configure one to eight DNS resolvers")
	}
	servers := []string{}
	seenServer := map[string]bool{}
	for _, raw := range resolvers {
		host, address, err := HostPort(raw, "53")
		if err != nil {
			return "", nil, nil, err
		}
		if _, err = netip.ParseAddr(host); err != nil {
			return "", nil, nil, fmt.Errorf("DNS resolver must be a numeric IP address")
		}
		if !seenServer[address] {
			servers = append(servers, address)
			seenServer[address] = true
		}
	}
	return strings.ToLower(dns.Fqdn(name)), qtypes, servers, nil
}

func dnsExchange(ctx context.Context, m *dns.Msg, server, network string) (*dns.Msg, error) {
	c := &dns.Client{Net: network, Timeout: 2 * time.Second, UDPSize: 4096}
	conn, err := c.DialContext(ctx, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	r, _, err := c.ExchangeWithConnContext(ctx, m, conn)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return r, err
}

func canonicalRR(rr dns.RR) (DNSAnswer, string) {
	copy := dns.Copy(rr)
	h := copy.Header()
	h.Name = strings.ToLower(h.Name)
	switch v := copy.(type) {
	case *dns.CNAME:
		v.Target = strings.ToLower(v.Target)
	case *dns.NS:
		v.Ns = strings.ToLower(v.Ns)
	case *dns.PTR:
		v.Ptr = strings.ToLower(v.Ptr)
	case *dns.MX:
		v.Mx = strings.ToLower(v.Mx)
	case *dns.SOA:
		v.Ns = strings.ToLower(v.Ns)
		v.Mbox = strings.ToLower(v.Mbox)
	case *dns.SRV:
		v.Target = strings.ToLower(v.Target)
	}
	parts := strings.SplitN(copy.String(), "\t", 5)
	value := copy.String()
	if len(parts) == 5 {
		value = parts[4]
	}
	a := DNSAnswer{Name: h.Name, Type: dns.TypeToString[h.Rrtype], TTL: h.Ttl, Value: value}
	h.Ttl = 0
	return a, copy.String()
}

func oneDNS(ctx context.Context, name string, typ uint16, server string) DNSQuery {
	r := DNSQuery{Resolver: server, Type: dns.TypeToString[typ], Transport: "udp", Answers: []DNSAnswer{}}
	start := time.Now()
	m := new(dns.Msg)
	m.SetQuestion(name, typ)
	m.SetEdns0(1232, false)
	resp, err := dnsExchange(ctx, m, server, "udp")
	if err == nil && resp.Truncated {
		r.Transport = "tcp"
		resp, err = dnsExchange(ctx, m, server, "tcp")
	}
	r.DurationMS = float64(time.Since(start)) / float64(time.Millisecond)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	if !resp.Response || resp.Opcode != dns.OpcodeQuery || resp.Truncated || len(resp.Question) != 1 || !strings.EqualFold(resp.Question[0].Name, name) || resp.Question[0].Qtype != typ || resp.Question[0].Qclass != dns.ClassINET {
		r.Error = "invalid DNS response question, flags, or truncation"
		return r
	}
	r.RCode = dns.RcodeToString[resp.Rcode]
	r.Authoritative = resp.Authoritative
	r.AuthenticatedData = resp.AuthenticatedData
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		r.Error = "DNS " + r.RCode
		return r
	}
	if len(resp.Answer) > 512 {
		r.Error = "DNS response exceeds 512 answer records"
		return r
	}
	canonical := []string{}
	for _, rr := range resp.Answer {
		a, key := canonicalRR(rr)
		r.Answers = append(r.Answers, a)
		canonical = append(canonical, key)
	}
	sort.Slice(r.Answers, func(i, j int) bool {
		a, b := r.Answers[i], r.Answers[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Value != b.Value {
			return a.Value < b.Value
		}
		return a.TTL < b.TTL
	})
	sort.Strings(canonical)
	unique := canonical[:0]
	for _, key := range canonical {
		if len(unique) == 0 || unique[len(unique)-1] != key {
			unique = append(unique, key)
		}
	}
	r.canonical = r.RCode + "\n" + strings.Join(unique, "\n")
	return r
}

func DNS(ctx context.Context, name string, types []uint16, resolvers []string) (DNSResult, error) {
	out := DNSResult{Name: name, Queries: []DNSQuery{}, Comparisons: []DNSComparison{}, Note: "Answer comparison ignores TTL. AD is the resolver's assertion, not local DNSSEC validation; geographic and rotating answers can differ."}
	if len(types) == 0 || len(types) > 8 || len(resolvers) == 0 || len(resolvers) > 8 {
		return out, fmt.Errorf("invalid DNS query bounds")
	}
	out.Queries = make([]DNSQuery, len(types)*len(resolvers))
	var wg sync.WaitGroup
	for i, server := range resolvers {
		for j, typ := range types {
			index := i*len(types) + j
			wg.Add(1)
			go func() { defer wg.Done(); out.Queries[index] = oneDNS(ctx, name, typ, server) }()
		}
	}
	wg.Wait()
	failures := 0
	for _, q := range out.Queries {
		if q.Error != "" {
			failures++
		}
	}
	for _, typ := range types {
		comparison := DNSComparison{Type: dns.TypeToString[typ]}
		sets := map[string]bool{}
		for _, q := range out.Queries {
			if q.Type == comparison.Type && q.Error == "" {
				comparison.SuccessfulResolvers++
				sets[q.canonical] = true
			}
		}
		comparison.DistinctAnswers = len(sets)
		comparison.Status = "agree"
		if len(sets) > 1 {
			comparison.Status = "differ"
		}
		if comparison.SuccessfulResolvers < 2 {
			comparison.Status = "insufficient_data"
		}
		out.Comparisons = append(out.Comparisons, comparison)
	}
	if failures > 0 {
		return out, fmt.Errorf("%d of %d DNS queries failed", failures, len(out.Queries))
	}
	return out, nil
}
