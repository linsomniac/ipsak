package lookup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var ErrNXDomain = errors.New("DNS name does not exist")

type DNSClient struct{ Servers []string }

func SystemDNS() *DNSClient {
	c := &DNSClient{}
	if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil {
		for _, s := range cfg.Servers {
			c.Servers = append(c.Servers, net.JoinHostPort(s, cfg.Port))
		}
	}
	return c
}

func (c *DNSClient) Query(ctx context.Context, name string, typ uint16) ([]dns.RR, error) {
	return c.query(ctx, name, typ, make(map[string]bool))
}

func (c *DNSClient) query(ctx context.Context, name string, typ uint16, visited map[string]bool) ([]dns.RR, error) {
	name = strings.ToLower(dns.Fqdn(name))
	if visited[name] || len(visited) >= 16 {
		return nil, fmt.Errorf("DNS CNAME cycle or chain longer than 16 names")
	}
	visited[name] = true
	if len(c.Servers) == 0 {
		return nil, fmt.Errorf("no system DNS servers configured in /etc/resolv.conf")
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), typ)
	var last error
	for _, server := range c.Servers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		client := &dns.Client{Timeout: 2 * time.Second}
		r, err := exchange(ctx, client, msg, server)
		if err == nil && r.Truncated {
			client.Net = "tcp"
			r, err = exchange(ctx, client, msg, server)
		}
		if err != nil {
			last = err
			continue
		}
		if r.Rcode == dns.RcodeNameError {
			return nil, ErrNXDomain
		}
		if r.Rcode != dns.RcodeSuccess {
			last = fmt.Errorf("DNS %s", dns.RcodeToString[r.Rcode])
			continue
		}
		if typ != dns.TypeCNAME {
			alias, hasType := "", false
			for _, rr := range r.Answer {
				if rr.Header().Rrtype == typ {
					hasType = true
				}
				if cn, ok := rr.(*dns.CNAME); ok && strings.EqualFold(cn.Hdr.Name, name) {
					alias = cn.Target
				}
			}
			if !hasType && alias != "" {
				more, err := c.query(ctx, alias, typ, visited)
				return append(r.Answer, more...), err
			}
		}
		return r.Answer, nil
	}
	return nil, last
}

func exchange(ctx context.Context, client *dns.Client, msg *dns.Msg, server string) (*dns.Msg, error) {
	conn, err := client.DialContext(ctx, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	r, _, err := client.ExchangeWithConnContext(ctx, msg, conn)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return r, err
}

type DNSRecords struct {
	Records map[string][]string `json:"records"`
	Errors  map[string]string   `json:"errors,omitempty"`
}

func (c *DNSClient) Records(ctx context.Context, t Target) (any, error) {
	name := t.Name
	types := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeNS, dns.TypeTXT, dns.TypeSOA}
	if t.IP.IsValid() {
		var err error
		name, err = dns.ReverseAddr(t.IP.WithZone("").String())
		if err != nil {
			return nil, err
		}
		types = []uint16{dns.TypePTR}
	}
	r := DNSRecords{Records: map[string][]string{}, Errors: map[string]string{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, typ := range types {
		wg.Add(1)
		go func(typ uint16) {
			defer wg.Done()
			records, err := c.Query(ctx, name, typ)
			key := dns.TypeToString[typ]
			values := []string{}
			for _, rr := range records {
				if rr.Header().Rrtype != typ {
					continue
				}
				s := rr.String()
				fields := strings.SplitN(s, "\t", 5)
				if len(fields) == 5 {
					s = fields[4]
				}
				values = append(values, s)
			}
			sort.Strings(values)
			mu.Lock()
			defer mu.Unlock()
			r.Records[key] = values
			if err != nil {
				r.Errors[key] = err.Error()
			}
		}(typ)
	}
	wg.Wait()
	if len(r.Errors) > 0 {
		return r, fmt.Errorf("%d of %d DNS record lookups failed", len(r.Errors), len(types))
	}
	return r, nil
}

func (c *DNSClient) txt(ctx context.Context, name string) ([]string, error) {
	rrs, err := c.Query(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range rrs {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no TXT record for %s", name)
	}
	return out, nil
}

type ASN struct {
	Number       uint32   `json:"asn"`
	Name         string   `json:"name,omitempty"`
	Prefix       string   `json:"prefix"`
	Country      string   `json:"country,omitempty"`
	Registry     string   `json:"registry,omitempty"`
	Allocated    string   `json:"allocated,omitempty"`
	OtherOrigins []uint32 `json:"other_origins,omitempty"`
}

func OriginQuery(ip netip.Addr) string {
	reverse, _ := dns.ReverseAddr(ip.Unmap().WithZone("").String())
	if ip.Unmap().Is4() {
		return strings.TrimSuffix(reverse, "in-addr.arpa.") + "origin.asn.cymru.com."
	}
	return strings.TrimSuffix(reverse, "ip6.arpa.") + "origin6.asn.cymru.com."
}

func (c *DNSClient) ASN(ctx context.Context, ip netip.Addr) (ASN, error) {
	ip = ip.Unmap().WithZone("")
	text, err := c.txt(ctx, OriginQuery(ip))
	if err != nil {
		return ASN{}, err
	}
	fields := strings.Split(text[0], "|")
	if len(fields) < 5 {
		return ASN{}, fmt.Errorf("malformed Team Cymru origin record")
	}
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	p, err := netip.ParsePrefix(fields[1])
	if err != nil || !p.Contains(ip) {
		return ASN{}, fmt.Errorf("invalid Team Cymru prefix")
	}
	a := ASN{Prefix: p.Masked().String(), Country: fields[2], Registry: fields[3], Allocated: fields[4]}
	for _, s := range strings.Fields(fields[0]) {
		parsed, err := strconv.ParseUint(s, 10, 32)
		if err != nil || parsed == 0 {
			return ASN{}, fmt.Errorf("invalid Team Cymru ASN %q", s)
		}
		number := uint32(parsed)
		if a.Number == 0 {
			a.Number = number
		} else {
			a.OtherOrigins = append(a.OtherOrigins, number)
		}
	}
	if a.Number == 0 {
		return ASN{}, fmt.Errorf("no origin ASN found")
	}
	return a, nil
}

func (c *DNSClient) ASNName(ctx context.Context, number uint32) (any, error) {
	txt, err := c.txt(ctx, fmt.Sprintf("AS%d.asn.cymru.com", number))
	if err != nil {
		return nil, err
	}
	f := strings.SplitN(txt[0], "|", 5)
	if len(f) != 5 {
		return nil, fmt.Errorf("malformed Team Cymru ASN name record")
	}
	returned, err := strconv.ParseUint(strings.TrimSpace(f[0]), 10, 32)
	if err != nil || returned != uint64(number) {
		return nil, fmt.Errorf("Team Cymru ASN name does not match requested ASN")
	}
	return map[string]string{"name": strings.TrimSpace(f[4])}, nil
}

type ListResult struct {
	Zone   string   `json:"zone"`
	Status string   `json:"status"`
	Codes  []string `json:"codes,omitempty"`
	Error  string   `json:"error,omitempty"`
}

func (c *DNSClient) Reputation(ctx context.Context, ip netip.Addr) (any, error) {
	ip = ip.Unmap().WithZone("")
	if !ip.Is4() {
		return nil, Skip("configured DNS blocklists support IPv4 only")
	}
	zones := []string{"zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org"}
	out := make([]ListResult, len(zones))
	var wg sync.WaitGroup
	for i, z := range zones {
		wg.Add(1)
		go func(i int, z string) {
			defer wg.Done()
			reverse, _ := dns.ReverseAddr(ip.String())
			records, err := c.Query(ctx, strings.TrimSuffix(reverse, "in-addr.arpa.")+z, dns.TypeA)
			r := ListResult{Zone: z, Status: "unavailable"}
			if errors.Is(err, ErrNXDomain) {
				r.Status = "not_listed"
			}
			hasA := false
			if err != nil && !errors.Is(err, ErrNXDomain) {
				r.Status = "unavailable"
				r.Error = err.Error()
			}
			for _, rr := range records {
				if a, ok := rr.(*dns.A); ok {
					if !hasA && err == nil {
						r.Status = "listed"
					}
					hasA = true
					r.Codes = append(r.Codes, a.A.String())
					b := a.A.To4()
					allowed := false
					if b != nil && b[0] == 127 && b[1] == 0 && b[2] == 0 {
						switch z {
						case "zen.spamhaus.org":
							allowed = b[3] == 2 || b[3] == 3 || b[3] == 4 || b[3] == 9 || b[3] == 10 || b[3] == 11 || b[3] == 30
						default:
							allowed = b[3] == 2
						}
					}
					if !allowed {
						r.Status = "unavailable"
						r.Error = "provider refusal or unrecognized return code: " + a.A.String()
					} else if r.Status != "unavailable" {
						r.Status = "listed"
					}
				}
			}
			if err == nil && !hasA {
				r.Error = "no DNSBL A response; unable to determine listing status"
			}
			out[i] = r
		}(i, z)
	}
	wg.Wait()
	for _, r := range out {
		if r.Status == "unavailable" {
			return out, fmt.Errorf("one or more blocklists unavailable; results are incomplete")
		}
	}
	return out, nil
}
