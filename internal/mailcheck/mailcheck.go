// Package mailcheck inspects published mail DNS policy and optional SMTP greetings.
package mailcheck

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Options struct {
	Domain, Resolver, Selector string
	SMTP, STARTTLS             bool
	Port                       int
}
type Policy struct {
	Name          string   `json:"name"`
	QueryName     string   `json:"query_name"`
	CanonicalName string   `json:"canonical_name,omitempty"`
	Status        string   `json:"status"`
	Records       []string `json:"records"`
	Error         string   `json:"error,omitempty"`
}
type MX struct {
	Host       string `json:"host"`
	Preference uint16 `json:"preference"`
}
type SMTP struct {
	Host         string   `json:"host"`
	Greeting     string   `json:"greeting,omitempty"`
	Capabilities []string `json:"capabilities"`
	STARTTLS     bool     `json:"starttls_advertised"`
	TLSVerified  bool     `json:"tls_verified"`
	TLSVersion   uint16   `json:"tls_version,omitempty"`
	Error        string   `json:"error,omitempty"`
}
type Result struct {
	Domain   string   `json:"domain"`
	Resolver string   `json:"resolver"`
	MX       []MX     `json:"mx"`
	Policies []Policy `json:"policies"`
	SMTP     []SMTP   `json:"smtp"`
	Notes    []string `json:"notes"`
}

func (r Result) CompactLines() []string {
	lines := []string{r.Domain + " · resolver " + r.Resolver}
	for _, p := range r.Policies {
		line := fmt.Sprintf("%s · %s", p.Name, strings.ReplaceAll(p.Status, "_", " "))
		if p.QueryName != "" {
			line += " · " + p.QueryName
		}
		if p.CanonicalName != "" && !strings.EqualFold(p.QueryName, p.CanonicalName) {
			line += " → " + p.CanonicalName
		}
		lines = append(lines, line)
		if p.Name == "DKIM" && len(p.Records) > 0 {
			lines = append(lines, fmt.Sprintf("  %d TXT record(s); full key data in JSON/plain output", len(p.Records)))
		} else if p.Name != "MX" {
			for _, record := range p.Records {
				lines = append(lines, "  "+record)
			}
		}
		if p.Error != "" {
			lines = append(lines, "  Error: "+p.Error)
		}
	}
	for _, mx := range r.MX {
		lines = append(lines, fmt.Sprintf("MX %d · %s", mx.Preference, mx.Host))
	}
	for _, smtp := range r.SMTP {
		lines = append(lines, fmt.Sprintf("SMTP %s · STARTTLS advertised %t · TLS verified %t", smtp.Host, smtp.STARTTLS, smtp.TLSVerified))
		if smtp.Greeting != "" {
			lines = append(lines, "  "+smtp.Greeting)
		}
		if len(smtp.Capabilities) > 0 {
			lines = append(lines, "  EHLO: "+strings.Join(smtp.Capabilities, " · "))
		}
		if smtp.TLSVersion != 0 {
			lines = append(lines, "  "+tls.VersionName(smtp.TLSVersion))
		}
		if smtp.Error != "" {
			lines = append(lines, "  Error: "+smtp.Error)
		}
	}
	return append(lines, r.Notes...)
}

func policyRecord(label, value string) bool {
	switch label {
	case "SPF":
		// RFC 7208: the version is case-insensitive and ends at SP or EOS.
		return strings.EqualFold(value, "v=spf1") || len(value) > 6 && strings.EqualFold(value[:6], "v=spf1") && value[6] == ' '
	case "DMARC":
		return value == "v=DMARC1" || strings.HasPrefix(value, "v=DMARC1 ") || strings.HasPrefix(value, "v=DMARC1;")
	default:
		return true
	}
}

func query(ctx context.Context, server, name string, typ uint16) (*dns.Msg, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	owner := strings.ToLower(dns.Fqdn(name))
	seen := map[string]bool{owner: true}
	aliases := 0
	var response *dns.Msg
	for {
		if err := ctx.Err(); err != nil {
			return nil, owner, err
		}
		if response == nil {
			var err error
			response, err = queryOnce(ctx, server, owner, typ)
			if err != nil {
				return nil, owner, err
			}
		}
		next := ""
		hasData := false
		for _, rr := range response.Answer {
			h := rr.Header()
			if h.Class != dns.ClassINET || !strings.EqualFold(h.Name, owner) {
				continue
			}
			if h.Rrtype == typ {
				hasData = true
			}
			if c, ok := rr.(*dns.CNAME); ok {
				candidate := strings.ToLower(dns.Fqdn(c.Target))
				if _, ok := dns.IsDomainName(candidate); !ok {
					return nil, owner, fmt.Errorf("invalid CNAME target")
				}
				if next != "" && next != candidate {
					return nil, owner, fmt.Errorf("conflicting CNAME targets")
				}
				next = candidate
			}
		}
		if next == "" {
			if hasData || response.Rcode == dns.RcodeNameError || strings.EqualFold(response.Question[0].Name, owner) {
				return response, owner, nil
			}
			// The response ended at an alias without its target data. Query
			// that target using the same total deadline as the original name.
			response = nil
			continue
		}
		if hasData {
			return nil, owner, fmt.Errorf("CNAME coexists with requested data at the same owner")
		}
		aliases++
		if aliases > 8 {
			return nil, owner, fmt.Errorf("CNAME alias limit (8) exceeded")
		}
		if seen[next] {
			return nil, owner, fmt.Errorf("CNAME loop")
		}
		seen[next] = true
		owner = next
	}
}

func queryOnce(ctx context.Context, server, name string, typ uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), typ)
	m.SetEdns0(1232, false)
	for _, network := range []string{"udp", "tcp"} {
		c := &dns.Client{Net: network, Timeout: 2 * time.Second}
		conn, err := c.DialContext(ctx, server)
		if err != nil {
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		r, _, err := c.ExchangeWithConnContext(ctx, m, conn)
		stop()
		_ = conn.Close()
		if err != nil {
			return nil, err
		}
		if !r.Response || r.Opcode != dns.OpcodeQuery || len(r.Question) != 1 || !strings.EqualFold(r.Question[0].Name, m.Question[0].Name) || r.Question[0].Qtype != typ || r.Question[0].Qclass != dns.ClassINET {
			return nil, fmt.Errorf("invalid DNS response")
		}
		if r.Truncated && network == "udp" {
			continue
		}
		if r.Truncated || len(r.Answer) > 256 {
			return nil, fmt.Errorf("DNS response exceeds bounds")
		}
		if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
			return nil, fmt.Errorf("DNS %s", dns.RcodeToString[r.Rcode])
		}
		return r, nil
	}
	return nil, fmt.Errorf("truncated DNS response")
}

func Check(ctx context.Context, o Options) (Result, error) {
	r := Result{Domain: o.Domain, Resolver: o.Resolver, MX: []MX{}, SMTP: []SMTP{}, Notes: []string{"Published records only: no full SPF evaluation, DMARC organizational-domain fallback, DKIM message verification, or deliverability claim."}}
	if o.Port < 1 || o.Port > 65535 {
		return r, fmt.Errorf("SMTP port must be 1–65535")
	}
	type question struct {
		label, name string
		typ         uint16
	}
	qs := []question{{"MX", o.Domain, dns.TypeMX}, {"SPF", o.Domain, dns.TypeTXT}, {"DMARC", "_dmarc." + o.Domain, dns.TypeTXT}}
	if o.Selector != "" {
		qs = append(qs, question{"DKIM", o.Selector + "._domainkey." + o.Domain, dns.TypeTXT})
	} else {
		r.Notes = append(r.Notes, "DKIM not queried: supply --selector; selectors cannot be reliably discovered.")
	}
	r.Policies = make([]Policy, len(qs))
	answers := make([]*dns.Msg, len(qs))
	var wg sync.WaitGroup
	for i, q := range qs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := Policy{Name: q.label, QueryName: strings.ToLower(dns.Fqdn(q.name)), Status: "missing", Records: []string{}}
			resp, canonical, err := query(ctx, o.Resolver, q.name, q.typ)
			p.CanonicalName = canonical
			if err != nil {
				p.Status = "error"
				p.Error = err.Error()
			} else {
				if resp.Rcode == dns.RcodeNameError {
					p.Status = "nxdomain"
				}
				for _, rr := range resp.Answer {
					h := rr.Header()
					if h.Class != dns.ClassINET || !strings.EqualFold(h.Name, canonical) {
						continue
					}
					if h.Rrtype != q.typ || resp.Rcode != dns.RcodeSuccess {
						continue
					}
					switch v := rr.(type) {
					case *dns.MX:
						p.Records = append(p.Records, v.String())
					case *dns.TXT:
						s := strings.Join(v.Txt, "")
						if policyRecord(q.label, s) {
							p.Records = append(p.Records, s)
						}
					}
				}
				if len(p.Records) > 0 {
					p.Status = "present"
				}
				if q.label != "MX" && len(p.Records) > 1 {
					p.Status = "multiple_records"
					p.Error = "multiple policy records require correction; no effective policy was evaluated"
				}
				if p.Error != "" {
					p.Status = "error"
				} else if resp.Rcode == dns.RcodeSuccess {
					answers[i] = resp
				}
			}
			r.Policies[i] = p
		}()
	}
	wg.Wait()
	if answers[0] != nil {
		for _, rr := range answers[0].Answer {
			if mx, ok := rr.(*dns.MX); ok && mx.Hdr.Class == dns.ClassINET && strings.EqualFold(mx.Hdr.Name, r.Policies[0].CanonicalName) {
				r.MX = append(r.MX, MX{mx.Mx, mx.Preference})
			}
		}
	}
	sort.Slice(r.MX, func(i, j int) bool {
		if r.MX[i].Preference != r.MX[j].Preference {
			return r.MX[i].Preference < r.MX[j].Preference
		}
		return r.MX[i].Host < r.MX[j].Host
	})
	null := false
	for _, mx := range r.MX {
		if mx.Host == "." {
			null = true
		}
	}
	if null {
		if len(r.MX) == 1 && r.MX[0].Preference == 0 {
			r.Notes = append(r.Notes, "Valid null MX: SMTP probes suppressed; this domain declares it does not accept mail.")
		} else {
			r.Policies[0].Status = "error"
			r.Policies[0].Error = "invalid null MX: must be the sole MX with preference zero; SMTP probes suppressed"
		}
	}
	if o.SMTP || o.STARTTLS {
		if len(r.MX) == 0 {
			r.Notes = append(r.Notes, "No explicit MX: implicit A/AAAA delivery fallback is not probed.")
		}
		if !null {
			n := min(len(r.MX), 3)
			r.SMTP = make([]SMTP, n)
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); r.SMTP[i] = inspectSMTP(ctx, r.MX[i].Host, o.Port, o.STARTTLS) }()
			}
			wg.Wait()
			if len(r.MX) > n {
				r.Notes = append(r.Notes, "SMTP limited to the first three MX hosts by preference.")
			}
		}
	}
	failures := 0
	for _, p := range r.Policies {
		if p.Error != "" {
			failures++
		}
	}
	for _, s := range r.SMTP {
		if s.Error != "" {
			failures++
		}
	}
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	if failures > 0 {
		return r, fmt.Errorf("%d mail checks failed", failures)
	}
	return r, nil
}

func inspectSMTP(ctx context.Context, host string, port int, startTLS bool) (r SMTP) {
	return inspectSMTPWithTLS(ctx, host, port, startTLS, nil)
}

// tlsConfig is supplied only by fixtures; normal probes use system trust roots.
func inspectSMTPWithTLS(ctx context.Context, host string, port int, startTLS bool, tlsConfig *tls.Config) (r SMTP) {
	r = SMTP{Host: host, Capabilities: []string{}}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(strings.TrimSuffix(host, "."), strconv.Itoa(port)))
	if err != nil {
		r.Error = err.Error()
		return
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	reader := func(c net.Conn) *textproto.Reader {
		return textproto.NewReader(bufio.NewReader(io.LimitReader(c, 65536)))
	}
	rd := reader(conn)
	_, r.Greeting, err = rd.ReadResponse(220)
	if err != nil {
		r.Error = err.Error()
		return
	}
	ehlo := func(c net.Conn) error {
		if _, e := io.WriteString(c, "EHLO ipsak.invalid\r\n"); e != nil {
			return e
		}
		_, s, e := rd.ReadResponse(250)
		if e == nil {
			r.Capabilities = strings.Split(s, "\n")
			for _, line := range r.Capabilities {
				if strings.EqualFold(strings.TrimSpace(line), "STARTTLS") {
					r.STARTTLS = true
				}
			}
		}
		return e
	}
	if err = ehlo(conn); err != nil {
		r.Error = err.Error()
		return
	}
	if startTLS {
		if !r.STARTTLS {
			r.Error = "STARTTLS not advertised"
			return
		}
		if _, err = io.WriteString(conn, "STARTTLS\r\n"); err != nil {
			r.Error = err.Error()
			return
		}
		if _, _, err = rd.ReadResponse(220); err != nil {
			r.Error = err.Error()
			return
		}
		if tlsConfig == nil {
			tlsConfig = &tls.Config{ServerName: strings.TrimSuffix(host, "."), MinVersion: tls.VersionTLS12}
		}
		secure := tls.Client(conn, tlsConfig)
		if err = secure.HandshakeContext(ctx); err != nil {
			r.Error = err.Error()
			return
		}
		r.TLSVerified = true
		r.TLSVersion = secure.ConnectionState().Version
		rd = reader(secure)
		if err = ehlo(secure); err != nil {
			r.Error = err.Error()
			return
		}
	}
	return
}
