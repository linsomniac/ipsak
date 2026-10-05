package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

type Service struct {
	DNS                       *DNSClient
	HTTP                      *http.Client
	GeoURL, RDAPURL, RPKIURL  string
	NeighboursURL, RoutingURL string
	BootstrapURL              string
	PublicURLs                []string
}

func NewService() *Service {
	return &Service{DNS: SystemDNS(), HTTP: &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 8 {
			return fmt.Errorf("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing non-HTTPS redirect")
		}
		return nil
	}}, GeoURL: "https://ipwho.is/", BootstrapURL: "https://data.iana.org/rdap/", RPKIURL: "https://stat.ripe.net/data/rpki-validation/data.json", NeighboursURL: "https://stat.ripe.net/data/asn-neighbours/data.json", RoutingURL: "https://stat.ripe.net/data/routing-status/data.json", PublicURLs: []string{"https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"}}
}

func (s *Service) get(ctx context.Context, address string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ipsak/1.0 (+https://github.com/linsomniac/ipsak)")
	req.Header.Set("Accept", "application/rdap+json, application/json, text/plain")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider returned HTTP %d", resp.StatusCode)
	}
	const limit = 2 << 20
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("provider response exceeds 2 MiB")
	}
	return b, nil
}
func (s *Service) json(ctx context.Context, address string, out any) error {
	b, err := s.get(ctx, address)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("invalid provider JSON: %w", err)
	}
	return nil
}

type Geo struct {
	IP          string   `json:"ip"`
	Success     *bool    `json:"success,omitempty"`
	Message     string   `json:"message,omitempty"`
	Country     string   `json:"country"`
	CountryCode string   `json:"country_code"`
	Region      string   `json:"region"`
	City        string   `json:"city"`
	Latitude    *float64 `json:"latitude,omitempty"`
	Longitude   *float64 `json:"longitude,omitempty"`
	Connection  struct {
		ISP string `json:"isp"`
		Org string `json:"org"`
	} `json:"connection"`
	Timezone struct {
		ID string `json:"id"`
	} `json:"timezone"`
}

func (s *Service) Geo(ctx context.Context, ip netip.Addr) (any, error) {
	ip = ip.Unmap().WithZone("")
	var g Geo
	if err := s.json(ctx, s.GeoURL+url.PathEscape(ip.String()), &g); err != nil {
		return nil, err
	}
	if g.Success == nil || !*g.Success {
		return nil, fmt.Errorf("location lookup failed: %s", g.Message)
	}
	returned, err := netip.ParseAddr(g.IP)
	if err != nil || returned.Unmap() != ip.Unmap() {
		return nil, fmt.Errorf("location provider returned a different or missing IP")
	}
	if g.Latitude == nil || g.Longitude == nil || *g.Latitude < -90 || *g.Latitude > 90 || *g.Longitude < -180 || *g.Longitude > 180 {
		return nil, fmt.Errorf("location provider returned missing or invalid coordinates")
	}
	g.Success = nil
	return g, nil
}

type RDAPEntity struct {
	Roles    []string          `json:"roles"`
	VCard    []json.RawMessage `json:"vcardArray"`
	Entities []RDAPEntity      `json:"entities"`
}
type RDAP struct {
	Name     string       `json:"name"`
	Handle   string       `json:"handle"`
	Start    string       `json:"startAddress"`
	End      string       `json:"endAddress"`
	Country  string       `json:"country"`
	Entities []RDAPEntity `json:"entities"`
	Events   []RDAPEvent  `json:"events"`
}
type RDAPEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapContact struct {
	Roles         []string
	Kind          string
	Names, Emails []string
}

func (c rdapContact) has(role string) bool { return slices.Contains(c.Roles, role) }

// rdapContacts flattens embedded entities in document order, parents first.
// Linked entity documents are not fetched.
func rdapContacts(entities []RDAPEntity) []rdapContact {
	var out []rdapContact
	var scan func([]RDAPEntity, int)
	scan = func(entities []RDAPEntity, depth int) {
		if depth > 8 {
			return
		}
		for _, e := range entities {
			c := rdapContact{Roles: e.Roles}
			if len(e.VCard) == 2 {
				var props [][]json.RawMessage
				if json.Unmarshal(e.VCard[1], &props) == nil {
					for _, p := range props {
						if len(p) != 4 {
							continue
						}
						var key, value string
						_ = json.Unmarshal(p[0], &key)
						if json.Unmarshal(p[3], &value) != nil {
							continue
						}
						switch key {
						case "fn":
							c.Names = append(c.Names, value)
						case "email":
							c.Emails = append(c.Emails, value)
						case "kind":
							c.Kind = value
						}
					}
				}
			}
			out = append(out, c)
			scan(e.Entities, depth+1)
		}
	}
	scan(entities, 0)
	return out
}

// AIDEV-NOTE: RIPE lists maintainers as registrants beside the holding
// organisation, so the vCard kind decides: an org registrant, else the first
// registrant, else the first contact that is not the abuse desk. Whois and
// the ASN registration share this rule.
func registrantName(contacts []rdapContact) string {
	registrant, other := "", ""
	for _, c := range contacts {
		if len(c.Names) == 0 {
			continue
		}
		if c.has("registrant") {
			if c.Kind == "org" {
				return c.Names[0]
			}
			if registrant == "" {
				registrant = c.Names[0]
			}
		} else if other == "" && !c.has("abuse") {
			other = c.Names[0]
		}
	}
	if registrant != "" {
		return registrant
	}
	return other
}

// abuseEmails lists each abuse mailbox once, in order of first appearance.
// Registries repeat one mailbox across contacts and their nested entities.
func abuseEmails(contacts []rdapContact) []string {
	var out []string
	for _, c := range contacts {
		if !c.has("abuse") {
			continue
		}
		for _, email := range c.Emails {
			if !slices.Contains(out, email) {
				out = append(out, email)
			}
		}
	}
	return out
}

func rdapDates(events []RDAPEvent) (created, updated string) {
	for _, event := range events {
		if event.Action == "registration" {
			created = event.Date
		}
		if event.Action == "last changed" {
			updated = event.Date
		}
	}
	return created, updated
}

// rdapBase returns the first usable HTTPS registry URL without a trailing slash.
func rdapBase(urls []string) string {
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" {
			return strings.TrimRight(u.String(), "/")
		}
	}
	return ""
}

type Whois struct {
	Name         string   `json:"name"`
	Handle       string   `json:"handle"`
	Range        string   `json:"range"`
	Country      string   `json:"country,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Abuse        []string `json:"abuse_email,omitempty"`
	Created      string   `json:"created,omitempty"`
	Updated      string   `json:"updated,omitempty"`
}

func (s *Service) Whois(ctx context.Context, ip netip.Addr) (any, error) {
	ip = ip.Unmap().WithZone("")
	endpoint := s.RDAPURL
	if endpoint == "" {
		var err error
		endpoint, err = s.rdapEndpoint(ctx, ip)
		if err != nil {
			return nil, err
		}
	}
	var r RDAP
	if err := s.json(ctx, endpoint+url.PathEscape(ip.String()), &r); err != nil {
		return nil, err
	}
	start, e1 := netip.ParseAddr(r.Start)
	end, e2 := netip.ParseAddr(r.End)
	if e1 != nil || e2 != nil || start.Zone() != "" || end.Zone() != "" || start.BitLen() != ip.BitLen() || end.BitLen() != ip.BitLen() || start.Compare(end) > 0 || start.Compare(ip) > 0 || end.Compare(ip) < 0 {
		return nil, fmt.Errorf("invalid RDAP network range")
	}
	w := Whois{Name: r.Name, Handle: r.Handle, Range: r.Start + " – " + r.End, Country: r.Country}
	contacts := rdapContacts(r.Entities)
	w.Organization, w.Abuse = registrantName(contacts), abuseEmails(contacts)
	w.Created, w.Updated = rdapDates(r.Events)
	return w, nil
}

// IANA bootstrapping avoids a third-party redirect service becoming a bottleneck.
// The longest matching prefix selects the authoritative registry over HTTPS.
func (s *Service) rdapEndpoint(ctx context.Context, ip netip.Addr) (string, error) {
	file := "ipv6.json"
	if ip.Is4() {
		file = "ipv4.json"
	}
	var bootstrap struct {
		Services [][][]string `json:"services"`
	}
	if err := s.json(ctx, s.BootstrapURL+file, &bootstrap); err != nil {
		return "", fmt.Errorf("RDAP bootstrap: %w", err)
	}
	best, endpoint := -1, ""
	for _, service := range bootstrap.Services {
		if len(service) != 2 {
			return "", fmt.Errorf("malformed RDAP bootstrap service")
		}
		for _, cidr := range service[0] {
			p, err := netip.ParsePrefix(cidr)
			if err != nil {
				return "", fmt.Errorf("invalid RDAP bootstrap prefix")
			}
			if !p.Contains(ip) || p.Bits() <= best {
				continue
			}
			best = p.Bits()
			endpoint = ""
			if base := rdapBase(service[1]); base != "" {
				endpoint = base + "/ip/"
			}
		}
	}
	if endpoint == "" {
		return "", fmt.Errorf("no HTTPS RDAP registry found for %s", ip)
	}
	return endpoint, nil
}

func (s *Service) RPKI(ctx context.Context, a ASN) (any, error) {
	u, err := url.Parse(s.RPKIURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("resource", fmt.Sprintf("AS%d", a.Number))
	q.Set("prefix", a.Prefix)
	u.RawQuery = q.Encode()
	var raw struct {
		Status string `json:"status"`
		Data   struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := s.json(ctx, u.String(), &raw); err != nil {
		return nil, err
	}
	if raw.Status != "ok" {
		return nil, fmt.Errorf("RIPEstat did not return ok status")
	}
	state := raw.Data.Status
	switch state {
	case "valid", "invalid_asn", "invalid_length", "invalid", "unknown":
	default:
		return nil, fmt.Errorf("unrecognized RPKI status %q", state)
	}
	return map[string]any{"asn": a.Number, "prefix": a.Prefix, "status": state}, nil
}

type PublicIP struct {
	IP     netip.Addr `json:"ip"`
	Source string     `json:"source"`
}

func (s *Service) PublicIP(ctx context.Context) (any, error) {
	return s.discoverPublicIP(ctx, "")
}

func (s *Service) PublicIPv4(ctx context.Context) (any, error) {
	return s.publicIPFamily(ctx, "tcp4")
}

func (s *Service) PublicIPv6(ctx context.Context) (any, error) {
	return s.publicIPFamily(ctx, "tcp6")
}

// Each family uses a fresh connection pool. Proxy settings are retained: the
// network selects the connection to the proxy, and the provider response must
// still contain a public address of the requested family.
func (s *Service) publicIPFamily(ctx context.Context, network string) (any, error) {
	base := s.HTTP.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	transport, ok := base.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("public IP discovery requires an HTTP transport with address-family control")
	}
	transport = transport.Clone()
	defer transport.CloseIdleConnections()
	dial := transport.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		return dial(ctx, network, address)
	}
	// Alternate TLS dialers or protocol callbacks can own their own pools and
	// bypass DialContext. Let this cloned transport handle TLS and ALPN itself.
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	transport.TLSNextProto = nil
	client := *s.HTTP
	client.Transport = transport
	service := *s
	service.HTTP = &client
	return service.discoverPublicIP(ctx, network)
}

func (s *Service) discoverPublicIP(ctx context.Context, network string) (any, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type response struct {
		p   PublicIP
		err error
	}
	ch := make(chan response, len(s.PublicURLs))
	for _, address := range s.PublicURLs {
		go func(address string) {
			b, err := s.get(ctx, address)
			var ip netip.Addr
			if err == nil {
				ip, err = netip.ParseAddr(strings.TrimSpace(string(b)))
				if err == nil && ip.Zone() != "" {
					err = fmt.Errorf("provider returned a scoped address")
				}
				if err == nil {
					ip = ip.Unmap()
					switch {
					case network == "tcp4" && !ip.Is4():
						err = fmt.Errorf("provider did not return IPv4")
					case network == "tcp6" && !ip.Is6():
						err = fmt.Errorf("provider did not return IPv6")
					case Classify(ip) != "Public":
						err = fmt.Errorf("provider returned a non-public address")
					}
				}
			}
			ch <- response{PublicIP{ip, address}, err}
		}(address)
	}
	var errs []string
	for range s.PublicURLs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r := <-ch:
			if r.err == nil {
				return r.p, nil
			}
			errs = append(errs, r.err.Error())
		}
	}
	return nil, fmt.Errorf("public IP discovery failed: %s", strings.Join(errs, "; "))
}
