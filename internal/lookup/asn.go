package lookup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// ParseASN accepts an AS number written as "AS15169" or "15169".
func ParseASN(raw string) (uint32, error) {
	digits := raw
	if len(raw) >= 2 && strings.EqualFold(raw[:2], "AS") {
		digits = raw[2:]
	}
	n, err := strconv.ParseUint(digits, 10, 32)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("expected an AS number such as AS15169")
	}
	return uint32(n), nil
}

type ASNInfo struct {
	Number    uint32 `json:"asn"`
	Name      string `json:"name"`
	Country   string `json:"country,omitempty"`
	Registry  string `json:"registry,omitempty"`
	Allocated string `json:"allocated,omitempty"`
}

// asnRecord reads Team Cymru's "ASN | CC | registry | allocated | name" record.
func (c *DNSClient) asnRecord(ctx context.Context, number uint32) (ASNInfo, error) {
	txt, err := c.txt(ctx, fmt.Sprintf("AS%d.asn.cymru.com", number))
	if err != nil {
		return ASNInfo{}, err
	}
	f := strings.SplitN(txt[0], "|", 5)
	if len(f) != 5 {
		return ASNInfo{}, fmt.Errorf("malformed Team Cymru ASN name record")
	}
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	returned, err := strconv.ParseUint(f[0], 10, 32)
	if err != nil || returned != uint64(number) {
		return ASNInfo{}, fmt.Errorf("Team Cymru ASN name does not match requested ASN")
	}
	return ASNInfo{Number: number, Name: f[4], Country: f[1], Registry: f[2], Allocated: f[3]}, nil
}

func (c *DNSClient) ASNInfo(ctx context.Context, number uint32) (ASNInfo, error) {
	info, err := c.asnRecord(ctx, number)
	if errors.Is(err, ErrNXDomain) {
		return info, fmt.Errorf("Team Cymru has no record for AS%d", number)
	}
	return info, err
}

type ASNRegistration struct {
	Handle       string   `json:"handle"`
	Name         string   `json:"name,omitempty"`
	Range        string   `json:"range"`
	Country      string   `json:"country,omitempty"`
	Status       []string `json:"status,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Abuse        []string `json:"abuse_email,omitempty"`
	Created      string   `json:"created,omitempty"`
	Updated      string   `json:"updated,omitempty"`
}

func (s *Service) ASNRegistration(ctx context.Context, number uint32) (ASNRegistration, error) {
	endpoint, err := s.asnRDAPEndpoint(ctx, number)
	if err != nil {
		return ASNRegistration{}, err
	}
	var r struct {
		Handle   string       `json:"handle"`
		Name     string       `json:"name"`
		Start    *uint32      `json:"startAutnum"`
		End      *uint32      `json:"endAutnum"`
		Country  string       `json:"country"`
		Status   []string     `json:"status"`
		Entities []RDAPEntity `json:"entities"`
		Events   []RDAPEvent  `json:"events"`
	}
	if err := s.json(ctx, endpoint+strconv.FormatUint(uint64(number), 10), &r); err != nil {
		return ASNRegistration{}, err
	}
	// Registries answer for a block when the number is reserved or unassigned.
	if r.Start == nil || r.End == nil || *r.Start > number || *r.End < number {
		return ASNRegistration{}, fmt.Errorf("invalid RDAP autnum range")
	}
	out := ASNRegistration{Handle: r.Handle, Name: r.Name, Range: fmt.Sprintf("AS%d", *r.Start), Country: r.Country, Status: r.Status}
	if *r.Start != *r.End {
		out.Range = fmt.Sprintf("AS%d – AS%d", *r.Start, *r.End)
	}
	contacts := rdapContacts(r.Entities)
	out.Organization = registrantName(contacts)
	for _, c := range contacts {
		if !c.has("abuse") {
			continue
		}
		for _, email := range c.Emails {
			if !slices.Contains(out.Abuse, email) {
				out.Abuse = append(out.Abuse, email)
			}
		}
	}
	out.Created, out.Updated = rdapDates(r.Events)
	return out, nil
}

// AIDEV-NOTE: RIPE lists maintainers as registrants beside the holding
// organisation, so the vCard kind decides. Whois keeps its older rule (the
// last registrant wins) and shows a maintainer name for the same data.
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

// asnRDAPEndpoint selects the registry from IANA's ASN bootstrap. The narrowest
// matching range wins, as the longest prefix does for addresses.
func (s *Service) asnRDAPEndpoint(ctx context.Context, number uint32) (string, error) {
	var bootstrap struct {
		Services [][][]string `json:"services"`
	}
	if err := s.json(ctx, s.BootstrapURL+"asn.json", &bootstrap); err != nil {
		return "", fmt.Errorf("RDAP bootstrap: %w", err)
	}
	found, best, endpoint := false, uint64(0), ""
	for _, service := range bootstrap.Services {
		if len(service) != 2 {
			return "", fmt.Errorf("malformed RDAP bootstrap service")
		}
		for _, entry := range service[0] {
			first, last, isRange := strings.Cut(entry, "-")
			if !isRange {
				last = first
			}
			start, e1 := strconv.ParseUint(first, 10, 32)
			end, e2 := strconv.ParseUint(last, 10, 32)
			if e1 != nil || e2 != nil || start > end {
				return "", fmt.Errorf("invalid RDAP bootstrap ASN range")
			}
			if uint64(number) < start || uint64(number) > end || found && end-start >= best {
				continue
			}
			found, best, endpoint = true, end-start, ""
			if base := rdapBase(service[1]); base != "" {
				endpoint = base + "/autnum/"
			}
		}
	}
	if endpoint == "" {
		return "", fmt.Errorf("no HTTPS RDAP registry found for AS%d", number)
	}
	return endpoint, nil
}

type ASNNeighbour struct {
	Number  uint32 `json:"asn"`
	Name    string `json:"name,omitempty"`
	Power   int    `json:"power"`
	V4Peers int    `json:"v4_peers"`
	V6Peers int    `json:"v6_peers"`
}

type ASNNeighbourCounts struct {
	Total      int `json:"total"`
	Upstream   int `json:"upstream"`
	Downstream int `json:"downstream"`
	Uncertain  int `json:"uncertain"`
}

type ASNNeighbours struct {
	Number     uint32             `json:"asn"`
	Counts     ASNNeighbourCounts `json:"counts"`
	Upstream   []ASNNeighbour     `json:"upstream"`
	Downstream []ASNNeighbour     `json:"downstream"`
	Truncated  bool               `json:"truncated"`
	LatestTime string             `json:"latest_time,omitempty"`
	Warnings   []string           `json:"warnings"`
	Scope      string             `json:"scope"`
}

// AIDEV-NOTE: the interactive view shows sections in columns about 47 cells
// wide and hard-wraps longer lines mid-word, so both CompactLines methods keep
// fixed text short and put the unbounded AS name last. JSON has the full scope.
func (r ASNNeighbours) CompactLines() []string {
	lines := []string{fmt.Sprintf("%d neighbours", r.Counts.Total), fmt.Sprintf("%d upstream · %d downstream · %d uncertain", r.Counts.Upstream, r.Counts.Downstream, r.Counts.Uncertain)}
	for _, side := range []struct {
		label  string
		total  int
		listed []ASNNeighbour
	}{{"Upstream", r.Counts.Upstream, r.Upstream}, {"Downstream", r.Counts.Downstream, r.Downstream}} {
		switch {
		case side.total == 0:
			lines = append(lines, side.label+" · none")
		case len(side.listed) < side.total:
			lines = append(lines, fmt.Sprintf("%s · top %d of %d by power", side.label, len(side.listed), side.total))
		default:
			lines = append(lines, fmt.Sprintf("%s · %d", side.label, side.total))
		}
		for _, n := range side.listed {
			line := fmt.Sprintf("  AS%d · power %d", n.Number, n.Power)
			if n.Name != "" {
				line += " · " + n.Name
			}
			lines = append(lines, line)
		}
	}
	return append(append(lines, r.Warnings...), "Path positions, not business relationships")
}

// ripestat fetches one RIPEstat data call for an AS into data, after checking
// that the envelope reports success for the AS that was asked about.
func (s *Service) ripestat(ctx context.Context, endpoint string, number uint32, data any) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("resource", fmt.Sprintf("AS%d", number))
	u.RawQuery = q.Encode()
	var raw struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := s.json(ctx, u.String(), &raw); err != nil {
		return err
	}
	if raw.Status != "ok" {
		return fmt.Errorf("RIPEstat did not return ok status")
	}
	var echo struct {
		Resource string `json:"resource"`
	}
	_ = json.Unmarshal(raw.Data, &echo)
	if returned, err := ParseASN(echo.Resource); err != nil || returned != number {
		return fmt.Errorf("RIPEstat returned a different or missing resource")
	}
	if err := json.Unmarshal(raw.Data, data); err != nil {
		return fmt.Errorf("invalid provider JSON: %w", err)
	}
	return nil
}

// ASNNeighbours lists at most limit neighbours per direction, strongest first.
// AIDEV-NOTE: RIPEstat's "left" and "right" are positions in observed AS
// paths. They are presented as upstream and downstream, which is the usual
// reading but is not a statement about transit or peering contracts.
func (s *Service) ASNNeighbours(ctx context.Context, number uint32, limit int) (ASNNeighbours, error) {
	out := ASNNeighbours{Number: number, Upstream: []ASNNeighbour{}, Downstream: []ASNNeighbour{}, Warnings: []string{}, Scope: "AS-path adjacency seen by RIPE RIS collectors; upstream and downstream are path positions, not confirmed business relationships"}
	if limit < 1 || limit > 100 {
		return out, fmt.Errorf("neighbour limit must be 1–100")
	}
	var data struct {
		LatestTime string `json:"latest_time"`
		Neighbours []struct {
			Number  uint32 `json:"asn"`
			Type    string `json:"type"`
			Power   int    `json:"power"`
			V4Peers int    `json:"v4_peers"`
			V6Peers int    `json:"v6_peers"`
		} `json:"neighbours"`
	}
	if err := s.ripestat(ctx, s.NeighboursURL, number, &data); err != nil {
		return out, err
	}
	out.LatestTime = data.LatestTime
	out.Counts.Total = len(data.Neighbours)
	for _, n := range data.Neighbours {
		if n.Number == 0 || n.Power < 0 || n.V4Peers < 0 || n.V6Peers < 0 {
			return out, fmt.Errorf("RIPEstat returned an invalid neighbour")
		}
		neighbour := ASNNeighbour{Number: n.Number, Power: n.Power, V4Peers: n.V4Peers, V6Peers: n.V6Peers}
		switch n.Type {
		case "left":
			out.Upstream = append(out.Upstream, neighbour)
		case "right":
			out.Downstream = append(out.Downstream, neighbour)
		case "uncertain":
			out.Counts.Uncertain++
		default:
			return out, fmt.Errorf("unrecognized RIPEstat neighbour type %q", n.Type)
		}
	}
	out.Counts.Upstream, out.Counts.Downstream = len(out.Upstream), len(out.Downstream)
	var listed []*ASNNeighbour
	for _, side := range []*[]ASNNeighbour{&out.Upstream, &out.Downstream} {
		all := *side
		sort.Slice(all, func(i, j int) bool {
			if all[i].Power != all[j].Power {
				return all[i].Power > all[j].Power
			}
			return all[i].Number < all[j].Number
		})
		if len(all) > limit {
			*side = all[:limit]
			out.Truncated = true
		}
		for i := range *side {
			listed = append(listed, &(*side)[i])
		}
	}
	// Names are looked up only for listed neighbours, a few at a time, so a
	// well-connected AS cannot turn one command into hundreds of DNS queries.
	var wg sync.WaitGroup
	var failed atomic.Int32
	slots := make(chan struct{}, 8)
	for _, n := range listed {
		wg.Add(1)
		go func(n *ASNNeighbour) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			info, err := s.DNS.ASNInfo(ctx, n.Number)
			if err != nil {
				failed.Add(1)
				return
			}
			n.Name = info.Name
		}(n)
	}
	wg.Wait()
	if failed.Load() > 0 {
		warning := fmt.Sprintf("Names unavailable for %d of %d listed neighbours", failed.Load(), len(listed))
		// AIDEV-NOTE: RIPEstat's answer is still good when the deadline lands
		// here, so it is kept and the warning names the real cause. runReport
		// turns the expired deadline into a nonzero exit.
		if err := ctx.Err(); err != nil {
			warning += ": lookups stopped early (" + err.Error() + ")"
		}
		out.Warnings = append(out.Warnings, warning)
	}
	return out, nil
}

type ASNSighting struct {
	Prefix string `json:"prefix"`
	Time   string `json:"time"`
}

type ASNRoutingV4 struct {
	PeersSeeing int    `json:"ris_peers_seeing"`
	TotalPeers  int    `json:"total_ris_peers"`
	Prefixes    int    `json:"prefixes"`
	Addresses   uint64 `json:"addresses"`
}

type ASNRoutingV6 struct {
	PeersSeeing int    `json:"ris_peers_seeing"`
	TotalPeers  int    `json:"total_ris_peers"`
	Prefixes    int    `json:"prefixes"`
	Slash48s    uint64 `json:"slash48s"`
}

type ASNRouting struct {
	Number             uint32       `json:"asn"`
	Announced          bool         `json:"announced"`
	FirstSeen          *ASNSighting `json:"first_seen,omitempty"`
	LastSeen           *ASNSighting `json:"last_seen,omitempty"`
	IPv4               ASNRoutingV4 `json:"ipv4"`
	IPv6               ASNRoutingV6 `json:"ipv6"`
	ObservedNeighbours int          `json:"observed_neighbours"`
	QueryTime          string       `json:"query_time,omitempty"`
	Scope              string       `json:"scope"`
}

func (r ASNRouting) CompactLines() []string {
	lines := []string{"Not announced"}
	if r.Announced {
		lines[0] = "Announced"
	}
	if r.FirstSeen != nil {
		lines = append(lines, "First seen "+r.FirstSeen.Time)
	}
	if r.LastSeen != nil {
		lines = append(lines, "Last seen "+r.LastSeen.Time)
	}
	return append(lines,
		fmt.Sprintf("IPv4 · %d of %d RIS peers", r.IPv4.PeersSeeing, r.IPv4.TotalPeers),
		fmt.Sprintf("  %d prefixes · %d addresses", r.IPv4.Prefixes, r.IPv4.Addresses),
		fmt.Sprintf("IPv6 · %d of %d RIS peers", r.IPv6.PeersSeeing, r.IPv6.TotalPeers),
		fmt.Sprintf("  %d prefixes · %d /48s", r.IPv6.Prefixes, r.IPv6.Slash48s),
		fmt.Sprintf("%d observed neighbours", r.ObservedNeighbours),
		"As seen by RIPE RIS route collectors",
	)
}

func (s *Service) ASNRouting(ctx context.Context, number uint32) (ASNRouting, error) {
	out := ASNRouting{Number: number, Scope: "Seen by RIPE RIS route collectors; routes visible to fewer than 10 full-feed peers are excluded"}
	type visibility struct {
		Seeing int `json:"ris_peers_seeing"`
		Total  int `json:"total_ris_peers"`
	}
	var data struct {
		FirstSeen  *ASNSighting `json:"first_seen"`
		LastSeen   *ASNSighting `json:"last_seen"`
		Visibility struct {
			V4 visibility `json:"v4"`
			V6 visibility `json:"v6"`
		} `json:"visibility"`
		Space struct {
			V4 struct {
				Prefixes int    `json:"prefixes"`
				IPs      uint64 `json:"ips"`
			} `json:"v4"`
			V6 struct {
				Prefixes int    `json:"prefixes"`
				Slash48s uint64 `json:"48s"`
			} `json:"v6"`
		} `json:"announced_space"`
		ObservedNeighbours int    `json:"observed_neighbours"`
		QueryTime          string `json:"query_time"`
	}
	if err := s.ripestat(ctx, s.RoutingURL, number, &data); err != nil {
		return out, err
	}
	v4, v6 := data.Visibility.V4, data.Visibility.V6
	if min(v4.Seeing, v4.Total, v6.Seeing, v6.Total, data.Space.V4.Prefixes, data.Space.V6.Prefixes, data.ObservedNeighbours) < 0 {
		return out, fmt.Errorf("RIPEstat returned invalid routing counts")
	}
	// An AS that was never routed has empty sighting objects.
	if data.FirstSeen != nil && data.FirstSeen.Time != "" {
		out.FirstSeen = data.FirstSeen
	}
	if data.LastSeen != nil && data.LastSeen.Time != "" {
		out.LastSeen = data.LastSeen
	}
	out.Announced = v4.Seeing > 0 || v6.Seeing > 0
	out.IPv4 = ASNRoutingV4{PeersSeeing: v4.Seeing, TotalPeers: v4.Total, Prefixes: data.Space.V4.Prefixes, Addresses: data.Space.V4.IPs}
	out.IPv6 = ASNRoutingV6{PeersSeeing: v6.Seeing, TotalPeers: v6.Total, Prefixes: data.Space.V6.Prefixes, Slash48s: data.Space.V6.Slash48s}
	out.ObservedNeighbours, out.QueryTime = data.ObservedNeighbours, data.QueryTime
	return out, nil
}

// sectionData drops a zero-valued result on failure, so a failed section
// reports its error without data that merely looks empty.
func sectionData[T any](value T, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return value, nil
}

// ASNTasks describes one AS. The providers do not depend on each other, so a
// failure in one leaves the other sections intact.
func (s *Service) ASNTasks(number uint32, limit int) []Task {
	return []Task{
		{Key: "asn", Title: "Network · ASN", Source: "Team Cymru", Run: func(ctx context.Context, _ map[string]Section) (any, error) {
			return sectionData(s.DNS.ASNInfo(ctx, number))
		}},
		{Key: "registration", Title: "Registration · RDAP", Source: "IANA → regional registry", Run: func(ctx context.Context, _ map[string]Section) (any, error) {
			return sectionData(s.ASNRegistration(ctx, number))
		}},
		{Key: "neighbours", Title: "Neighbours · BGP", Source: "RIPEstat", Run: func(ctx context.Context, _ map[string]Section) (any, error) {
			return sectionData(s.ASNNeighbours(ctx, number, limit))
		}},
		{Key: "routing", Title: "Routing visibility", Source: "RIPEstat", Run: func(ctx context.Context, _ map[string]Section) (any, error) {
			return sectionData(s.ASNRouting(ctx, number))
		}},
	}
}
