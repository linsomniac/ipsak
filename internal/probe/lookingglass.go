package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Provider struct{ Kind, URL string }

func LookingGlassOptions(resource string, providers []string, limit int, collector string) (string, []Provider, error) {
	if ip, err := netip.ParseAddr(resource); err == nil && ip.Zone() == "" {
		resource = ip.Unmap().String()
	} else if prefix, err := netip.ParsePrefix(resource); err == nil {
		resource = prefix.Masked().String()
	} else {
		return "", nil, fmt.Errorf("lookingglass requires an IP address or CIDR prefix")
	}
	if limit < 1 || limit > 1000 {
		return "", nil, fmt.Errorf("route limit must be 1–1000")
	}
	if len(providers) == 0 || len(providers) > 4 {
		return "", nil, fmt.Errorf("select one to four looking-glass providers")
	}
	if collector != "" {
		suffix := strings.TrimPrefix(collector, "rrc")
		n, err := strconv.Atoi(suffix)
		if err != nil || n < 0 || n > 999 {
			return "", nil, fmt.Errorf("collector must be an RRC identifier such as rrc00")
		}
	}
	out := []Provider{}
	for _, raw := range providers {
		kind, endpoint, override := strings.Cut(raw, "=")
		switch kind {
		case "ripe":
			if !override {
				endpoint = "https://stat.ripe.net/data/looking-glass/data.json"
			}
		case "nlnog":
			if !override {
				endpoint = "https://lg.ring.nlnog.net/api/prefix"
			}
		default:
			return "", nil, fmt.Errorf("unknown provider %q; choose ripe or nlnog", kind)
		}
		u, err := HTTPURL(endpoint)
		if err != nil {
			return "", nil, err
		}
		if err = providerURL(u); err != nil {
			return "", nil, err
		}
		out = append(out, Provider{Kind: kind, URL: u.String()})
	}
	return resource, out, nil
}

func providerURL(u *url.URL) error {
	if u.Scheme == "https" {
		return nil
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if u.Scheme == "http" && err == nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("provider endpoints require HTTPS (HTTP permitted only for numeric loopback fixtures)")
}

type BGPRoute struct {
	Collector   string   `json:"collector"`
	Location    string   `json:"location,omitempty"`
	Peer        string   `json:"peer"`
	Prefix      string   `json:"prefix"`
	ASPath      []string `json:"as_path"`
	NextHop     string   `json:"next_hop,omitempty"`
	Origin      string   `json:"origin,omitempty"`
	LastUpdated string   `json:"last_updated,omitempty"`
	LatestTime  string   `json:"latest_time,omitempty"`
}
type LookingGlassResult struct {
	Provider    string     `json:"provider"`
	URL         string     `json:"url"`
	Resource    string     `json:"resource"`
	QueryTime   string     `json:"query_time,omitempty"`
	LatestTime  string     `json:"latest_time,omitempty"`
	Routes      []BGPRoute `json:"routes"`
	TotalRoutes int        `json:"total_routes"`
	Truncated   bool       `json:"truncated"`
	HasRoutes   bool       `json:"has_routes"`
	Warnings    []string   `json:"warnings"`
	Scope       string     `json:"scope"`
}

// scalar accepts the documented string fields and numeric collector IDs emitted
// by some API versions without converting arbitrary objects into display text.
type scalar string

func (s *scalar) UnmarshalJSON(b []byte) error {
	var str string
	if json.Unmarshal(b, &str) == nil {
		*s = scalar(str)
		return nil
	}
	var n json.Number
	if json.Unmarshal(b, &n) == nil && n != "" {
		*s = scalar(n)
		return nil
	}
	return fmt.Errorf("expected scalar string or number")
}

type asPath []string

func (p *asPath) UnmarshalJSON(b []byte) error {
	var str string
	if json.Unmarshal(b, &str) == nil {
		*p = strings.Fields(str)
		return nil
	}
	var fields []scalar
	if err := json.Unmarshal(b, &fields); err != nil {
		return err
	}
	*p = []string{}
	for _, f := range fields {
		*p = append(*p, string(f))
	}
	return nil
}

func fetchProvider(ctx context.Context, address string) ([]byte, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxResponseHeaderBytes = 64 << 10
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return fmt.Errorf("provider redirect limit exceeded")
		}
		if req.URL.User != nil {
			return fmt.Errorf("provider redirect contains credentials")
		}
		return providerURL(req.URL)
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ipsak/1.0")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 2<<20 {
		return nil, fmt.Errorf("provider response exceeds 2 MiB")
	}
	return b, nil
}

func matchingPrefix(prefix, resource string) bool {
	p, err := netip.ParsePrefix(prefix)
	if err != nil || p != p.Masked() {
		return false
	}
	if ip, err := netip.ParseAddr(resource); err == nil {
		return p.Contains(ip)
	}
	want, err := netip.ParsePrefix(resource)
	return err == nil && want.Masked() == p
}

func LookingGlass(ctx context.Context, resource string, provider Provider, limit int, collector string) (LookingGlassResult, error) {
	r := LookingGlassResult{Provider: provider.Kind, Resource: resource, Routes: []BGPRoute{}, Warnings: []string{}, Scope: "BGP routes observed by this provider's collectors; not remote ping/traceroute or a reachability guarantee"}
	if limit < 1 || limit > 1000 {
		return r, fmt.Errorf("invalid route limit")
	}
	u, err := url.Parse(provider.URL)
	if err != nil {
		return r, err
	}
	q := u.Query()
	switch provider.Kind {
	case "ripe":
		q.Set("resource", resource)
		q.Set("look_back_limit", "86400")
	case "nlnog":
		q.Set("q", resource)
		q.Set("match", "exact")
	default:
		return r, fmt.Errorf("unknown provider kind")
	}
	u.RawQuery = q.Encode()
	r.URL = u.String()
	b, err := fetchProvider(ctx, r.URL)
	if err != nil {
		return r, err
	}
	if provider.Kind == "ripe" {
		err = decodeRIPE(b, &r, collector)
	} else {
		err = decodeNLNOG(b, &r)
	}
	sort.Slice(r.Routes, func(i, j int) bool {
		a, b := r.Routes[i], r.Routes[j]
		if a.Collector != b.Collector {
			return a.Collector < b.Collector
		}
		if a.Peer != b.Peer {
			return a.Peer < b.Peer
		}
		if a.Prefix != b.Prefix {
			return a.Prefix < b.Prefix
		}
		return strings.Join(a.ASPath, " ") < strings.Join(b.ASPath, " ")
	})
	r.TotalRoutes = len(r.Routes)
	r.HasRoutes = r.TotalRoutes > 0
	if len(r.Routes) > limit {
		r.Routes = r.Routes[:limit]
		r.Truncated = true
		r.Warnings = append(r.Warnings, "Route display limit reached; total_routes counts the returned provider data")
	}
	if !r.HasRoutes && err == nil {
		r.Warnings = append(r.Warnings, "No routes returned for this query; this does not establish global route absence")
	}
	if r.LatestTime == "" {
		r.Warnings = append(r.Warnings, "Provider did not supply a freshness timestamp")
	} else {
		parsed := time.Time{}
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05 MST"} {
			if t, e := time.Parse(layout, r.LatestTime); e == nil {
				parsed = t
				break
			}
		}
		if parsed.IsZero() {
			r.Warnings = append(r.Warnings, "Provider freshness timestamp could not be interpreted")
		} else if time.Since(parsed) > 24*time.Hour {
			r.Warnings = append(r.Warnings, "Provider freshness timestamp is older than 24 hours")
		}
	}
	return r, err
}

func decodeRIPE(b []byte, out *LookingGlassResult, collector string) error {
	var raw struct {
		Status string `json:"status"`
		Data   *struct {
			QueryTime  string `json:"query_time"`
			LatestTime string `json:"latest_time"`
			RRCs       []struct {
				RRC      scalar `json:"rrc"`
				Location string `json:"location"`
				Peers    []struct {
					Peer        string `json:"peer"`
					Prefix      string `json:"prefix"`
					ASPath      asPath `json:"as_path"`
					NextHop     string `json:"next_hop"`
					Origin      scalar `json:"origin"`
					LastUpdated string `json:"last_updated"`
					LatestTime  string `json:"latest_time"`
				} `json:"peers"`
			} `json:"rrcs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("invalid RIPE JSON: %w", err)
	}
	if raw.Status != "ok" || raw.Data == nil || raw.Data.RRCs == nil {
		return fmt.Errorf("RIPE returned missing data or unsuccessful status %q", raw.Status)
	}
	out.QueryTime, out.LatestTime = raw.Data.QueryTime, raw.Data.LatestTime
	for _, rrc := range raw.Data.RRCs {
		name := strings.ToLower(string(rrc.RRC))
		if n, err := strconv.Atoi(name); err == nil {
			name = fmt.Sprintf("rrc%02d", n)
		}
		if collector != "" && strings.TrimLeft(strings.TrimPrefix(name, "rrc"), "0") != strings.TrimLeft(strings.TrimPrefix(collector, "rrc"), "0") {
			continue
		}
		for _, p := range rrc.Peers {
			if name == "" || p.Peer == "" || !matchingPrefix(p.Prefix, out.Resource) {
				return fmt.Errorf("RIPE returned invalid or unrelated route")
			}
			out.Routes = append(out.Routes, BGPRoute{Collector: name, Location: rrc.Location, Peer: p.Peer, Prefix: p.Prefix, ASPath: append([]string{}, p.ASPath...), NextHop: p.NextHop, Origin: string(p.Origin), LastUpdated: p.LastUpdated, LatestTime: p.LatestTime})
		}
	}
	return nil
}

func decodeNLNOG(b []byte, out *LookingGlassResult) error {
	var raw struct {
		Error     string   `json:"error"`
		Prefix    string   `json:"prefix"`
		Collected string   `json:"collected"`
		Warnings  []string `json:"warnings"`
		Routes    map[string][]struct {
			Peer       string     `json:"peer"`
			IP         string     `json:"ip"`
			ASPath     [][]scalar `json:"aspath"`
			Origin     string     `json:"origin"`
			NextHop    string     `json:"exit_nexthop"`
			LastUpdate string     `json:"last_update_at"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("invalid NLNOG JSON: %w", err)
	}
	if raw.Error != "" {
		return fmt.Errorf("NLNOG: %s", raw.Error)
	}
	if raw.Routes == nil || raw.Prefix == "" {
		return fmt.Errorf("NLNOG returned missing route data")
	}
	if raw.Prefix != out.Resource && !matchingPrefix(raw.Prefix, out.Resource) {
		return fmt.Errorf("NLNOG returned an unrelated declared prefix")
	}
	out.LatestTime = raw.Collected
	out.Warnings = append(out.Warnings, raw.Warnings...)
	prefixes := make([]string, 0, len(raw.Routes))
	for prefix := range raw.Routes {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	for _, prefix := range prefixes {
		peers := raw.Routes[prefix]
		for _, p := range peers {
			if p.Peer == "" || !matchingPrefix(prefix, out.Resource) {
				return fmt.Errorf("NLNOG returned invalid or unrelated route")
			}
			path := []string{}
			for _, part := range p.ASPath {
				if len(part) == 0 {
					return fmt.Errorf("NLNOG returned malformed AS path")
				}
				path = append(path, string(part[0]))
			}
			out.Routes = append(out.Routes, BGPRoute{Collector: "nlnog", Peer: p.Peer, Prefix: prefix, ASPath: path, NextHop: p.NextHop, Origin: p.Origin, LastUpdated: p.LastUpdate})
		}
	}
	return nil
}
