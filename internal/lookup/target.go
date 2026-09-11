package lookup

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

type Target struct {
	Name   string       `json:"name"`
	Kind   string       `json:"kind"`
	IP     netip.Addr   `json:"ip,omitempty"`
	Prefix netip.Prefix `json:"-"`
	Class  string       `json:"classification,omitempty"`
}

func ParseTarget(input string) (Target, error) {
	s := strings.TrimSpace(input)
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return Target{}, fmt.Errorf("invalid target %q", input)
		}
		s = u.Hostname()
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	} else if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	if ip, err := netip.ParseAddr(s); err == nil {
		ip = ip.Unmap()
		kind := "ipv6"
		if ip.Is4() {
			kind = "ipv4"
		}
		return Target{Name: ip.String(), Kind: kind, IP: ip, Class: Classify(ip)}, nil
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Target{}, fmt.Errorf("invalid CIDR %q", s)
		}
		p = p.Masked()
		kind := "cidr6"
		if p.Addr().Is4() {
			kind = "cidr4"
		}
		return Target{Name: p.String(), Kind: kind, IP: p.Addr(), Prefix: p, Class: Classify(p.Addr())}, nil
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	s, err := idna.Lookup.ToASCII(s)
	if err != nil || s == "" || len(s) > 253 {
		return Target{}, fmt.Errorf("invalid host %q", input)
	}
	allNumeric := true
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return Target{}, fmt.Errorf("invalid host %q", input)
		}
		for _, c := range label {
			if !(c >= '0' && c <= '9') {
				allNumeric = false
			}
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return Target{}, fmt.Errorf("invalid host %q", input)
			}
		}
	}
	if allNumeric {
		return Target{}, fmt.Errorf("invalid IP address %q", input)
	}
	return Target{Name: s, Kind: "domain"}, nil
}

func Resolve(ctx context.Context, t Target, family string) (Target, error) {
	if t.IP.IsValid() {
		if family == "ip4" && !t.IP.Is4() || family == "ip6" && !t.IP.Is6() {
			return t, fmt.Errorf("target does not match requested address family")
		}
		return t, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, family, t.Name)
	if err != nil {
		return t, err
	}
	if len(ips) == 0 {
		return t, fmt.Errorf("no addresses for %s", t.Name)
	}
	t.IP = ips[0].Unmap()
	if family == "ip" {
		for _, ip := range ips {
			if ip.Is4() {
				t.IP = ip
				break
			}
		}
	}
	t.Class = Classify(t.IP)
	return t, nil
}

var specialRanges = []struct {
	prefix netip.Prefix
	name   string
}{}

func init() {
	// Most-specific match preserves globally reachable exceptions.
	for _, entry := range []string{
		"0.0.0.0/8|This host", "10.0.0.0/8|Private", "100.64.0.0/10|Shared address (CGNAT)",
		"127.0.0.0/8|Loopback", "169.254.0.0/16|Link-local", "172.16.0.0/12|Private",
		"192.0.0.0/24|IETF protocol assignments", "192.0.0.9/32|Public", "192.0.0.10/32|Public",
		"192.0.2.0/24|Documentation", "192.88.99.0/24|Deprecated 6to4 relay", "192.168.0.0/16|Private",
		"198.18.0.0/15|Benchmarking", "198.51.100.0/24|Documentation", "203.0.113.0/24|Documentation",
		"224.0.0.0/4|Multicast", "240.0.0.0/4|Reserved", "255.255.255.255/32|Limited broadcast",
		"::/128|Unspecified", "::1/128|Loopback", "::/96|Reserved", "64:ff9b::/96|Translation",
		"64:ff9b:1::/48|Local translation", "100::/64|Discard-only", "100:0:0:1::/64|Dummy prefix",
		"2001::/23|IETF protocol assignments", "2001:1::1/128|Public", "2001:1::2/128|Public", "2001:1::3/128|Public", "2001:3::/32|Public",
		"2001:4:112::/48|Public", "2001:20::/28|Public", "2001:30::/28|Public",
		"2001:db8::/32|Documentation", "2002::/16|6to4", "3fff::/20|Documentation",
		"5f00::/16|Segment routing", "fc00::/7|Unique local", "fe80::/10|Link-local", "ff00::/8|Multicast",
	} {
		p, n, _ := strings.Cut(entry, "|")
		specialRanges = append(specialRanges, struct {
			prefix netip.Prefix
			name   string
		}{netip.MustParsePrefix(p), n})
	}
}

// Classify is an operational special-use classification, not a routing assertion.
func Classify(ip netip.Addr) string {
	ip = ip.Unmap().WithZone("")
	name := "Public"
	bits := -1
	for _, r := range specialRanges {
		if r.prefix.Contains(ip) && r.prefix.Bits() > bits {
			name = r.name
			bits = r.prefix.Bits()
		}
	}
	if bits < 0 && ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return "Reserved"
	}
	return name
}
