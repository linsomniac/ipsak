package hostnet

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"

	"github.com/linsomniac/ipsak/internal/lookup"
)

type RouteReport struct {
	Destination   string   `json:"destination"`
	Address       string   `json:"address"`
	Interface     string   `json:"interface"`
	Source        *string  `json:"source"`
	SourceMethod  string   `json:"source_method"`
	Gateway       *string  `json:"gateway"`
	NextHopKind   string   `json:"next_hop_kind"`
	MatchedPrefix *string  `json:"matched_prefix"`
	Table         any      `json:"table,omitempty"`
	RouteType     string   `json:"route_type"`
	Notes         []string `json:"notes"`
}

// Route asks the OS to select the route for the first resolved address. A route
// lookup does not send traffic to the destination or prove reachability.
func Route(ctx context.Context, target string) (RouteReport, error) {
	r := RouteReport{Destination: target, Notes: []string{}}
	t, err := lookup.ParseTarget(target)
	if err != nil {
		return r, err
	}
	if t.Prefix.IsValid() {
		return r, fmt.Errorf("route requires a host address or domain, not a CIDR")
	}
	if !t.IP.IsValid() {
		t, err = lookup.Resolve(ctx, t, "ip")
		if err != nil {
			return r, err
		}
	}
	ip := t.IP.Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() || ip == netip.MustParseAddr("255.255.255.255") {
		return r, fmt.Errorf("route requires a unicast destination")
	}
	r.Address = ip.String()
	switch runtime.GOOS {
	case "linux":
		family := "-4"
		if ip.Is6() {
			family = "-6"
		}
		args := []string{"-j", family, "route", "get", ip.WithZone("").String()}
		if ip.Zone() != "" {
			args = append(args, "oif", ip.Zone())
		}
		var selected, matched []byte
		var selectedErr, matchedErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); selected, selectedErr = command(ctx, "ip", args...) }()
		go func() {
			defer wg.Done()
			a := append(append([]string{}, args[:4]...), "fibmatch")
			a = append(a, args[4:]...)
			matched, matchedErr = command(ctx, "ip", a...)
		}()
		wg.Wait()
		if selectedErr != nil {
			return r, selectedErr
		}
		if err = parseLinuxRoute(selected, &r); err != nil {
			return r, err
		}
		if matchedErr == nil {
			var routes []linuxRoute
			if err = json.Unmarshal(matched, &routes); err == nil && len(routes) > 0 && routes[0].Destination != "" {
				prefix := routes[0].Destination
				if prefix == "default" {
					prefix = "0.0.0.0/0"
					if ip.Is6() {
						prefix = "::/0"
					}
				}
				if a, e := netip.ParseAddr(prefix); e == nil {
					prefix = netip.PrefixFrom(a, a.BitLen()).String()
				}
				if p, e := netip.ParsePrefix(prefix); e == nil && p.Contains(ip.WithZone("")) {
					r.MatchedPrefix = &prefix
					r.Table = routes[0].Table
				} else {
					matchedErr = fmt.Errorf("invalid matched prefix")
				}
			} else {
				matchedErr = fmt.Errorf("empty or invalid matching route response")
			}
		}
		if matchedErr != nil {
			r.Notes = append(r.Notes, "Matching route unavailable: "+matchedErr.Error())
		}
	case "darwin":
		family := "-inet"
		if ip.Is6() {
			family = "-inet6"
		}
		data, e := command(ctx, "route", "-n", "get", family, ip.String())
		if e != nil {
			return r, e
		}
		if err = parseDarwinRoute(data, &r); err != nil {
			return r, err
		}
	default:
		return r, fmt.Errorf("route is unsupported on %s; supported systems are Linux and macOS", runtime.GOOS)
	}
	if r.Source == nil {
		// UDP connect asks the kernel for a source without transmitting a packet.
		conn, e := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(ip.String(), "9"))
		if e != nil {
			r.SourceMethod = "unavailable"
			r.Notes = append(r.Notes, "Source address unavailable: "+e.Error())
		} else {
			s := conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr().String()
			_ = conn.Close()
			r.Source = &s
			r.SourceMethod = "UDP route selection (may differ with policy routing)"
		}
	}
	return r, ctx.Err()
}

type linuxRoute struct {
	Destination     string `json:"dst"`
	Device          string `json:"dev"`
	Gateway         string `json:"gateway"`
	PreferredSource string `json:"prefsrc"`
	Source          string `json:"src"`
	Type            string `json:"type"`
	Table           any    `json:"table"`
}

func parseLinuxRoute(data []byte, r *RouteReport) error {
	var rows []linuxRoute
	if err := json.Unmarshal(data, &rows); err != nil {
		return fmt.Errorf("invalid ip route JSON: %w", err)
	}
	if len(rows) != 1 || rows[0].Device == "" {
		return fmt.Errorf("route selection returned no unique outgoing interface")
	}
	v := rows[0]
	address, addressErr := netip.ParseAddr(r.Address)
	r.Interface = v.Device
	r.RouteType = v.Type
	r.Table = v.Table
	if r.RouteType == "" {
		r.RouteType = "unicast"
	}
	if v.Gateway != "" {
		if a, e := netip.ParseAddr(v.Gateway); e != nil || (addressErr == nil && a.Is4() != address.Is4()) {
			return fmt.Errorf("invalid gateway in route response")
		}
		r.Gateway = &v.Gateway
		r.NextHopKind = "gateway"
	} else {
		r.NextHopKind = "on-link"
		if r.RouteType == "local" {
			r.NextHopKind = "local"
		}
	}
	source := v.PreferredSource
	if source == "" {
		source = v.Source
	}
	if source != "" {
		if a, e := netip.ParseAddr(source); e != nil || (addressErr == nil && a.Is4() != address.Is4()) {
			return fmt.Errorf("invalid source in route response")
		}
		r.Source = &source
		r.SourceMethod = "OS route selection"
	}
	return nil
}
func parseDarwinRoute(data []byte, r *RouteReport) error {
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			values[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	r.Interface = values["interface"]
	r.RouteType = "unicast"
	flags := map[string]bool{}
	for _, flag := range strings.Split(strings.Trim(values["flags"], "<>"), ",") {
		flags[strings.TrimSpace(flag)] = true
	}
	if flags["LOCAL"] {
		r.RouteType = "local"
	}
	if flags["REJECT"] {
		r.RouteType = "unreachable"
	}
	if flags["BLACKHOLE"] {
		r.RouteType = "blackhole"
	}
	if r.Interface == "" {
		return fmt.Errorf("route selection returned no outgoing interface")
	}
	gateway := values["gateway"]
	if a, e := netip.ParseAddr(gateway); e == nil {
		g := a.String()
		r.Gateway = &g
		r.NextHopKind = "gateway"
	} else if strings.HasPrefix(gateway, "link#") || gateway == "" {
		r.NextHopKind = "on-link"
	} else if mac, e := darwinMAC(gateway); e == nil {
		r.NextHopKind = "on-link"
		r.Notes = append(r.Notes, "On-link link-layer next hop: "+mac)
	} else {
		return fmt.Errorf("unrecognized route gateway %q", gateway)
	}
	dest := values["destination"]
	mask := values["mask"]
	if dest == "default" {
		p := "0.0.0.0/0"
		if strings.Contains(r.Address, ":") {
			p = "::/0"
		}
		r.MatchedPrefix = &p
	} else if p, e := netip.ParsePrefix(dest); e == nil {
		s := p.Masked().String()
		r.MatchedPrefix = &s
	} else if a, e := netip.ParseAddr(dest); e == nil {
		bits := a.BitLen()
		if mask != "" {
			m := net.ParseIP(mask)
			if m != nil {
				if a.Is4() {
					m = m.To4()
				}
				n, total := net.IPMask(m).Size()
				if total == bits {
					bits = n
				} else {
					bits = -1
				}
			} else {
				bits = -1
			}
		}
		if bits >= 0 {
			s := netip.PrefixFrom(a, bits).Masked().String()
			r.MatchedPrefix = &s
		}
	}
	if r.MatchedPrefix == nil {
		r.Notes = append(r.Notes, "Matching prefix unavailable from system route output")
	}
	if r.RouteType == "local" {
		r.NextHopKind = "local"
	}
	if r.RouteType == "unreachable" || r.RouteType == "blackhole" {
		r.NextHopKind = r.RouteType
		return fmt.Errorf("selected %s route does not forward packets to the destination", r.RouteType)
	}
	return nil
}
