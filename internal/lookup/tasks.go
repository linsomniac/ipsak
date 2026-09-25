package lookup

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
)

type Options struct {
	Trace      bool
	Probes     int
	TraceASN   bool
	Interfaces bool
}

func localInterfaces(context.Context, map[string]Section) (any, error) {
	type iface struct {
		Name      string   `json:"name"`
		Addresses []string `json:"addresses"`
	}
	host, _ := os.Hostname()
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := []iface{}
	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		entry := iface{Name: i.Name, Addresses: []string{}}
		for _, a := range addrs {
			entry.Addresses = append(entry.Addresses, a.String())
		}
		sort.Strings(entry.Addresses)
		out = append(out, entry)
	}
	return struct {
		Hostname   string  `json:"hostname"`
		Interfaces []iface `json:"interfaces"`
	}{host, out}, nil
}

func publicTarget(deps map[string]Section) (Target, error) {
	t := deps["target"].Data.(Target)
	if t.Class != "Public" {
		return t, Skip("public lookup is not applicable to " + t.Class + " addresses")
	}
	t.IP = t.IP.Unmap().WithZone("")
	return t, nil
}

func (s *Service) Tasks(command string, t Target, opts Options) ([]Task, error) {
	if command == "calc" {
		if !t.Prefix.IsValid() {
			return nil, fmt.Errorf("calc requires a CIDR, for example 10.0.0.0/24")
		}
		return []Task{{Key: "subnet", Title: "Subnet", Source: "local calculation", Run: func(context.Context, map[string]Section) (any, error) { return Calculate(t.Name) }}}, nil
	}
	if command == "dns" {
		if t.Prefix.IsValid() {
			return nil, fmt.Errorf("dns requires an IP address or domain")
		}
		return []Task{{Key: "dns", Title: "DNS", Source: "system resolver", Run: func(ctx context.Context, _ map[string]Section) (any, error) { return s.DNS.Records(ctx, t) }}}, nil
	}
	tasks := []Task{}
	resolve := Task{Key: "target", Title: "Target", Source: "system resolver", Run: func(ctx context.Context, _ map[string]Section) (any, error) { return Resolve(ctx, t, "ip") }}
	if command == "myip" {
		discovery := newPublicDiscovery(s.PublicIPv4, s.PublicIPv6)
		tasks = append(tasks,
			Task{Key: "public", Title: "First public response", Source: "HTTPS discovery", Run: func(ctx context.Context, _ map[string]Section) (any, error) { return discovery.result(ctx, 0) }},
			Task{Key: "public_ipv4", Title: "Public IPv4", Source: "HTTPS discovery · IPv4", Run: func(ctx context.Context, _ map[string]Section) (any, error) { return discovery.result(ctx, 1) }},
			Task{Key: "public_ipv6", Title: "Public IPv6", Source: "HTTPS discovery · IPv6", Run: func(ctx context.Context, _ map[string]Section) (any, error) { return discovery.result(ctx, 2) }},
		)
		if opts.Interfaces {
			tasks = append(tasks, Task{Key: "local", Title: "Your interfaces", Source: "local", Run: localInterfaces})
		}
		resolve.Title = "Address used for details"
		resolve.Source = "first response · DNS, registration, location"
		resolve.Depends = []string{"public"}
		resolve.Run = func(ctx context.Context, deps map[string]Section) (any, error) {
			ip := deps["public"].Data.(PublicIP).IP
			return ParseTarget(ip.String())
		}
	}
	tasks = append(tasks, resolve)
	if t.Prefix.IsValid() {
		tasks = append(tasks, Task{Key: "subnet", Title: "Subnet", Source: "local calculation", Run: func(context.Context, map[string]Section) (any, error) { return Calculate(t.Name) }})
	}
	if command == "info" || command == "myip" {
		dnsTask := Task{Key: "dns", Title: "DNS", Source: "system resolver", Depends: []string{"target"}, Run: func(ctx context.Context, deps map[string]Section) (any, error) {
			return s.DNS.Records(ctx, deps["target"].Data.(Target))
		}}
		if t.Kind == "domain" && command != "myip" {
			dnsTask.Depends = nil
			dnsTask.Run = func(ctx context.Context, _ map[string]Section) (any, error) { return s.DNS.Records(ctx, t) }
		}
		tasks = append(tasks, dnsTask)
		if t.Kind == "domain" && command != "myip" {
			tasks = append(tasks, Task{Key: "ptr", Title: "Reverse DNS", Source: "system resolver", Depends: []string{"target"}, Run: func(ctx context.Context, deps map[string]Section) (any, error) {
				return s.DNS.Records(ctx, deps["target"].Data.(Target))
			}})
		}
	}
	ipTask := func(key, title, source string, fn func(context.Context, netip.Addr) (any, error)) Task {
		return Task{Key: key, Title: title, Source: source, Depends: []string{"target"}, Run: func(ctx context.Context, deps map[string]Section) (any, error) {
			t, err := publicTarget(deps)
			if err != nil {
				return nil, err
			}
			return fn(ctx, t.IP)
		}}
	}
	if command == "info" || command == "myip" || command == "whois" {
		tasks = append(tasks, ipTask("whois", "Registration · RDAP", "IANA → regional registry", s.Whois))
	}
	if command == "info" || command == "myip" {
		tasks = append(tasks,
			ipTask("asn", "Network · ASN", "Team Cymru", func(ctx context.Context, ip netip.Addr) (any, error) { return s.DNS.ASN(ctx, ip) }),
			Task{Key: "asn_name", Title: "Network organization", Source: "Team Cymru", Depends: []string{"asn"}, Run: func(ctx context.Context, deps map[string]Section) (any, error) {
				return s.DNS.ASNName(ctx, deps["asn"].Data.(ASN).Number)
			}},
			ipTask("geo", "Location", "ipwho.is · approximate", s.Geo),
			Task{Key: "rpki", Title: "Route validation · RPKI", Source: "RIPEstat", Depends: []string{"asn"}, Run: func(ctx context.Context, deps map[string]Section) (any, error) {
				return s.RPKI(ctx, deps["asn"].Data.(ASN))
			}},
			ipTask("reputation", "Reputation · DNS blocklists", "Spamhaus · SpamCop · Barracuda", s.DNS.Reputation),
		)
	}
	if command == "trace" || opts.Trace {
		tasks = append(tasks, Task{Key: "trace", Title: "Traceroute", Source: "system traceroute / tracepath", Depends: []string{"target"}, Run: func(ctx context.Context, deps map[string]Section) (any, error) {
			return s.Trace(ctx, deps["target"].Data.(Target).IP, opts.Probes, opts.TraceASN)
		}})
	}
	return tasks, nil
}
