// Package discovery browses and resolves interface-scoped mDNS/DNS-SD services.
package discovery

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const enumeration = "_services._dns-sd._udp.local."

type Service struct {
	Interface    string   `json:"interface"`
	Name         string   `json:"name"`
	Instance     string   `json:"instance"`
	Type         string   `json:"type"`
	Host         string   `json:"host,omitempty"`
	Port         uint16   `json:"port,omitempty"`
	TXT          []string `json:"txt"`
	Addresses    []string `json:"addresses"`
	Endpoints    []string `json:"endpoints"`
	Complete     bool     `json:"complete"`
	TXTTruncated bool     `json:"txt_truncated"`
}
type cached struct {
	rr       dns.RR
	until    time.Time
	received time.Time
	size     int
}
type cache struct {
	records map[string]cached
	types   map[string]bool
	bytes   int
	limited bool
}

func ServiceType(raw string) (string, error) {
	name := strings.ToLower(dns.Fqdn(raw))
	if !strings.HasSuffix(name, ".local.") {
		name = strings.TrimSuffix(name, ".") + ".local."
	}
	labels := dns.SplitDomainName(name)
	if len(labels) != 3 || len(labels[0]) < 2 || len(labels[0]) > 16 || labels[0][0] != '_' || (labels[1] != "_tcp" && labels[1] != "_udp") || labels[2] != "local" {
		return "", fmt.Errorf("service type must be _name._tcp or _name._udp (optional .local)")
	}
	for _, r := range labels[0][1:] {
		if r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return "", fmt.Errorf("invalid service type label")
		}
	}
	return name, nil
}
func newCache(types []string) *cache {
	c := &cache{records: map[string]cached{}, types: map[string]bool{}}
	for _, t := range types {
		c.types[t] = true
	}
	return c
}
func rrKey(rr dns.RR) string {
	v := dns.Copy(rr)
	v.Header().Ttl = 0
	v.Header().Class = dns.ClassINET
	v.Header().Name = strings.ToLower(v.Header().Name)
	switch r := v.(type) {
	case *dns.PTR:
		r.Ptr = strings.ToLower(r.Ptr)
	case *dns.SRV:
		r.Target = strings.ToLower(r.Target)
	}
	return v.String()
}
func (c *cache) expire(now time.Time) {
	for key, value := range c.records {
		if !now.Before(value.until) {
			delete(c.records, key)
			c.bytes -= value.size
		}
	}
}
func (c *cache) apply(packet []byte, port, hop, index, wantIndex int, now time.Time) error {
	if port != 5353 || hop != 255 || index != wantIndex || len(packet) > 9000 {
		return fmt.Errorf("invalid mDNS provenance or size")
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(packet); err != nil {
		return err
	}
	if !msg.Response || msg.Id != 0 || msg.Opcode != dns.OpcodeQuery || msg.Rcode != dns.RcodeSuccess || msg.Truncated {
		return fmt.Errorf("not a complete mDNS response")
	}
	rrs := append(append(append([]dns.RR{}, msg.Answer...), msg.Ns...), msg.Extra...)
	if len(rrs) > 128 {
		return fmt.Errorf("mDNS response exceeds 128 records")
	}
	c.expire(now)
	accepted := []dns.RR{}
	flush := map[string]bool{}
	for _, rr := range rrs {
		h := rr.Header()
		if h.Class&0x7fff != dns.ClassINET {
			continue
		}
		switch rr.(type) {
		case *dns.PTR, *dns.SRV, *dns.TXT, *dns.A, *dns.AAAA:
		default:
			continue
		}
		if _, valid := dns.IsDomainName(h.Name); !valid {
			continue
		}
		accepted = append(accepted, rr)
		if h.Class&0x8000 != 0 && h.Ttl > 0 {
			flush[strings.ToLower(h.Name)+"/"+strconv.Itoa(int(h.Rrtype))] = true
		}
	}
	for key, value := range c.records {
		h := value.rr.Header()
		if flush[strings.ToLower(h.Name)+"/"+strconv.Itoa(int(h.Rrtype))] && now.Sub(value.received) >= time.Second && value.until.After(now.Add(time.Second)) {
			// RFC 6762 section 10.2 protects recent split announcements and
			// gives omitted old members one second to be refreshed.
			value.until = now.Add(time.Second)
			c.records[key] = value
		}
	}
	for _, rr := range accepted {
		key := rrKey(rr)
		if old, ok := c.records[key]; ok {
			c.bytes -= old.size
			delete(c.records, key)
		}
		if rr.Header().Ttl == 0 {
			continue
		}
		size := len(rr.String())
		if len(c.records) >= 1024 || c.bytes+size > 1<<20 {
			c.limited = true
			continue
		}
		c.records[key] = cached{rr: dns.Copy(rr), until: now.Add(time.Duration(min(rr.Header().Ttl, uint32(3600))) * time.Second), received: now, size: size}
		c.bytes += size
		if p, ok := rr.(*dns.PTR); ok && strings.EqualFold(p.Hdr.Name, enumeration) {
			if typ, e := ServiceType(p.Ptr); e == nil {
				if len(c.types) < 64 {
					c.types[typ] = true
				} else {
					c.limited = true
				}
			}
		}
	}
	return nil
}
func (c *cache) questions() []dns.Question {
	questions := map[string]dns.Question{}
	add := func(name string, typ uint16) {
		name = strings.ToLower(dns.Fqdn(name))
		questions[name+"/"+strconv.Itoa(int(typ))] = dns.Question{Name: name, Qtype: typ, Qclass: dns.ClassINET}
	}
	add(enumeration, dns.TypePTR)
	for typ := range c.types {
		add(typ, dns.TypePTR)
	}
	instances := map[string]bool{}
	for _, v := range c.records {
		if p, ok := v.rr.(*dns.PTR); ok && c.types[strings.ToLower(p.Hdr.Name)] && strings.HasSuffix(strings.ToLower(p.Ptr), "."+strings.ToLower(p.Hdr.Name)) {
			name := strings.ToLower(p.Ptr)
			instances[name] = true
			add(p.Ptr, dns.TypeSRV)
			add(p.Ptr, dns.TypeTXT)
		}
	}
	for _, v := range c.records {
		if srv, ok := v.rr.(*dns.SRV); ok && instances[strings.ToLower(srv.Hdr.Name)] && srv.Target != "." {
			add(srv.Target, dns.TypeA)
			add(srv.Target, dns.TypeAAAA)
		}
	}
	keys := make([]string, 0, len(questions))
	for key := range questions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]dns.Question, 0, len(keys))
	for _, key := range keys {
		out = append(out, questions[key])
	}
	return out
}
func labelText(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			if i+3 < len(value) {
				if n, e := strconv.Atoi(value[i+1 : i+4]); e == nil && n <= 255 {
					out.WriteByte(byte(n))
					i += 3
					continue
				}
			}
			i++
		}
		out.WriteByte(value[i])
	}
	return out.String()
}
func (c *cache) services(iface string, now time.Time) []Service {
	c.expire(now)
	instances := map[string]Service{}
	for _, value := range c.records {
		if ptr, ok := value.rr.(*dns.PTR); ok {
			typ := strings.ToLower(ptr.Hdr.Name)
			name := strings.ToLower(ptr.Ptr)
			if c.types[typ] && strings.HasSuffix(name, "."+typ) {
				prefix := ptr.Ptr[:len(ptr.Ptr)-len(typ)-1]
				instances[name] = Service{Interface: iface, Name: labelText(prefix), Instance: ptr.Ptr, Type: typ, TXT: []string{}, Addresses: []string{}, Endpoints: []string{}}
			}
		}
	}
	records := make([]dns.RR, 0, len(c.records))
	for _, v := range c.records {
		records = append(records, v.rr)
	}
	sort.Slice(records, func(i, j int) bool { return rrKey(records[i]) < rrKey(records[j]) })
	for key, service := range instances {
		size := 0
		for _, rr := range records {
			if !strings.EqualFold(rr.Header().Name, key) {
				continue
			}
			switch rr := rr.(type) {
			case *dns.SRV:
				if rr.Target != "." && service.Host == "" {
					service.Host = rr.Target
					service.Port = rr.Port
				}
			case *dns.TXT:
				for _, txt := range rr.Txt {
					if size+len(txt) > 4096 || len(service.TXT) >= 64 {
						service.TXTTruncated = true
						continue
					}
					service.TXT = append(service.TXT, txt)
					size += len(txt)
				}
			}
		}
		seen := map[string]bool{}
		for _, rr := range records {
			if !strings.EqualFold(rr.Header().Name, service.Host) {
				continue
			}
			var address netip.Addr
			switch rr := rr.(type) {
			case *dns.A:
				address, _ = netip.AddrFromSlice(rr.A)
				address = address.Unmap()
			case *dns.AAAA:
				address, _ = netip.AddrFromSlice(rr.AAAA)
			}
			if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
				continue
			}
			if address.Is6() && address.IsLinkLocalUnicast() {
				address = address.WithZone(iface)
			}
			text := address.String()
			if !seen[text] && len(service.Addresses) < 32 {
				seen[text] = true
				service.Addresses = append(service.Addresses, text)
				service.Endpoints = append(service.Endpoints, net.JoinHostPort(text, strconv.Itoa(int(service.Port))))
			}
		}
		sort.Strings(service.Addresses)
		sort.Strings(service.Endpoints)
		service.Complete = service.Host != "" && service.Port != 0 && len(service.Addresses) > 0
		instances[key] = service
	}
	keys := make([]string, 0, len(instances))
	for key := range instances {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := []Service{}
	for _, key := range keys {
		if len(out) >= 256 {
			c.limited = true
			break
		}
		out = append(out, instances[key])
	}
	return out
}
