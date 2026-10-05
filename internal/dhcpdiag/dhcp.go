// Package dhcpdiag inspects local DHCPv4 evidence and collects discover-only offers.
package dhcpdiag

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

type Lease struct {
	Interface    string   `json:"interface"`
	Source       string   `json:"source"`
	Address      string   `json:"address,omitempty"`
	Server       string   `json:"server,omitempty"`
	SubnetMask   string   `json:"subnet_mask,omitempty"`
	Routers      []string `json:"routers"`
	DNS          []string `json:"dns"`
	Domain       string   `json:"domain,omitempty"`
	LeaseSeconds uint32   `json:"lease_seconds,omitempty"`
	Evidence     string   `json:"evidence"`
}
type Offer struct {
	Lease
	ReplySource string `json:"reply_source"`
}

func ParseOffer(packet []byte, xid uint32, hardware net.HardwareAddr) (Offer, error) {
	o := Offer{Lease: Lease{Routers: []string{}, DNS: []string{}, Evidence: "offer_only"}}
	if len(packet) < 240 || len(packet) > 4096 {
		return o, fmt.Errorf("invalid DHCP packet size")
	}
	if len(hardware) != 6 || packet[0] != 2 || packet[1] != 1 || packet[2] != 6 || binary.BigEndian.Uint32(packet[4:8]) != xid || !bytes.Equal(packet[28:34], hardware) || !bytes.Equal(packet[236:240], []byte{99, 130, 83, 99}) {
		return o, fmt.Errorf("unrelated or invalid DHCP reply")
	}
	options := map[byte][]byte{}
	parse := func(data []byte) error {
		for i := 0; i < len(data); {
			code := data[i]
			i++
			if code == 0 {
				continue
			}
			if code == 255 {
				return nil
			}
			if i >= len(data) {
				return fmt.Errorf("truncated DHCP option length")
			}
			size := int(data[i])
			i++
			if size > len(data)-i {
				return fmt.Errorf("truncated DHCP option")
			}
			if len(options[code])+size > 1024 {
				return fmt.Errorf("DHCP option exceeds limit")
			}
			options[code] = append(options[code], data[i:i+size]...)
			i += size
		}
		return fmt.Errorf("DHCP options missing end marker")
	}
	if err := parse(packet[240:]); err != nil {
		return o, err
	}
	if overload, ok := options[52]; ok {
		if len(overload) != 1 || overload[0] == 0 || overload[0] > 3 {
			return o, fmt.Errorf("invalid DHCP option overload")
		}
		if overload[0]&1 != 0 {
			if err := parse(packet[108:236]); err != nil {
				return o, err
			}
		}
		if overload[0]&2 != 0 {
			if err := parse(packet[44:108]); err != nil {
				return o, err
			}
		}
	}
	if v := options[53]; len(v) != 1 || v[0] != 2 {
		return o, fmt.Errorf("reply is not DHCPOFFER")
	}
	address, ok := netip.AddrFromSlice(packet[16:20])
	if !ok || !usableV4(address) {
		return o, fmt.Errorf("offer has invalid address")
	}
	o.Address = address.String()
	server, ok := netip.AddrFromSlice(options[54])
	if !ok || !usableV4(server) {
		return o, fmt.Errorf("offer has invalid server identifier")
	}
	o.Server = server.String()
	if v, ok := options[1]; ok {
		if len(v) != 4 {
			return o, fmt.Errorf("invalid subnet mask option")
		}
		mask := net.IPMask(v)
		_, bits := mask.Size()
		if bits != 32 {
			return o, fmt.Errorf("noncontiguous subnet mask")
		}
		o.SubnetMask = net.IP(v).String()
	}
	for code, destination := range map[byte]*[]string{3: &o.Routers, 6: &o.DNS} {
		if v, ok := options[code]; ok {
			if len(v) == 0 || len(v)%4 != 0 || len(v) > 64 {
				return o, fmt.Errorf("invalid IPv4 list option %d", code)
			}
			for i := 0; i < len(v); i += 4 {
				a, _ := netip.AddrFromSlice(v[i : i+4])
				if !usableV4(a) {
					return o, fmt.Errorf("invalid IPv4 address in option %d", code)
				}
				*destination = append(*destination, a.String())
			}
		}
	}
	if v, ok := options[51]; ok {
		if len(v) != 4 {
			return o, fmt.Errorf("invalid lease lifetime option")
		}
		o.LeaseSeconds = binary.BigEndian.Uint32(v)
	}
	if v, ok := options[15]; ok {
		if len(v) > 255 {
			return o, fmt.Errorf("domain option too long")
		}
		o.Domain = string(v)
	}
	return o, nil
}
func usableV4(a netip.Addr) bool {
	return a.Is4() && !a.IsUnspecified() && !a.IsMulticast() && a.String() != "255.255.255.255"
}
func DiscoverPacket(xid uint32, hardware net.HardwareAddr) ([]byte, error) {
	if len(hardware) != 6 {
		return nil, fmt.Errorf("DHCP probe requires a six-byte Ethernet address")
	}
	p := make([]byte, 240)
	p[0] = 1
	p[1] = 1
	p[2] = 6
	binary.BigEndian.PutUint32(p[4:8], xid)
	p[10] = 0x80
	copy(p[28:34], hardware)
	copy(p[236:], []byte{99, 130, 83, 99})
	p = append(p, 53, 1, 1, 55, 6, 1, 3, 6, 15, 51, 54, 61, 7, 1)
	p = append(p, hardware...)
	p = append(p, 255)
	for len(p) < 300 {
		p = append(p, 0)
	}
	return p, nil
}

// ParseLease accepts systemd-networkd key files, nmcli DHCP4.OPTION output,
// dhclient lease blocks, and macOS ipconfig getpacket text. It never executes input.
func ParseLease(data []byte, iface, source string) (Lease, error) {
	l := Lease{Interface: iface, Source: source, Routers: []string{}, DNS: []string{}, Evidence: "local_lease_record"}
	if len(data) > 256<<10 {
		return l, fmt.Errorf("lease evidence exceeds 256 KiB")
	}
	text := string(data)
	// dhclient retains historical blocks; use its last complete lease block.
	if strings.Contains(text, "lease {") {
		blocks := regexp.MustCompile(`(?s)lease\s*\{([^{}]*)\}`).FindAllStringSubmatch(text, -1)
		selected := ""
		declared := ""
		for _, block := range blocks {
			match := regexp.MustCompile(`(?m)\binterface\s+"([^"\r\n]+)"\s*;`).FindStringSubmatch(block[1])
			name := ""
			if len(match) > 1 {
				name = match[1]
			}
			if iface != "" && iface != "file" && name != "" && name != iface {
				continue
			}
			selected = block[1]
			declared = name
		}
		if selected == "" {
			return l, fmt.Errorf("no complete dhclient lease block matches interface")
		}
		text = selected
		if (iface == "" || iface == "file") && declared != "" {
			l.Interface = declared
		}
	}
	setAddress := func(value string, destination *string) error {
		value = strings.Trim(value, "\";{} \t")
		a, err := netip.ParseAddr(value)
		if err != nil || !a.Is4() {
			return fmt.Errorf("invalid IPv4 lease value %q", value)
		}
		*destination = a.String()
		return nil
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.ReplaceAll(line, " = ", "=")
		line = strings.ReplaceAll(line, ": ", "=")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			key, value, ok = strings.Cut(line, " ")
		}
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "option" {
			key, value, _ = strings.Cut(value, " ")
		}
		if i := strings.IndexByte(key, ' '); i >= 0 {
			key = key[:i]
		}
		key = strings.TrimSuffix(key, ":")
		switch key {
		case "address", "ip_address", "fixed-address", "yiaddr":
			if err := setAddress(value, &l.Address); err != nil {
				return l, err
			}
		case "server_address", "dhcp_server_identifier", "dhcp-server-identifier", "server_identifier":
			if err := setAddress(value, &l.Server); err != nil {
				return l, err
			}
		case "netmask", "subnet_mask", "subnet-mask":
			if err := setAddress(value, &l.SubnetMask); err != nil {
				return l, err
			}
		case "router", "routers", "dns", "domain_name_server", "domain_name_servers", "domain-name-servers":
			values := strings.Fields(strings.NewReplacer(",", " ", "{", " ", "}", " ", ";", " ").Replace(value))
			if len(values) > 16 {
				return l, fmt.Errorf("too many lease addresses")
			}
			destination := &l.DNS
			if key == "router" || key == "routers" {
				destination = &l.Routers
			}
			for _, v := range values {
				var a string
				if err := setAddress(v, &a); err != nil {
					return l, err
				}
				*destination = append(*destination, a)
			}
		case "lifetime", "dhcp_lease_time", "dhcp-lease-time", "lease_time":
			v := strings.Trim(value, ";\"{} ")
			n, err := strconv.ParseUint(v, 0, 32)
			if err != nil {
				n, err = strconv.ParseUint(v, 10, 32)
			}
			if err != nil {
				return l, fmt.Errorf("invalid lease duration")
			}
			l.LeaseSeconds = uint32(n)
		case "domainname", "domain_name", "domain-name":
			l.Domain = strings.Trim(value, ";\"{} ")
		}
	}
	if l.Address == "" || l.Server == "" {
		return l, fmt.Errorf("no complete DHCPv4 address/server lease evidence found")
	}
	for _, text := range append(append([]string{l.Address, l.Server}, l.Routers...), l.DNS...) {
		a, _ := netip.ParseAddr(text)
		if !usableV4(a) {
			return l, fmt.Errorf("lease contains a non-unicast IPv4 address")
		}
	}
	if l.SubnetMask != "" {
		_, bits := net.IPMask(net.ParseIP(l.SubnetMask).To4()).Size()
		if bits != 32 {
			return l, fmt.Errorf("lease contains noncontiguous subnet mask")
		}
	}
	if len(l.Domain) > 255 {
		return l, fmt.Errorf("lease domain exceeds 255 bytes")
	}
	return l, nil
}
