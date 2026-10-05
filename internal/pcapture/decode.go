package pcapture

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

type Packet struct {
	Time            time.Time `json:"time"`
	Protocol        string    `json:"protocol"`
	Source          string    `json:"source,omitempty"`
	Destination     string    `json:"destination,omitempty"`
	SourcePort      uint16    `json:"source_port,omitempty"`
	DestinationPort uint16    `json:"destination_port,omitempty"`
	SourceMAC       string    `json:"source_mac,omitempty"`
	DestinationMAC  string    `json:"destination_mac,omitempty"`
	Captured        int       `json:"captured_bytes"`
	Original        uint32    `json:"original_bytes"`
	Truncated       bool      `json:"truncated"`
	Fragment        bool      `json:"fragment"`
	Detail          string    `json:"detail,omitempty"`
	Error           string    `json:"decode_error,omitempty"`
}

func Decode(link uint32, r Record) Packet {
	p := Packet{Time: r.At, Captured: len(r.Data), Original: r.Original, Truncated: uint32(len(r.Data)) < r.Original, Protocol: "unknown"}
	b := r.Data
	ether := uint16(0)
	fail := func(s string) Packet { p.Error = s; return p }
	switch link {
	case 1:
		if len(b) < 14 {
			return fail("short Ethernet header")
		}
		p.DestinationMAC = net.HardwareAddr(b[:6]).String()
		p.SourceMAC = net.HardwareAddr(b[6:12]).String()
		ether = binary.BigEndian.Uint16(b[12:14])
		b = b[14:]
		for n := 0; (ether == 0x8100 || ether == 0x88a8) && n < 2; n++ {
			if len(b) < 4 {
				return fail("short VLAN header")
			}
			ether = binary.BigEndian.Uint16(b[2:4])
			b = b[4:]
		}
	case 113:
		if len(b) < 16 {
			return fail("short Linux cooked header")
		}
		ether = binary.BigEndian.Uint16(b[14:16])
		if binary.BigEndian.Uint16(b[4:6]) == 6 {
			p.SourceMAC = net.HardwareAddr(b[6:12]).String()
		}
		b = b[16:]
	case 276:
		if len(b) < 20 {
			return fail("short Linux cooked v2 header")
		}
		ether = binary.BigEndian.Uint16(b[:2])
		if b[11] == 6 {
			p.SourceMAC = net.HardwareAddr(b[12:18]).String()
		}
		b = b[20:]
	case 0, 108:
		if len(b) < 4 {
			return fail("short loopback header")
		}
		b = b[4:]
	case 12, 101:
	default:
		return fail("unsupported link type")
	}
	if ether == 0 && len(b) > 0 {
		switch b[0] >> 4 {
		case 4:
			ether = 0x0800
		case 6:
			ether = 0x86dd
		}
	}
	var protocol byte
	switch ether {
	case 0x0806:
		p.Protocol = "arp"
		if len(b) < 28 || binary.BigEndian.Uint16(b[:2]) != 1 || binary.BigEndian.Uint16(b[2:4]) != 0x0800 || b[4] != 6 || b[5] != 4 {
			return fail("unsupported or short ARP packet")
		}
		p.SourceMAC = net.HardwareAddr(b[8:14]).String()
		p.Source = net.IP(b[14:18]).String()
		p.Destination = net.IP(b[24:28]).String()
		op := binary.BigEndian.Uint16(b[6:8])
		p.Detail = fmt.Sprintf("operation %d", op)
		if op == 1 {
			p.Detail = "who has " + p.Destination + "? tell " + p.Source
		}
		if op == 2 {
			p.Detail = p.Source + " is at " + p.SourceMAC
		}
		return p
	case 0x0800:
		if len(b) < 20 || b[0]>>4 != 4 {
			return fail("short or invalid IPv4 header")
		}
		header := int(b[0]&15) * 4
		length := int(binary.BigEndian.Uint16(b[2:4]))
		if header < 20 || len(b) < header || length < header {
			return fail("invalid IPv4 lengths")
		}
		p.Source = net.IP(b[12:16]).String()
		p.Destination = net.IP(b[16:20]).String()
		protocol = b[9]
		flags := binary.BigEndian.Uint16(b[6:8])
		p.Fragment = flags&0x3fff != 0
		if flags&0x1fff != 0 {
			p.Protocol = protocolName(protocol, false)
			p.Detail = "noninitial fragment"
			return p
		}
		if length < len(b) {
			b = b[:length]
		}
		b = b[header:]
	case 0x86dd:
		if len(b) < 40 || b[0]>>4 != 6 {
			return fail("short or invalid IPv6 header")
		}
		p.Source = net.IP(b[8:24]).String()
		p.Destination = net.IP(b[24:40]).String()
		protocol = b[6]
		length := 40 + int(binary.BigEndian.Uint16(b[4:6]))
		if length < len(b) {
			b = b[:length]
		}
		b = b[40:]
		for n := 0; n < 8; n++ {
			if protocol == 44 {
				if len(b) < 8 {
					return fail("short IPv6 fragment header")
				}
				p.Fragment = true
				offset := binary.BigEndian.Uint16(b[2:4])
				protocol = b[0]
				b = b[8:]
				if offset&0xfff8 != 0 {
					p.Protocol = protocolName(protocol, true)
					p.Detail = "noninitial fragment"
					return p
				}
				continue
			}
			if protocol != 0 && protocol != 43 && protocol != 60 && protocol != 51 {
				break
			}
			if len(b) < 2 {
				return fail("short IPv6 extension header")
			}
			size := (int(b[1]) + 1) * 8
			if protocol == 51 {
				size = (int(b[1]) + 2) * 4
			}
			if size > len(b) {
				return fail("truncated IPv6 extension header")
			}
			protocol = b[0]
			b = b[size:]
			if n == 7 {
				return fail("too many IPv6 extension headers")
			}
		}
	default:
		p.Detail = fmt.Sprintf("EtherType 0x%04x", ether)
		return p
	}
	p.Protocol = protocolName(protocol, ether == 0x86dd)
	switch protocol {
	case 6:
		if len(b) < 20 {
			return fail("short TCP header")
		}
		hlen := int(b[12]>>4) * 4
		if hlen < 20 || hlen > len(b) {
			return fail("invalid TCP header length")
		}
		p.SourcePort = binary.BigEndian.Uint16(b[:2])
		p.DestinationPort = binary.BigEndian.Uint16(b[2:4])
		flags := []string{}
		for _, f := range []struct {
			bit  byte
			name string
		}{{2, "SYN"}, {16, "ACK"}, {1, "FIN"}, {4, "RST"}, {8, "PSH"}, {32, "URG"}} {
			if b[13]&f.bit != 0 {
				flags = append(flags, f.name)
			}
		}
		p.Detail = strings.Join(flags, ",")
	case 17:
		if len(b) < 8 {
			return fail("short UDP header")
		}
		if binary.BigEndian.Uint16(b[4:6]) < 8 {
			return fail("invalid UDP length")
		}
		p.SourcePort = binary.BigEndian.Uint16(b[:2])
		p.DestinationPort = binary.BigEndian.Uint16(b[2:4])
	case 1, 58:
		if len(b) < 4 {
			return fail("short ICMP header")
		}
		p.Detail = fmt.Sprintf("type %d code %d", b[0], b[1])
	}
	return p
}
func protocolName(n byte, v6 bool) string {
	switch n {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmp6"
	}
	if v6 {
		return "ipv6"
	}
	return "ipv4"
}

type Filter struct {
	Protocol, Host string
	Port           int
}

func (f Filter) Validate() error {
	switch f.Protocol {
	case "", "tcp", "udp", "icmp", "icmp6", "arp":
	default:
		return fmt.Errorf("protocol must be tcp, udp, icmp, icmp6, or arp")
	}
	if f.Host != "" {
		a, e := netip.ParseAddr(f.Host)
		if e != nil || a.Zone() != "" {
			return fmt.Errorf("host filter requires an unscoped numeric IP")
		}
	}
	if f.Port < 0 || f.Port > 65535 {
		return fmt.Errorf("port filter must be 1–65535")
	}
	return nil
}
func (f Filter) Match(p Packet) bool {
	if f.Protocol != "" && p.Protocol != f.Protocol {
		return false
	}
	if f.Host != "" {
		a, _ := netip.ParseAddr(f.Host)
		src, _ := netip.ParseAddr(p.Source)
		dst, _ := netip.ParseAddr(p.Destination)
		if a.Unmap() != src.Unmap() && a.Unmap() != dst.Unmap() {
			return false
		}
	}
	return f.Port == 0 || (p.Protocol == "tcp" || p.Protocol == "udp") && (int(p.SourcePort) == f.Port || int(p.DestinationPort) == f.Port)
}
