package mtu

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func fixture(t *testing.T, v6 bool) (*ICMP, []byte, *net.IPAddr, int) {
	t.Helper()
	p := &ICMP{ip: netip.MustParseAddr("192.0.2.1"), id: 321, seq: 123, token: [16]byte{1, 2, 3, 4, 5}}
	size, header, typ := 1500, 20, icmp.Type(ipv4.ICMPTypeEchoReply)
	if v6 {
		p.ip = netip.MustParseAddr("2001:db8::1")
		header, typ = 40, ipv6.ICMPTypeEchoReply
	}
	data := make([]byte, size-header-8)
	copy(data, p.token[:])
	m := icmp.Message{Type: typ, Body: &icmp.Echo{ID: int(p.id), Seq: int(p.seq), Data: data}}
	b, err := m.Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	return p, b, &net.IPAddr{IP: net.IP(p.ip.AsSlice())}, size
}

func TestEchoMatching(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		p, b, source, size := fixture(t, v6)
		if r, ok := p.parse(b, source, size); !ok || r.Status != "reply" {
			t.Fatal(r, ok)
		}
		if _, ok := p.parse(b, &net.IPAddr{IP: net.ParseIP("192.0.2.2")}, size); ok {
			t.Fatal("accepted wrong source")
		}
		for _, offset := range []int{1, 4, 6, 8} {
			copyPacket := append([]byte(nil), b...)
			copyPacket[offset] ^= 1
			if _, ok := p.parse(copyPacket, source, size); ok {
				t.Fatalf("accepted corrupt field %d", offset)
			}
		}
		if _, ok := p.parse(b[:len(b)-1], source, size); ok {
			t.Fatal("accepted truncated reply")
		}
	}
}

func TestTooBigMatchesQuotedProbe(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		p, echo, source, size := fixture(t, v6)
		header := 20
		if v6 {
			header = 40
		}
		quote := make([]byte, header+24)
		copy(quote[header:], echo[:24])
		if v6 {
			quote[0], quote[6], quote[header] = 0x60, 58, 128
			binary.BigEndian.PutUint16(quote[4:6], uint16(size-40))
			copy(quote[24:40], p.ip.AsSlice())
		} else {
			quote[0], quote[9], quote[header] = 0x45, 1, 8
			binary.BigEndian.PutUint16(quote[2:4], uint16(size))
			copy(quote[16:20], p.ip.AsSlice())
		}
		packet := make([]byte, 8+len(quote))
		if v6 {
			packet[0] = 2
			binary.BigEndian.PutUint32(packet[4:8], 1400)
		} else {
			packet[0], packet[1] = 3, 4
			binary.BigEndian.PutUint16(packet[6:8], 1400)
		}
		copy(packet[8:], quote)
		if r, ok := p.parse(packet, source, size); !ok || r.Status != "too_big" || r.ReportedMTU != 1400 {
			t.Fatalf("v6=%v %+v %v", v6, r, ok)
		}
		// Minimum IPv4 quote omits the token, but still identifies the probe.
		if !v6 {
			if _, ok := p.parse(packet[:8+header+8], source, size); !ok {
				t.Fatal("rejected minimum quote")
			}
		}
		for _, offset := range []int{8, 8 + header + 4, 8 + header + 6, 8 + header + 8} {
			bad := append([]byte(nil), packet...)
			if offset == 8 {
				bad[offset] ^= 0x10 // Corrupt version, not the valid IPv6 traffic class.
			} else {
				bad[offset] ^= 1
			}
			if _, ok := p.parse(bad, source, size); ok {
				t.Fatalf("accepted bad quoted field %d", offset)
			}
		}
	}
}
