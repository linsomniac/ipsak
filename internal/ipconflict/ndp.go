package ipconflict

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/ipv6"
)

func checksum(source, destination netip.Addr, payload []byte) uint16 {
	sum := uint32(0)
	add := func(b []byte) {
		for len(b) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(b))
			b = b[2:]
		}
		if len(b) > 0 {
			sum += uint32(b[0]) << 8
		}
	}
	add(source.AsSlice())
	add(destination.AsSlice())
	sum += uint32(len(payload)>>16) + uint32(len(payload)&65535) + 58
	add(payload)
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func solicitation(target, source netip.Addr, hardware net.HardwareAddr) ([]byte, netip.Addr) {
	raw := target.As16()
	destination := [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, raw[13], raw[14], raw[15]}
	dst := netip.AddrFrom16(destination)
	p := make([]byte, 32)
	p[0] = 135
	copy(p[8:24], raw[:])
	p[24] = 1
	p[25] = 1
	copy(p[26:], hardware)
	binary.BigEndian.PutUint16(p[2:4], checksum(source, dst, p))
	return p, dst
}
func parseAdvertisement(p []byte, source, destination, target, local netip.Addr, hop, index, wantIndex int) (string, error) {
	if hop != 255 || index != wantIndex || !source.Is6() || source.IsUnspecified() || source.IsMulticast() || source.Is4In6() {
		return "", fmt.Errorf("invalid NDP provenance")
	}
	if destination != local && destination != netip.MustParseAddr("ff02::1") {
		return "", fmt.Errorf("unrelated NDP destination")
	}
	if len(p) < 24 || p[0] != 136 || p[1] != 0 {
		return "", fmt.Errorf("not a valid neighbor advertisement")
	}
	if checksum(source, destination, p) != 0 {
		return "", fmt.Errorf("invalid ICMPv6 checksum")
	}
	address, _ := netip.AddrFromSlice(p[8:24])
	if address != target {
		return "", fmt.Errorf("unrelated advertisement target")
	}
	if p[4]&0x40 != 0 && destination.IsMulticast() {
		return "", fmt.Errorf("solicited advertisement has multicast destination")
	}
	mac := ""
	for rest := p[24:]; len(rest) > 0; {
		if len(rest) < 2 || rest[1] == 0 {
			return "", fmt.Errorf("invalid NDP option length")
		}
		size := int(rest[1]) * 8
		if size > len(rest) {
			return "", fmt.Errorf("truncated NDP option")
		}
		if rest[0] == 2 {
			if size != 8 || mac != "" {
				return "", fmt.Errorf("invalid target link-layer option")
			}
			mac = net.HardwareAddr(rest[2:8]).String()
		}
		rest = rest[size:]
	}
	if mac == "" {
		return "", fmt.Errorf("advertisement lacks link-layer owner")
	}
	return mac, nil
}
func probeND(parent context.Context, o Options, iface net.Interface, target netip.Addr, r *Result, emit func(Result)) error {
	addresses, err := iface.Addrs()
	if err != nil {
		return err
	}
	var source netip.Addr
	for _, a := range addresses {
		p, e := netip.ParsePrefix(a.String())
		if e != nil || !p.Addr().Is6() || p.Addr().Is4In6() {
			continue
		}
		if !source.IsValid() || p.Addr().IsLinkLocalUnicast() {
			source = p.Addr()
		}
		if source.IsLinkLocalUnicast() {
			break
		}
	}
	if !source.IsValid() {
		return fmt.Errorf("selected interface has no IPv6 source address")
	}
	conn, err := net.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return fmt.Errorf("raw ICMPv6 privileges are required for NDP: %w", err)
	}
	defer conn.Close()
	packet := ipv6.NewPacketConn(conn)
	if err = packet.SetControlMessage(ipv6.FlagHopLimit|ipv6.FlagInterface|ipv6.FlagDst, true); err != nil {
		return err
	}
	if err = packet.SetMulticastInterface(&iface); err != nil {
		return err
	}
	if err = packet.SetMulticastHopLimit(255); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, o.Duration)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	payload, destination := solicitation(target, source, iface.HardwareAddr)
	next := time.Now()
	buffer := make([]byte, 4096)
	for ctx.Err() == nil {
		if r.Sent < o.Count && !time.Now().Before(next) {
			_, err = packet.WriteTo(payload, &ipv6.ControlMessage{IfIndex: iface.Index, Src: net.IP(source.AsSlice()), HopLimit: 255}, &net.IPAddr{IP: net.IP(destination.AsSlice()), Zone: iface.Name})
			if err != nil {
				return err
			}
			r.Sent++
			next = time.Now().Add(o.Interval)
		}
		deadline := time.Now().Add(100 * time.Millisecond)
		if r.Sent < o.Count && next.Before(deadline) {
			deadline = next
		}
		_ = conn.SetReadDeadline(deadline)
		n, cm, from, e := packet.ReadFrom(buffer)
		if e != nil {
			if ctx.Err() != nil {
				break
			}
			if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return e
		}
		peer, ok := from.(*net.IPAddr)
		if !ok || cm == nil {
			r.Ignored++
			continue
		}
		src, _ := netip.AddrFromSlice(peer.IP)
		dst, _ := netip.AddrFromSlice(cm.Dst)
		mac, e := parseAdvertisement(buffer[:n], src, dst, target, source, cm.HopLimit, cm.IfIndex, iface.Index)
		if e != nil {
			r.Ignored++
			continue
		}
		if e = addOwner(r, mac, src.String(), iface.HardwareAddr.String()); e != nil {
			return e
		}
		classify(r)
		if emit != nil {
			snapshot := *r
			snapshot.Owners = append([]Owner(nil), r.Owners...)
			emit(snapshot)
		}
	}
	return parent.Err()
}
