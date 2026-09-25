package mtu

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type ICMP struct {
	conn  *net.IPConn
	ip    netip.Addr
	id    uint16
	seq   uint16
	token [16]byte
}

func Open(ip netip.Addr) (*ICMP, error) {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsMulticast() || ip.IsUnspecified() || ip == netip.MustParseAddr("255.255.255.255") {
		return nil, fmt.Errorf("MTU probes require a unicast address")
	}
	p := &ICMP{ip: ip}
	var seed [18]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	p.id = binary.BigEndian.Uint16(seed[:2])
	copy(p.token[:], seed[2:])
	network, bind := "ip4:icmp", "0.0.0.0"
	if ip.Is6() {
		network, bind = "ip6:ipv6-icmp", "::"
	}
	conn, err := net.ListenIP(network, &net.IPAddr{IP: net.ParseIP(bind)})
	if err != nil {
		return nil, fmt.Errorf("open raw ICMP for MTU discovery: %w; Linux requires CAP_NET_RAW (sudo setcap cap_net_raw+ep ./bin/ipsak), macOS requires elevated privileges", err)
	}
	if err = dontFragment(conn, ip.Is6()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("disable packet fragmentation: %w", err)
	}
	p.conn = conn
	return p, nil
}

func (p *ICMP) Close() error { return p.conn.Close() }

func (p *ICMP) Probe(ctx context.Context, size int) (Probe, error) {
	r := Probe{Size: size}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	header, typ := 20, icmp.Type(ipv4.ICMPTypeEcho)
	if p.ip.Is6() {
		header, typ = 40, ipv6.ICMPTypeEchoRequest
	}
	if size < header+8+len(p.token) || size > 65535 {
		return r, fmt.Errorf("invalid probe size")
	}
	p.seq++
	data := make([]byte, size-header-8)
	copy(data, p.token[:])
	message := icmp.Message{Type: typ, Body: &icmp.Echo{ID: int(p.id), Seq: int(p.seq), Data: data}}
	packet, err := message.Marshal(nil)
	if err != nil {
		return r, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return r, fmt.Errorf("probe context must have a deadline")
	}
	if err := p.conn.SetDeadline(deadline); err != nil {
		return r, err
	}
	// Interrupt both reads and writes without closing the reusable socket on a
	// per-probe timeout. Join the callback before resetting deadlines next time.
	woke := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { p.conn.SetDeadline(time.Now()); close(woke) })
	defer func() {
		if !stop() {
			<-woke
		}
	}()
	start := time.Now()
	_, err = p.conn.WriteToIP(packet, &net.IPAddr{IP: net.IP(p.ip.AsSlice()), Zone: p.ip.Zone()})
	if err != nil {
		if errors.Is(err, syscall.EMSGSIZE) {
			r.Status, r.Source = "too_big", "local socket"
			return r, nil
		}
		return p.readError(ctx, r, err)
	}
	buf := make([]byte, 65536)
	for {
		n, source, err := p.conn.ReadFromIP(buf)
		if err != nil {
			return p.readError(ctx, r, err)
		}
		if v, ok := p.parse(buf[:n], source, size); ok {
			v.RTTMS = float64(time.Since(start)) / float64(time.Millisecond)
			return v, nil
		}
	}
}

func (p *ICMP) readError(ctx context.Context, r Probe, err error) (Probe, error) {
	if ctx.Err() == context.Canceled {
		return r, ctx.Err()
	}
	var ne net.Error
	if ctx.Err() == context.DeadlineExceeded || errors.As(err, &ne) && ne.Timeout() {
		r.Status = "timeout"
		return r, nil
	}
	return r, err
}

func (p *ICMP) parse(packet []byte, source *net.IPAddr, size int) (Probe, bool) {
	r := Probe{Size: size}
	if len(packet) < 8 || source == nil {
		return r, false
	}
	addr, valid := netip.AddrFromSlice(source.IP)
	if !valid {
		return r, false
	}
	protocol, replyType := 1, icmp.Type(ipv4.ICMPTypeEchoReply)
	if p.ip.Is6() {
		protocol, replyType = 58, ipv6.ICMPTypeEchoReply
	}
	m, err := icmp.ParseMessage(protocol, packet)
	if err != nil {
		return r, false
	}
	if m.Type == replyType && m.Code == 0 {
		e, ok := m.Body.(*icmp.Echo)
		header := 20
		if p.ip.Is6() {
			header = 40
		}
		if !ok || addr.Unmap() != p.ip.WithZone("") || e.ID != int(p.id) || e.Seq != int(p.seq) || len(e.Data) != size-header-8 || len(e.Data) < len(p.token) || !bytes.Equal(e.Data[:len(p.token)], p.token[:]) {
			return r, false
		}
		r.Status, r.Source = "reply", addr.String()
		return r, true
	}
	var quote []byte
	if !p.ip.Is6() && m.Type == ipv4.ICMPTypeDestinationUnreachable && m.Code == 4 {
		r.ReportedMTU = int(binary.BigEndian.Uint16(packet[6:8]))
		quote = packet[8:]
	} else if p.ip.Is6() && m.Type == ipv6.ICMPTypePacketTooBig && m.Code == 0 {
		body, ok := m.Body.(*icmp.PacketTooBig)
		if !ok {
			return r, false
		}
		r.ReportedMTU, quote = body.MTU, body.Data
	} else {
		return r, false
	}
	if !p.matchesQuote(quote, size) || r.ReportedMTU >= size {
		return r, false
	}
	r.Status, r.Source = "too_big", addr.String()
	return r, true
}

func (p *ICMP) matchesQuote(b []byte, size int) bool {
	header, echoType := 20, byte(8)
	if p.ip.Is6() {
		header, echoType = 40, 128
		if len(b) < header+8 || b[0]>>4 != 6 || b[6] != 58 || !bytes.Equal(b[24:40], p.ip.AsSlice()) || int(binary.BigEndian.Uint16(b[4:6]))+40 != size {
			return false
		}
	} else {
		if len(b) < 28 || b[0]>>4 != 4 || b[9] != 1 || !bytes.Equal(b[16:20], p.ip.AsSlice()) || binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			return false
		}
		header = int(b[0]&15) * 4
		if header < 20 || len(b) < header+8 || int(binary.BigEndian.Uint16(b[2:4])) != size {
			return false
		}
	}
	echo := b[header:]
	if echo[0] != echoType || echo[1] != 0 || binary.BigEndian.Uint16(echo[4:6]) != p.id || binary.BigEndian.Uint16(echo[6:8]) != p.seq {
		return false
	}
	// RFC 792 only requires the first eight bytes of the original payload.
	// When a router quotes our token too, require all available token bytes.
	n := min(len(echo)-8, len(p.token))
	return bytes.Equal(echo[8:8+n], p.token[:n])
}
