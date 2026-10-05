// Package pathwatch samples hop responses alongside an independent destination probe.
package pathwatch

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Probe struct {
	TTL                   int
	Sent                  bool
	Status, Source, Error string
	RTTMS                 float64
}
type OpenError struct{ Err error }

func (e *OpenError) Error() string {
	return "raw ICMP unavailable: " + e.Err.Error() + "; requires CAP_NET_RAW on Linux or elevated privileges on macOS"
}
func (e *OpenError) Unwrap() error { return e.Err }

type wire struct {
	ip    netip.Addr
	id    uint16
	token [16]byte
	count int
}

// Measure sends one outstanding probe at every TTL plus a separate TTL=255
// destination probe. A fresh socket and random session identity isolate rounds.
func Measure(ctx context.Context, ip netip.Addr, hops int, timeout time.Duration) ([]Probe, error) {
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.Unmap() == netip.MustParseAddr("255.255.255.255") || hops < 1 || hops > 64 || timeout <= 0 {
		return nil, fmt.Errorf("invalid pathwatch probe options")
	}
	ip = ip.Unmap()
	w := wire{ip: ip, count: hops + 1}
	var seed [18]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	w.id = binary.BigEndian.Uint16(seed[:2])
	copy(w.token[:], seed[2:])
	network, bind := "ip4:icmp", "0.0.0.0"
	typ := icmp.Type(ipv4.ICMPTypeEcho)
	if ip.Is6() {
		network, bind, typ = "ip6:ipv6-icmp", "::", ipv6.ICMPTypeEchoRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := icmp.ListenPacket(network, bind)
	if err != nil {
		return nil, &OpenError{err}
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	lifecycleDeadline := false
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
		lifecycleDeadline = true
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { conn.Close(); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	out := make([]Probe, hops+1)
	sent := make([]time.Time, hops+1)
	remaining := 0
	for i := range out {
		ttl := i + 1
		if i == hops {
			ttl = 255
		}
		out[i] = Probe{TTL: ttl, Status: "pending"}
		if ctx.Err() != nil {
			continue
		}
		if ip.Is6() {
			err = conn.IPv6PacketConn().SetHopLimit(ttl)
		} else {
			err = conn.IPv4PacketConn().SetTTL(ttl)
		}
		if err != nil {
			out[i].Status, out[i].Error = "send_error", err.Error()
			continue
		}
		m := icmp.Message{Type: typ, Body: &icmp.Echo{ID: int(w.id), Seq: i + 1, Data: w.token[:]}}
		b, e := m.Marshal(nil)
		if e != nil {
			return out, e
		}
		sent[i] = time.Now()
		_, e = conn.WriteTo(b, &net.IPAddr{IP: net.IP(ip.AsSlice()), Zone: ip.Zone()})
		if e != nil {
			if ctx.Err() != nil {
				continue
			}
			out[i].Status, out[i].Error = "send_error", e.Error()
			continue
		}
		out[i].Sent = true
		remaining++
	}
	buf := make([]byte, 4096)
	for remaining > 0 {
		n, from, e := conn.ReadFrom(buf)
		at := time.Now()
		if e != nil {
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				if lifecycleDeadline && !at.Before(deadline) {
					<-ctx.Done()
					return out, ctx.Err()
				}
				for i := range out {
					if out[i].Sent && out[i].Status == "pending" {
						out[i].Status = "timeout"
					}
				}
				return out, nil
			}
			return out, e
		}
		idx, status, source, ok := w.parse(buf[:n], from)
		if !ok || !out[idx].Sent || out[idx].Status != "pending" {
			continue
		}
		out[idx].Status, out[idx].Source, out[idx].RTTMS = status, source, float64(at.Sub(sent[idx]))/float64(time.Millisecond)
		remaining--
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	return out, nil
}
func (w wire) parse(b []byte, source net.Addr) (int, string, string, bool) {
	a, ok := source.(*net.IPAddr)
	if !ok {
		return 0, "", "", false
	}
	ip, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		return 0, "", "", false
	}
	protocol := 1
	reply := icmp.Type(ipv4.ICMPTypeEchoReply)
	if w.ip.Is6() {
		protocol, reply = 58, ipv6.ICMPTypeEchoReply
	}
	m, err := icmp.ParseMessage(protocol, b)
	if err != nil {
		return 0, "", "", false
	}
	var seq uint16
	status := ""
	if m.Type == reply && m.Code == 0 {
		e, ok := m.Body.(*icmp.Echo)
		if !ok || ip.Unmap() != w.ip.WithZone("") || e.ID != int(w.id) || !bytes.Equal(e.Data, w.token[:]) {
			return 0, "", "", false
		}
		seq = uint16(e.Seq)
		status = "echo"
	} else {
		var quote []byte
		switch {
		case !w.ip.Is6() && m.Type == ipv4.ICMPTypeTimeExceeded && m.Code == 0, w.ip.Is6() && m.Type == ipv6.ICMPTypeTimeExceeded && m.Code == 0:
			x, ok := m.Body.(*icmp.TimeExceeded)
			if !ok {
				return 0, "", "", false
			}
			quote = x.Data
			status = "hop_reply"
		case !w.ip.Is6() && m.Type == ipv4.ICMPTypeDestinationUnreachable && m.Code <= 15, w.ip.Is6() && m.Type == ipv6.ICMPTypeDestinationUnreachable && m.Code <= 7:
			x, ok := m.Body.(*icmp.DstUnreach)
			if !ok {
				return 0, "", "", false
			}
			quote = x.Data
			status = "unreachable"
		case w.ip.Is6() && m.Type == ipv6.ICMPTypePacketTooBig && m.Code == 0:
			x, ok := m.Body.(*icmp.PacketTooBig)
			if !ok {
				return 0, "", "", false
			}
			quote = x.Data
			status = "too_big"
		default:
			return 0, "", "", false
		}
		seq, ok = w.quoted(quote)
		if !ok {
			return 0, "", "", false
		}
	}
	if seq == 0 || int(seq) > w.count {
		return 0, "", "", false
	}
	return int(seq) - 1, status, ip.Unmap().String(), true
}
func (w wire) quoted(b []byte) (uint16, bool) {
	h, typ := 20, byte(8)
	if w.ip.Is6() {
		h, typ = 40, 128
		if len(b) < 48 || b[0]>>4 != 6 || b[6] != 58 || !bytes.Equal(b[24:40], w.ip.AsSlice()) || binary.BigEndian.Uint16(b[4:6]) != 24 {
			return 0, false
		}
	} else {
		if len(b) < 28 || b[0]>>4 != 4 || b[9] != 1 || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 || !bytes.Equal(b[16:20], w.ip.AsSlice()) {
			return 0, false
		}
		h = int(b[0]&15) * 4
		if h < 20 || len(b) < h+8 || int(binary.BigEndian.Uint16(b[2:4])) != h+24 {
			return 0, false
		}
	}
	e := b[h:]
	if e[0] != typ || e[1] != 0 || binary.BigEndian.Uint16(e[4:6]) != w.id {
		return 0, false
	}
	n := min(len(e)-8, len(w.token))
	if !bytes.Equal(e[8:8+n], w.token[:n]) {
		return 0, false
	}
	return binary.BigEndian.Uint16(e[6:8]), true
}
