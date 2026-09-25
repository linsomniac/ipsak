package hostnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

type WakeOptions struct {
	MAC         string
	Destination string
	Port        int
	Interface   string
	Count       int
	Interval    time.Duration
}

func (o WakeOptions) Validate() error {
	if _, err := MagicPacket(o.MAC); err != nil {
		return err
	}
	ip, err := netip.ParseAddr(o.Destination)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("destination must be a numeric IPv4 unicast or broadcast address")
	}
	if o.Port < 1 || o.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if o.Count < 1 || o.Count > 100 {
		return fmt.Errorf("count must be between 1 and 100")
	}
	if o.Interval < 10*time.Millisecond || o.Interval > time.Minute {
		return fmt.Errorf("interval must be between 10ms and 1m")
	}
	return nil
}

type WakeReport struct {
	MAC         string `json:"mac"`
	Destination string `json:"destination"`
	Interface   string `json:"interface,omitempty"`
	Source      string `json:"source,omitempty"`
	Requested   int    `json:"requested"`
	Sent        int    `json:"sent"`
	PacketBytes int    `json:"packet_bytes"`
	Note        string `json:"note"`
}

func MagicPacket(mac string) ([]byte, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return nil, fmt.Errorf("MAC must contain exactly six octets")
	}
	if hw[0]&1 != 0 {
		return nil, fmt.Errorf("MAC must be an individual device address, not multicast or broadcast")
	}
	zero := true
	for _, b := range hw {
		if b != 0 {
			zero = false
		}
	}
	if zero {
		return nil, fmt.Errorf("MAC must not be all zeros")
	}
	b := make([]byte, 102)
	for i := range 6 {
		b[i] = 0xff
	}
	for i := range 16 {
		copy(b[6+i*6:], hw)
	}
	return b, nil
}

// Wake sends UDP magic packets. Successful writes do not establish receipt or
// that a sleeping device woke. An interface selects the IPv4 source address.
func Wake(ctx context.Context, o WakeOptions) (WakeReport, error) {
	r := WakeReport{MAC: o.MAC, Requested: o.Count, PacketBytes: 102, Interface: o.Interface, Note: "Sent means accepted by the local UDP socket; delivery and device wake-up are not confirmed."}
	if err := o.Validate(); err != nil {
		return r, err
	}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	hw, _ := net.ParseMAC(o.MAC)
	r.MAC = hw.String()
	dest := netip.AddrPortFrom(netip.MustParseAddr(o.Destination), uint16(o.Port))
	r.Destination = dest.String()
	local := &net.UDPAddr{}
	if o.Interface != "" {
		iface, err := net.InterfaceByName(o.Interface)
		if err != nil {
			return r, err
		}
		if iface.Flags&net.FlagUp == 0 {
			return r, fmt.Errorf("interface %q is down", o.Interface)
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return r, err
		}
		for _, addr := range addrs {
			p, e := netip.ParsePrefix(addr.String())
			if e == nil && p.Addr().Is4() {
				local.IP = net.IP(p.Addr().AsSlice())
				break
			}
		}
		if local.IP == nil {
			return r, fmt.Errorf("interface %q has no IPv4 address", o.Interface)
		}
		r.Source = local.IP.String()
		r.Note += " The interface selects the source address; the operating system still selects the outgoing route."
	}
	conn, err := net.ListenUDP("udp4", local)
	if err != nil {
		return r, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err = enableBroadcast(conn); err != nil {
		return r, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err = conn.SetWriteDeadline(deadline); err != nil {
			return r, err
		}
	}
	packet, _ := MagicPacket(o.MAC)
	for i := 0; i < o.Count; i++ {
		if i > 0 {
			timer := time.NewTimer(o.Interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return r, ctx.Err()
			case <-timer.C:
			}
		}
		if err = ctx.Err(); err != nil {
			return r, err
		}
		n, e := conn.WriteToUDPAddrPort(packet, dest)
		if e != nil {
			if ctx.Err() != nil {
				return r, ctx.Err()
			}
			return r, e
		}
		if n != len(packet) {
			return r, fmt.Errorf("short UDP write: %d of %d bytes", n, len(packet))
		}
		r.Sent++
	}
	return r, nil
}
