package dhcpdiag

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/linsomniac/ipsak/internal/localnet"
	"golang.org/x/net/ipv4"
)

type ProbeResult struct {
	Interface string  `json:"interface"`
	Sent      int     `json:"discovers_sent"`
	Ignored   int     `json:"ignored_datagrams"`
	Offers    []Offer `json:"offers"`
	Note      string  `json:"note"`
}
type probeIO struct {
	write    func([]byte) error
	read     func([]byte) (int, int, *net.UDPAddr, error)
	deadline func(time.Time) error
	close    func() error
}

func (r ProbeResult) CompactLines() []string {
	lines := []string{fmt.Sprintf("%s · %d DISCOVER messages · %d offers", r.Interface, r.Sent, len(r.Offers)), r.Note}
	for _, o := range r.Offers {
		lines = append(lines, fmt.Sprintf("%s offers %s · lease %ds", o.Server, o.Address, o.LeaseSeconds))
	}
	return lines
}
func Probe(parent context.Context, name string, duration time.Duration, emit func(ProbeResult)) (r ProbeResult, err error) {
	r = ProbeResult{Interface: name, Offers: []Offer{}, Note: "Offers only: no DHCPREQUEST is sent, no lease is accepted, and interface configuration is unchanged. Silence is inconclusive. DISCOVER uses this interface's available UDP source address."}
	if duration < time.Second || duration > 30*time.Second {
		return r, fmt.Errorf("probe duration must be 1s–30s")
	}
	if err := parent.Err(); err != nil {
		return r, err
	}
	ifaces, err := localnet.Interfaces([]string{name}, false)
	if err != nil {
		return r, err
	}
	iface := ifaces[0]
	if len(iface.HardwareAddr) != 6 {
		return r, fmt.Errorf("DHCP probe requires an Ethernet interface")
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 68})
	if err != nil {
		return r, fmt.Errorf("exclusive DHCP client port 68 is unavailable (privileges or an existing DHCP client): %w", err)
	}
	defer conn.Close()
	if err = bindBroadcast(conn, iface); err != nil {
		return r, fmt.Errorf("cannot isolate DHCP probe to interface: %w", err)
	}
	packetConn := ipv4.NewPacketConn(conn)
	if err = packetConn.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		return r, err
	}
	var random [4]byte
	if _, err = rand.Read(random[:]); err != nil {
		return r, err
	}
	xid := binary.BigEndian.Uint32(random[:])
	socket := probeIO{close: conn.Close, deadline: conn.SetReadDeadline, write: func(p []byte) error {
		_, e := packetConn.WriteTo(p, &ipv4.ControlMessage{IfIndex: iface.Index}, &net.UDPAddr{IP: net.IPv4bcast, Port: 67})
		return e
	}, read: func(p []byte) (int, int, *net.UDPAddr, error) {
		n, cm, source, e := packetConn.ReadFrom(p)
		peer, _ := source.(*net.UDPAddr)
		index := 0
		if cm != nil {
			index = cm.IfIndex
		}
		return n, index, peer, e
	}}
	return collectOffers(parent, iface, duration, xid, socket, r, emit)
}
func collectOffers(parent context.Context, iface net.Interface, duration time.Duration, xid uint32, socket probeIO, r ProbeResult, emit func(ProbeResult)) (ProbeResult, error) {
	ctx, cancel := context.WithTimeout(parent, duration)
	defer cancel()
	defer socket.close()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { socket.close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	packet, err := DiscoverPacket(xid, iface.HardwareAddr)
	if err != nil {
		return r, err
	}
	next := time.Now()
	buffer := make([]byte, 4097)
	seen := map[string]bool{}
	for ctx.Err() == nil {
		if r.Sent < 3 && !time.Now().Before(next) {
			if err = socket.write(packet); err != nil {
				return r, err
			}
			r.Sent++
			next = time.Now().Add(time.Second)
		}
		deadline := time.Now().Add(200 * time.Millisecond)
		if r.Sent < 3 && next.Before(deadline) {
			deadline = next
		}
		if err = socket.deadline(deadline); err != nil {
			return r, err
		}
		n, index, peer, readErr := socket.read(buffer)
		if readErr != nil {
			if ctx.Err() != nil {
				break
			}
			if e, ok := readErr.(net.Error); ok && e.Timeout() {
				continue
			}
			return r, readErr
		}
		if peer == nil || peer.Port != 67 || peer.IP.To4() == nil || peer.IP.IsUnspecified() || peer.IP.IsMulticast() || index != iface.Index {
			r.Ignored++
			continue
		}
		offer, parseErr := ParseOffer(buffer[:n], xid, iface.HardwareAddr)
		if parseErr != nil {
			r.Ignored++
			continue
		}
		offer.Interface = iface.Name
		offer.Source = "DHCPDISCOVER response"
		offer.ReplySource = peer.IP.String()
		key := offer.Server + "/" + offer.Address
		if seen[key] {
			continue
		}
		if len(r.Offers) >= 64 {
			return r, fmt.Errorf("offer limit reached")
		}
		seen[key] = true
		r.Offers = append(r.Offers, offer)
		if emit != nil {
			snapshot := r
			snapshot.Offers = append([]Offer(nil), r.Offers...)
			emit(snapshot)
		}
	}
	sort.Slice(r.Offers, func(i, j int) bool {
		if r.Offers[i].Server != r.Offers[j].Server {
			return r.Offers[i].Server < r.Offers[j].Server
		}
		return r.Offers[i].Address < r.Offers[j].Address
	})
	if parent.Err() != nil {
		return r, parent.Err()
	}
	if len(r.Offers) == 0 {
		return r, fmt.Errorf("no correlated DHCP offers observed; this does not prove no DHCP server exists")
	}
	return r, nil
}
