package ping

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Reply struct {
	ID      uint64
	At      time.Time
	Address netip.Addr
}
type Transport interface {
	Send(uint64) error
	Receive() (Reply, error)
	Close() error
}

type ICMP struct {
	conn           *icmp.PacketConn
	destination    net.Addr
	ip             netip.Addr
	token          [16]byte
	protocol       int
	raw            bool
	request, reply icmp.Type
}

func Open(ip netip.Addr) (*ICMP, error) {
	p := &ICMP{ip: ip.Unmap(), protocol: 1, request: ipv4.ICMPTypeEcho, reply: ipv4.ICMPTypeEchoReply}
	if _, err := rand.Read(p.token[:]); err != nil {
		return nil, err
	}
	network, raw, address := "udp4", "ip4:icmp", "0.0.0.0"
	if p.ip.Is6() {
		network, raw, address = "udp6", "ip6:ipv6-icmp", "::"
		p.protocol = 58
		p.request = ipv6.ICMPTypeEchoRequest
		p.reply = ipv6.ICMPTypeEchoReply
	}
	conn, datagramErr := icmp.ListenPacket(network, address)
	if datagramErr != nil {
		var err error
		conn, err = icmp.ListenPacket(raw, address)
		if err != nil {
			return nil, fmt.Errorf("cannot open ICMP socket (datagram: %v; raw: %v); on Linux allow your group in net.ipv4.ping_group_range or grant the ipsak binary CAP_NET_RAW; raw ICMP may require elevated privileges on other systems", datagramErr, err)
		}
		p.raw = true
	}
	p.conn = conn
	if p.raw {
		p.destination = &net.IPAddr{IP: net.IP(p.ip.AsSlice()), Zone: p.ip.Zone()}
	} else {
		p.destination = &net.UDPAddr{IP: net.IP(p.ip.AsSlice()), Zone: p.ip.Zone()}
	}
	return p, nil
}

func (p *ICMP) Send(id uint64) error {
	return p.sendTo(id, p.destination)
}

// OpenSweep shares one socket across all destinations of an address family.
// The scheduler validates the source of each reply against its pending probe.
func OpenSweep(ip netip.Addr) (*ICMP, error) {
	p, err := Open(ip)
	if err == nil {
		p.ip = netip.Addr{}
	}
	return p, err
}

func (p *ICMP) SendTo(id uint64, ip netip.Addr) error {
	if p.raw {
		return p.sendTo(id, &net.IPAddr{IP: net.IP(ip.AsSlice()), Zone: ip.Zone()})
	}
	return p.sendTo(id, &net.UDPAddr{IP: net.IP(ip.AsSlice()), Zone: ip.Zone()})
}

func (p *ICMP) sendTo(id uint64, destination net.Addr) error {
	data := make([]byte, 56)
	copy(data, p.token[:])
	binary.BigEndian.PutUint64(data[16:24], id)
	msg := icmp.Message{Type: p.request, Code: 0, Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: int(id & 0xffff), Data: data}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	if err = p.conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	_, err = p.conn.WriteTo(b, destination)
	return err
}

func (p *ICMP) parse(b []byte, source net.Addr, at time.Time) (Reply, bool) {
	var ip net.IP
	switch a := source.(type) {
	case *net.IPAddr:
		ip = a.IP
	case *net.UDPAddr:
		ip = a.IP
	default:
		return Reply{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || (p.ip.IsValid() && addr.Unmap() != p.ip.WithZone("")) {
		return Reply{}, false
	}
	m, err := icmp.ParseMessage(p.protocol, b)
	if err != nil || m.Type != p.reply || m.Code != 0 {
		return Reply{}, false
	}
	e, ok := m.Body.(*icmp.Echo)
	if !ok || len(e.Data) < 24 || !bytes.Equal(e.Data[:16], p.token[:]) {
		return Reply{}, false
	}
	id := binary.BigEndian.Uint64(e.Data[16:24])
	if id == 0 || e.Seq != int(id&0xffff) {
		return Reply{}, false
	}
	if p.raw && e.ID != os.Getpid()&0xffff {
		return Reply{}, false
	}
	return Reply{ID: id, At: at, Address: addr.Unmap()}, true
}

func (p *ICMP) Receive() (Reply, error) {
	buf := make([]byte, 1500)
	for {
		n, source, err := p.conn.ReadFrom(buf)
		at := time.Now()
		if err != nil {
			return Reply{}, err
		}
		if r, ok := p.parse(buf[:n], source, at); ok {
			return r, nil
		}
	}
}
func (p *ICMP) Close() error  { return p.conn.Close() }
func IsClosed(err error) bool { return errors.Is(err, net.ErrClosed) }
