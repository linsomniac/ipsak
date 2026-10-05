package pathwatch

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func fixtureWire(v6 bool) wire {
	ip := netip.MustParseAddr("192.0.2.10")
	if v6 {
		ip = netip.MustParseAddr("2001:db8::10")
	}
	w := wire{ip: ip, id: 12345, count: 4}
	copy(w.token[:], "abcdefghijklmnop")
	return w
}
func quote(w wire, full bool) []byte {
	h, typ := 20, byte(8)
	if w.ip.Is6() {
		h, typ = 40, 128
	}
	n := h + 8
	if full {
		n += 16
	}
	b := make([]byte, n)
	if w.ip.Is6() {
		b[0] = 0x60
		b[6] = 58
		binary.BigEndian.PutUint16(b[4:], 24)
		copy(b[24:40], w.ip.AsSlice())
	} else {
		b[0] = 0x45
		b[9] = 1
		binary.BigEndian.PutUint16(b[2:], 44)
		copy(b[16:20], w.ip.AsSlice())
	}
	b[h] = typ
	binary.BigEndian.PutUint16(b[h+4:], w.id)
	binary.BigEndian.PutUint16(b[h+6:], 2)
	if full {
		copy(b[h+8:], w.token[:])
	}
	return b
}
func TestQuoteCorrelation(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		w := fixtureWire(v6)
		for _, full := range []bool{false, true} {
			b := quote(w, full)
			if seq, ok := w.quoted(b); !ok || seq != 2 {
				t.Fatalf("valid quote rejected v6=%v full=%v", v6, full)
			}
		}
		for _, kind := range []string{"id", "destination", "protocol", "type", "token", "fragment"} {
			b := quote(w, true)
			h := 20
			if v6 {
				h = 40
			}
			switch kind {
			case "id":
				b[h+4] ^= 1
			case "destination":
				b[h-1] ^= 1
			case "protocol":
				if v6 {
					b[6] = 17
				} else {
					b[9] = 17
				}
			case "type":
				b[h] ^= 1
			case "token":
				b[h+8] ^= 1
			case "fragment":
				if v6 {
					b[6] = 44
				} else {
					b[6] = 0x20
				}
			}
			if _, ok := w.quoted(b); ok {
				t.Errorf("accepted %s v6=%v", kind, v6)
			}
		}
	}
}
func TestEchoAndTimeExceededParsing(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		w := fixtureWire(v6)
		typ := icmp.Type(ipv4.ICMPTypeEchoReply)
		ttltyp := icmp.Type(ipv4.ICMPTypeTimeExceeded)
		if v6 {
			typ, ttltyp = ipv6.ICMPTypeEchoReply, ipv6.ICMPTypeTimeExceeded
		}
		src := &net.IPAddr{IP: net.IP(w.ip.AsSlice())}
		m := icmp.Message{Type: typ, Body: &icmp.Echo{ID: int(w.id), Seq: 4, Data: w.token[:]}}
		b, _ := m.Marshal(nil)
		i, status, _, ok := w.parse(b, src)
		if !ok || i != 3 || status != "echo" {
			t.Fatal("valid echo rejected")
		}
		if _, _, _, ok = w.parse(b, &net.IPAddr{IP: net.ParseIP("192.0.2.99")}); ok {
			t.Fatal("wrong-source echo accepted")
		}
		m.Code = 1
		b, _ = m.Marshal(nil)
		if _, _, _, ok = w.parse(b, src); ok {
			t.Fatal("wrong-code echo accepted")
		}
		m = icmp.Message{Type: ttltyp, Body: &icmp.TimeExceeded{Data: quote(w, false)}}
		b, _ = m.Marshal(nil)
		if i, s, _, ok := w.parse(b, src); !ok || i != 1 || s != "hop_reply" {
			t.Fatal("minimum quote rejected")
		}
		q := quote(w, false)
		h := 20
		if v6 {
			h = 40
		}
		binary.BigEndian.PutUint16(q[h+6:], 99)
		m.Body = &icmp.TimeExceeded{Data: q}
		b, _ = m.Marshal(nil)
		if _, _, _, ok = w.parse(b, src); ok {
			t.Fatal("unknown probe accepted")
		}
	}
}
func TestGrowingPathAndIntermediateSilence(t *testing.T) {
	o := Options{Hops: 3, Count: 2, Interval: 100 * time.Millisecond, Timeout: time.Second}
	round := 0
	var snaps []Result
	m := func(context.Context, netip.Addr, int, time.Duration) ([]Probe, error) {
		round++
		p := []Probe{{TTL: 1, Sent: true, Status: "timeout"}, {TTL: 2, Sent: true, Status: "hop_reply", Source: "192.0.2.2", RTTMS: 1}, {TTL: 3, Sent: true, Status: "echo", Source: "192.0.2.10", RTTMS: 2}, {TTL: 255, Sent: true, Status: "echo", Source: "192.0.2.10", RTTMS: 2}}
		if round == 1 {
			p[0] = Probe{TTL: 1, Sent: true, Status: "echo", Source: "192.0.2.10", RTTMS: 1}
		}
		return p, nil
	}
	r, err := Run(context.Background(), fixtureWire(false).ip, o, m, func(r Result) { snaps = append(snaps, r) })
	if err != nil || r.ReachedTTL != 3 || snaps[0].ReachedTTL != 1 || snaps[0].Hops[0].Sent != 1 || r.Destination.Echoes != 2 {
		t.Fatalf("%+v %v", r, err)
	}
}
func TestDestinationFailureAndPending(t *testing.T) {
	o := Options{Hops: 1, Count: 1, Interval: time.Second, Timeout: time.Second}
	m := func(context.Context, netip.Addr, int, time.Duration) ([]Probe, error) {
		return []Probe{{TTL: 1, Sent: true, Status: "hop_reply", Source: "192.0.2.1"}, {TTL: 255, Sent: true, Status: "timeout"}}, nil
	}
	r, err := Run(context.Background(), fixtureWire(false).ip, o, m, nil)
	if err == nil || r.Destination.Timeouts != 1 {
		t.Fatal("destination loss not reported")
	}
	o.Duration = 20 * time.Millisecond
	m = func(ctx context.Context, _ netip.Addr, _ int, _ time.Duration) ([]Probe, error) {
		<-ctx.Done()
		return []Probe{{TTL: 1, Sent: true, Status: "pending"}, {TTL: 255, Sent: true, Status: "pending"}}, ctx.Err()
	}
	r, err = Run(context.Background(), fixtureWire(false).ip, o, m, nil)
	if err == nil || r.Destination.Pending != 1 || r.Destination.Timeouts != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	o.Hops = -1
	if _, e := Run(context.Background(), fixtureWire(false).ip, o, m, nil); e == nil {
		t.Fatal("negative hops accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e := Measure(ctx, fixtureWire(false).ip, 2, time.Second)
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
