package discovery

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func rr(t *testing.T, text string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(text)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func wire(t *testing.T, records ...dns.RR) []byte {
	t.Helper()
	m := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Answer: records}
	p, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func fixtureRecords(t *testing.T) []dns.RR {
	return []dns.RR{rr(t, `_http._tcp.local. 120 IN PTR Office\032Printer._http._tcp.local.`), rr(t, `Office\032Printer._http._tcp.local. 120 IN SRV 0 0 8080 printer.local.`), rr(t, `Office\032Printer._http._tcp.local. 120 IN TXT "path=/" "model=Fixture"`), rr(t, `printer.local. 120 IN A 192.0.2.10`), rr(t, `printer.local. 120 IN AAAA fe80::10`)}
}

func TestDiscoveryBrowseResolveFriendlyScopedEndpoints(t *testing.T) {
	c := newCache([]string{"_http._tcp.local."})
	now := time.Now()
	records := fixtureRecords(t)
	if err := c.apply(wire(t, records[0]), 5353, 255, 3, 3, now); err != nil {
		t.Fatal(err)
	}
	services := c.services("eth0", now)
	if len(services) != 1 || services[0].Complete || services[0].Name != "Office Printer" {
		t.Fatal(services)
	}
	questions := c.questions()
	hasSRV, hasTXT := false, false
	for _, q := range questions {
		if q.Qtype == dns.TypeSRV {
			hasSRV = true
		}
		if q.Qtype == dns.TypeTXT {
			hasTXT = true
		}
	}
	if !hasSRV || !hasTXT {
		t.Fatal(questions)
	}
	if err := c.apply(wire(t, records[1], records[2]), 5353, 255, 3, 3, now); err != nil {
		t.Fatal(err)
	}
	hasA, hasAAAA := false, false
	for _, q := range c.questions() {
		if q.Name == "printer.local." {
			hasA = hasA || q.Qtype == dns.TypeA
			hasAAAA = hasAAAA || q.Qtype == dns.TypeAAAA
		}
	}
	if !hasA || !hasAAAA {
		t.Fatal(c.questions())
	}
	if err := c.apply(wire(t, records[3], records[4]), 5353, 255, 3, 3, now); err != nil {
		t.Fatal(err)
	}
	services = c.services("eth0", now)
	if !services[0].Complete || len(services[0].Endpoints) != 2 || services[0].Endpoints[1] != "[fe80::10%eth0]:8080" || len(services[0].TXT) != 2 {
		t.Fatal(services)
	}
}
func TestDiscoveryProvenanceMalformedAndBounds(t *testing.T) {
	packet := wire(t, fixtureRecords(t)...)
	for _, test := range []struct{ port, hop, index int }{{53, 255, 3}, {5353, 254, 3}, {5353, 255, 4}} {
		if err := newCache(nil).apply(packet, test.port, test.hop, test.index, 3, time.Now()); err == nil {
			t.Fatal("accepted invalid provenance")
		}
	}
	for _, packet := range [][]byte{{1, 2, 3}, make([]byte, 9001)} {
		if err := newCache(nil).apply(packet, 5353, 255, 3, 3, time.Now()); err == nil {
			t.Fatal("accepted invalid packet")
		}
	}
	m := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Id: 1}, Answer: fixtureRecords(t)}
	p, _ := m.Pack()
	if err := newCache(nil).apply(p, 5353, 255, 3, 3, time.Now()); err == nil {
		t.Fatal("unrelated id accepted")
	}
	for _, bad := range []string{"http", "_x._tcp.example.com", "_a._sctp", "_bad!._udp", "_abcdefghijklmnop._tcp"} {
		if _, err := ServiceType(bad); err == nil {
			t.Fatal("invalid type", bad)
		}
	}
	c := newCache([]string{"_http._tcp.local."})
	now := time.Now()
	for batch := 0; batch < 9; batch++ {
		records := []dns.RR{}
		for i := 0; i < 128; i++ {
			records = append(records, rr(t, fmt.Sprintf("host%d.local. 120 IN A 192.0.2.1", batch*128+i)))
		}
		if err := c.apply(wire(t, records...), 5353, 255, 3, 3, now); err != nil {
			t.Fatal(err)
		}
	}
	if !c.limited || len(c.records) != 1024 {
		t.Fatal(c.limited, len(c.records))
	}
}
func TestDiscoveryFlushGraceSplitAnnouncementsAndGoodbye(t *testing.T) {
	c := newCache(nil)
	now := time.Unix(1700000000, 0)
	a := rr(t, "printer.local. 120 IN A 192.0.2.1")
	a.Header().Class |= 0x8000
	b := rr(t, "printer.local. 120 IN A 192.0.2.2")
	b.Header().Class |= 0x8000
	if err := c.apply(wire(t, a), 5353, 255, 3, 3, now); err != nil {
		t.Fatal(err)
	}
	c.apply(wire(t, b), 5353, 255, 3, 3, now.Add(500*time.Millisecond))
	if len(c.records) != 2 {
		t.Fatal("split recent RRset lost")
	}
	c.expire(now.Add(2 * time.Second))
	if len(c.records) != 2 {
		t.Fatal("recent record was prematurely aged")
	}
	c.apply(wire(t, b), 5353, 255, 3, 3, now.Add(3*time.Second))
	c.expire(now.Add(3500 * time.Millisecond))
	if len(c.records) != 2 {
		t.Fatal("flush grace missing")
	}
	c.expire(now.Add(4 * time.Second))
	if len(c.records) != 1 {
		t.Fatal("old omitted member not expired")
	}
	b.Header().Ttl = 0
	c.apply(wire(t, b), 5353, 255, 3, 3, now.Add(5*time.Second))
	if len(c.records) != 0 {
		t.Fatal("goodbye retained")
	}
}
func TestDiscoveryTXTCapAndEnumeration(t *testing.T) {
	c := newCache(nil)
	now := time.Now()
	enumerated := rr(t, "_services._dns-sd._udp.local. 120 IN PTR _http._tcp.local.")
	c.apply(wire(t, enumerated), 5353, 255, 3, 3, now)
	records := fixtureRecords(t)
	text := &dns.TXT{Hdr: dns.RR_Header{Name: records[2].Header().Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120}}
	for range 30 {
		text.Txt = append(text.Txt, strings.Repeat("x", 200))
	}
	records[2] = text
	if err := c.apply(wire(t, records...), 5353, 255, 3, 3, now); err != nil {
		t.Fatal(err)
	}
	services := c.services("eth0", now)
	if len(services) != 1 || !services[0].TXTTruncated || len(services[0].TXT) != 20 {
		t.Fatal(services)
	}
	c.expire(now.Add(121 * time.Second))
	if len(c.records) != 0 {
		t.Fatal("expired records retained")
	}
}

func TestDiscoveryLiveBrowseResolveAndJoinedCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	iface := net.Interface{Index: 3, Name: "fixture"}
	records := fixtureRecords(t)
	responses := make(chan []byte, 64)
	closed := make(chan struct{})
	var closeOnce sync.Once
	queryTypes := map[uint16]bool{}
	socket := multicastSocket{close: func() error { closeOnce.Do(func() { close(closed) }); return nil }, read: func(buffer []byte) (int, int, int, *net.UDPAddr, error) {
		select {
		case <-closed:
			return 0, 0, 0, nil, io.EOF
		case p := <-responses:
			return copy(buffer, p), 255, 3, &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 5353}, nil
		}
	}, write: func(p []byte) error {
		m := new(dns.Msg)
		if err := m.Unpack(p); err != nil {
			return err
		}
		for _, q := range m.Question {
			queryTypes[q.Qtype] = true
			switch q.Qtype {
			case dns.TypePTR:
				if q.Name == "_http._tcp.local." {
					responses <- wire(t, records[0])
				}
			case dns.TypeSRV:
				responses <- wire(t, records[1])
			case dns.TypeTXT:
				responses <- wire(t, records[2])
			case dns.TypeA:
				responses <- wire(t, records[3])
			case dns.TypeAAAA:
				responses <- wire(t, records[4])
			}
		}
		return nil
	}}
	result := make(chan interfaceResult, 1)
	snapshots := 0
	go func() {
		result <- browseSockets(ctx, iface, Options{Types: []string{"_http._tcp.local."}}, []multicastSocket{socket}, interfaceResult{}, func(r interfaceResult) {
			snapshots++
			if len(r.services) > 0 && r.services[0].Complete {
				cancel()
			}
		})
	}()
	select {
	case r := <-result:
		if len(r.services) != 1 || !r.services[0].Complete || snapshots == 0 || !queryTypes[dns.TypeSRV] || !queryTypes[dns.TypeAAAA] {
			t.Fatal(r, snapshots, queryTypes)
		}
		select {
		case <-closed:
		default:
			t.Fatal("receiver not joined/closed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("browse→resolve did not finish")
	}
}
func TestDiscoveryPreCanceledDoesNotOpenSockets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, Options{Duration: time.Second}, nil); err != context.Canceled {
		t.Fatal(err)
	}
}
