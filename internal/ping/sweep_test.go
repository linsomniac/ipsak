package ping

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func sweepOptions() SweepOptions {
	return SweepOptions{Count: 3, Interval: 10 * time.Millisecond, Timeout: 20 * time.Millisecond, Rate: 1000, MaxHosts: 4096}
}

func TestSweepRanges(t *testing.T) {
	for _, tt := range []struct {
		input, first, last string
		n                  int
	}{
		{"192.0.2.99/24", "192.0.2.0", "192.0.2.255", 256},
		{"192.0.2.4/31", "192.0.2.4", "192.0.2.5", 2},
		{"192.0.2.4/32", "192.0.2.4", "192.0.2.4", 1},
		{"2001:db8::3/127", "2001:db8::2", "2001:db8::3", 2},
		{"2001:db8::3/128", "2001:db8::3", "2001:db8::3", 1},
	} {
		p, n, err := SweepRange(netip.MustParsePrefix(tt.input), sweepOptions())
		if err != nil || n != tt.n {
			t.Fatal(tt, n, err)
		}
		tr := newSweepTracker(p, n, sweepOptions(), time.Now())
		if tr.hosts[0].Address.String() != tt.first || tr.hosts[n-1].Address.String() != tt.last {
			t.Fatal(tt, tr.hosts)
		}
	}
	for _, cidr := range []string{"::/0", "2001:db8::/64", "192.0.0.0/16", "224.0.0.0/24", "ff02::/120", "0.0.0.0/32", "::/128", "255.255.255.255/32", "fe80::/120", "::ffff:192.0.2.0/120"} {
		if _, _, err := SweepRange(netip.MustParsePrefix(cidr), sweepOptions()); err == nil {
			t.Fatalf("accepted %s", cidr)
		}
	}
	opts := sweepOptions()
	opts.MaxHosts = 65536
	if _, n, err := SweepRange(netip.MustParsePrefix("192.0.0.0/16"), opts); err != nil || n != 65536 {
		t.Fatal(n, err)
	}
	if _, _, err := SweepRange(netip.MustParsePrefix("192.0.0.0/15"), opts); err == nil {
		t.Fatal("accepted /15")
	}
	for _, mutate := range []func(*SweepOptions){
		func(o *SweepOptions) { o.Count = math.MaxUint64 }, func(o *SweepOptions) { o.Rate = 0 }, func(o *SweepOptions) { o.Rate = 1001 }, func(o *SweepOptions) { o.MaxHosts = 0 }, func(o *SweepOptions) { o.MaxHosts = 65537 }, func(o *SweepOptions) { o.Timeout = 0 }, func(o *SweepOptions) { o.Timeout = 2 * time.Hour }, func(o *SweepOptions) { o.Interval = time.Millisecond },
	} {
		o := sweepOptions()
		mutate(&o)
		if _, _, err := SweepRange(netip.MustParsePrefix("192.0.2.0/31"), o); err == nil {
			t.Fatal("accepted invalid options", o)
		}
	}
	opts.Timeout = time.Hour
	if _, _, err := SweepRange(netip.MustParsePrefix("192.0.2.0/31"), opts); err != nil {
		t.Fatal("sweep incorrectly used host pending ratio", err)
	}
}

func assertSweepAccounting(t *testing.T, s SweepSnapshot) {
	t.Helper()
	if s.Attempts != s.Sent+s.SendErrors || s.Sent != s.Received+s.Lost+s.Pending {
		t.Fatalf("aggregate invariant: %+v", s)
	}
	if s.Total != s.Responded+s.NoReply+s.Errors+s.Incomplete+s.Unprobed {
		t.Fatalf("host partition: %+v", s)
	}
	var attempts, sent, received, lost, pending, failed uint64
	for _, h := range s.Hosts {
		if h.Attempts != h.Sent+h.SendErrors || h.Sent != h.Received+h.Lost+h.Pending {
			t.Fatalf("host invariant: %+v", h)
		}
		attempts += h.Attempts
		sent += h.Sent
		received += h.Received
		lost += h.Lost
		pending += h.Pending
		failed += h.SendErrors
	}
	if attempts != s.Attempts || sent != s.Sent || received != s.Received || lost != s.Lost || pending != s.Pending || failed != s.SendErrors {
		t.Fatal("totals differ from hosts")
	}
}

func TestSweepReplyIdentityDeadlinesAndAccounting(t *testing.T) {
	start := time.Unix(1000, 0)
	o := sweepOptions()
	o.Count = 1
	o.Timeout = time.Second
	tr := newSweepTracker(netip.MustParsePrefix("192.0.2.0/30"), 4, o, start)
	for i := 0; i < 3; i++ {
		tr.sent(uint64(i+1), i, start, nil)
	}
	tr.sent(4, 3, start, errors.New("no route"))
	tr.reply(Reply{ID: 1, Address: tr.hosts[1].Address, At: start.Add(time.Millisecond)})
	tr.reply(Reply{ID: 1, Address: tr.hosts[0].Address, At: start.Add(-time.Millisecond)})
	tr.reply(Reply{ID: 999, Address: tr.hosts[0].Address, At: start})
	tr.reply(Reply{ID: 2, Address: tr.hosts[1].Address, At: start.Add(time.Second)})
	tr.reply(Reply{ID: 2, Address: tr.hosts[1].Address, At: start.Add(time.Second)})
	tr.reply(Reply{ID: 3, Address: tr.hosts[2].Address, At: start.Add(2 * time.Second)})
	tr.expire(start.Add(3 * time.Second))
	tr.reply(Reply{ID: 1, Address: tr.hosts[1].Address, At: start.Add(4 * time.Second)})
	tr.reply(Reply{ID: 1, Address: tr.hosts[0].Address, At: start.Add(4 * time.Second)})
	tr.reply(Reply{ID: 1, Address: tr.hosts[0].Address, At: start.Add(5 * time.Second)})
	tr.reply(Reply{ID: 3, Address: tr.hosts[2].Address, At: start.Add(5 * time.Second)})
	s := tr.snapshot(start.Add(5*time.Second), true)
	assertSweepAccounting(t, s)
	if s.Responded != 1 || s.Received != 1 || s.Lost != 2 || s.Late != 2 || s.SendErrors != 1 || s.Completed != 4 || s.NoReply != 2 || s.RTT.AvgMS != 1000 {
		t.Fatalf("%+v", s)
	}
	if s.Hosts[0].RTT != nil {
		t.Fatal("silent host has RTT")
	}
	b, err := json.Marshal(s)
	if err != nil || !strings.Contains(string(b), `"rtt":null`) {
		t.Fatal(string(b), err)
	}
}

func TestSweepWeightedStatisticsAndSnapshotIsolation(t *testing.T) {
	start := time.Unix(1000, 0)
	tr := newSweepTracker(netip.MustParsePrefix("192.0.2.0/31"), 2, sweepOptions(), start)
	for id := uint64(1); id <= 3; id++ {
		tr.sent(id, 0, start, nil)
		tr.reply(Reply{ID: id, Address: tr.hosts[0].Address, At: start.Add(time.Millisecond)})
	}
	tr.sent(4, 1, start, nil)
	tr.reply(Reply{ID: 4, Address: tr.hosts[1].Address, At: start.Add(9 * time.Millisecond)})
	s := tr.snapshot(start, true)
	assertSweepAccounting(t, s)
	if s.RTT.Samples != 4 || s.RTT.AvgMS != 3 || s.RTT.MinMS != 1 || s.RTT.MaxMS != 9 || math.Abs(s.RTT.StdDevMS-math.Sqrt(12)) > 1e-10 {
		t.Fatalf("%+v", s.RTT)
	}
	tr.sent(5, 1, start, nil)
	tr.reply(Reply{ID: 5, Address: tr.hosts[1].Address, At: start.Add(10 * time.Millisecond)})
	if s.RTT.AvgMS != 3 || s.Hosts[1].RTT.AvgMS != 9 {
		t.Fatal("snapshot mutated after publication")
	}
	for id := uint64(6); id < 5000; id++ {
		tr.sent(id, 0, start, nil)
		tr.expire(start.Add(time.Second))
	}
	if len(tr.recent) != recentSweepProbes || len(tr.pending) != 0 {
		t.Fatal("unbounded probe state", len(tr.recent), len(tr.pending))
	}
	late := tr.s.Late
	tr.reply(Reply{ID: 6, Address: tr.hosts[0].Address, At: start.Add(time.Second)})
	if tr.s.Late != late {
		t.Fatal("evicted reply counted")
	}
}

type fakeSweepTransport struct {
	replies chan Reply
	errors  chan error
	closed  chan struct{}
	once    sync.Once
	send    func(uint64, netip.Addr) error
}

func fakeSweep() *fakeSweepTransport {
	return &fakeSweepTransport{replies: make(chan Reply, 100), errors: make(chan error, 1), closed: make(chan struct{}), send: func(uint64, netip.Addr) error { return nil }}
}
func (f *fakeSweepTransport) SendTo(id uint64, ip netip.Addr) error { return f.send(id, ip) }
func (f *fakeSweepTransport) Receive() (Reply, error) {
	select {
	case r := <-f.replies:
		return r, nil
	case err := <-f.errors:
		return Reply{}, err
	case <-f.closed:
		return Reply{}, net.ErrClosed
	}
}
func (f *fakeSweepTransport) Close() error { f.once.Do(func() { close(f.closed) }); return nil }

func TestSweepFiniteRoundRobinAndPacing(t *testing.T) {
	f := fakeSweep()
	o := sweepOptions()
	o.Rate = 200
	o.Interval = 30 * time.Millisecond
	var addresses []netip.Addr
	var times []time.Time
	var finished []time.Time
	f.send = func(id uint64, ip netip.Addr) error {
		addresses = append(addresses, ip)
		times = append(times, time.Now())
		if id == 1 {
			time.Sleep(20 * time.Millisecond)
		}
		defer func() { finished = append(finished, time.Now()) }()
		switch ip.String() {
		case "192.0.2.0":
			f.replies <- Reply{ID: id, Address: ip, At: time.Now()}
		case "192.0.2.2":
			return errors.New("no route")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	box := &SweepMailbox{}
	s := RunSweep(ctx, f, netip.MustParsePrefix("192.0.2.0/30"), o, box)
	assertSweepAccounting(t, s)
	if !s.Done || s.Partial || s.Error != "" || s.Completed != 4 || s.Attempts != 12 || s.SendErrors != 3 || s.Sent != 9 || s.Responded != 1 || s.NoReply != 2 || s.Errors != 1 {
		t.Fatalf("%+v", s)
	}
	for i, ip := range addresses {
		if ip != s.Hosts[i%4].Address {
			t.Fatal("not round robin", addresses)
		}
		if i > 0 && times[i].Sub(finished[i-1]) < time.Second/time.Duration(o.Rate) {
			t.Fatal("global burst", times)
		}
		if i >= 4 && times[i].Sub(times[i-4]) < o.Interval {
			t.Fatal("per-host interval violated")
		}
	}
	select {
	case <-f.closed:
	default:
		t.Fatal("transport not closed")
	}
	if preview := box.Snapshot(); !preview.Done || preview.Responded != s.Responded {
		t.Fatal(preview)
	}
}

func TestSweepOnePendingPerHostAndFiniteDrain(t *testing.T) {
	f := fakeSweep()
	o := sweepOptions()
	o.Count = 2
	o.Timeout = 40 * time.Millisecond
	var times []time.Time
	f.send = func(uint64, netip.Addr) error { times = append(times, time.Now()); return nil }
	s := RunSweep(context.Background(), f, netip.MustParsePrefix("192.0.2.1/32"), o, &SweepMailbox{})
	assertSweepAccounting(t, s)
	if len(times) != 2 || times[1].Sub(times[0]) < o.Timeout || s.Lost != 2 || s.Pending != 0 || s.ElapsedSeconds < .08 {
		t.Fatalf("%+v %v", s, times)
	}
}

func TestSweepPacesHostAfterBlockedWrite(t *testing.T) {
	f := fakeSweep()
	o := sweepOptions()
	o.Count = 2
	o.Interval = 20 * time.Millisecond
	o.Timeout = time.Second
	var finished time.Time
	f.send = func(id uint64, ip netip.Addr) error {
		if id == 1 {
			time.Sleep(30 * time.Millisecond)
		} else if time.Since(finished) < o.Interval {
			t.Error("blocked write caused per-host catch-up burst")
		}
		f.replies <- Reply{ID: id, Address: ip, At: time.Now()}
		finished = time.Now()
		return nil
	}
	s := RunSweep(context.Background(), f, netip.MustParsePrefix("192.0.2.1/32"), o, &SweepMailbox{})
	if s.Received != 2 || s.Error != "" {
		t.Fatalf("%+v", s)
	}
}

func TestSweepPreviewPrioritizesRespondersAndQueuedTimelyReply(t *testing.T) {
	start := time.Unix(1000, 0)
	o := sweepOptions()
	o.Count = 1
	tr := newSweepTracker(netip.MustParsePrefix("192.0.2.0/26"), 64, o, start)
	for i := 0; i < 63; i++ {
		tr.sent(uint64(i+1), i, start, errors.New("no route"))
	}
	tr.sent(64, 63, start, nil)
	// A reply queued before expiry is accepted even if accounting runs later.
	tr.reply(Reply{ID: 64, Address: tr.hosts[63].Address, At: start.Add(time.Millisecond)})
	tr.expire(start.Add(time.Second))
	s := tr.snapshot(start.Add(time.Second), false)
	if len(s.Hosts) != 1 || s.Hosts[0].Address.String() != "192.0.2.63" || s.Responded != 1 || s.Lost != 0 || s.Errors != 63 {
		t.Fatalf("%+v", s)
	}
}

func TestSweepCancellationAndReadErrorPreservePartialResults(t *testing.T) {
	for _, fatal := range []bool{false, true} {
		f := fakeSweep()
		ctx, cancel := context.WithCancel(context.Background())
		o := sweepOptions()
		o.Timeout = time.Hour
		o.Rate = 1
		f.send = func(uint64, netip.Addr) error {
			if fatal {
				f.errors <- errors.New("socket failed")
			} else {
				cancel()
			}
			return nil
		}
		s := RunSweep(ctx, f, netip.MustParsePrefix("192.0.2.0/30"), o, &SweepMailbox{})
		cancel()
		assertSweepAccounting(t, s)
		if !s.Done || !s.Partial || s.Pending != 1 || s.Lost != 0 || s.Unprobed != 3 {
			t.Fatalf("%+v", s)
		}
		if fatal && !strings.Contains(s.Error, "socket failed") || !fatal && s.StopReason != "interrupted" {
			t.Fatalf("%+v", s)
		}
	}
	f := fakeSweep()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	o := sweepOptions()
	o.Count = 0
	o.Timeout = time.Hour
	s := RunSweep(ctx, f, netip.MustParsePrefix("192.0.2.0/31"), o, &SweepMailbox{})
	assertSweepAccounting(t, s)
	if s.StopReason != "duration" || s.Pending != s.Sent || s.Pending > 2 || s.Lost != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestSweepICMPPreservesSourceAndFullID(t *testing.T) {
	for _, six := range []bool{false, true} {
		p := ICMP{protocol: 1, reply: ipv4.ICMPTypeEchoReply, raw: true}
		ip := netip.MustParseAddr("192.0.2.1")
		if six {
			p.protocol = 58
			p.reply = ipv6.ICMPTypeEchoReply
			ip = netip.MustParseAddr("2001:db8::1")
		}
		copy(p.token[:], "random-token-1234")
		for _, id := range []uint64{1, 65536, 65537} {
			data := make([]byte, 24)
			copy(data, p.token[:])
			binary.BigEndian.PutUint64(data[16:], id)
			msg := icmp.Message{Type: p.reply, Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: int(id & 0xffff), Data: data}}
			b, err := msg.Marshal(nil)
			if err != nil {
				t.Fatal(err)
			}
			r, ok := p.parse(b, &net.IPAddr{IP: net.IP(ip.AsSlice())}, time.Now())
			if !ok || r.Address != ip || r.ID != id {
				t.Fatal(r, ok)
			}
			data[0] ^= 0xff
			b, _ = msg.Marshal(nil)
			if _, ok = p.parse(b, &net.IPAddr{IP: net.IP(ip.AsSlice())}, time.Now()); ok {
				t.Fatal("foreign token accepted")
			}
		}
	}
}
