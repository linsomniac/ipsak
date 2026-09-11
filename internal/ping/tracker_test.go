package ping

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func TestReorderedRepliesDoNotInventLoss(t *testing.T) {
	start := time.Unix(1000, 0)
	tr := NewTracker(start, time.Second)
	for i := uint64(1); i <= 3; i++ {
		tr.Sent(i, start)
	}
	tr.Reply(3, start.Add(10*time.Millisecond))
	tr.Reply(2, start.Add(20*time.Millisecond))
	if events := tr.Advance(start.Add(30*time.Millisecond), true); len(events) != 0 {
		t.Fatal(events)
	}
	tr.Reply(1, start.Add(40*time.Millisecond))
	tr.Advance(start.Add(time.Second), true)
	s := tr.Snapshot(start.Add(time.Second))
	if s.Received != 3 || s.Lost != 0 || s.Pending != 0 || s.LossEvents != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestLossIntervalsRecoveryAndLateReplies(t *testing.T) {
	start := time.Unix(1000, 0)
	tr := NewTracker(start, time.Second)
	for i := uint64(1); i <= 6; i++ {
		tr.Sent(i, start.Add(time.Duration(i)*time.Millisecond))
	}
	tr.Reply(3, start.Add(20*time.Millisecond))
	tr.Reply(6, start.Add(30*time.Millisecond))
	events := tr.Advance(start.Add(2*time.Second), true)
	if len(events) != 4 {
		t.Fatalf("events: %+v", events)
	}
	for i, first := range []uint64{1, 4} {
		loss := events[i*2+1].Loss
		if loss.First != first || loss.Last != first+1 || loss.Count != 2 || !loss.Recovered {
			t.Fatalf("%+v", loss)
		}
	}
	tr.Reply(1, start.Add(3*time.Second))
	tr.Reply(1, start.Add(4*time.Second))
	tr.Reply(3, start.Add(30*time.Millisecond))
	tr.Reply(999, start)
	s := tr.Snapshot(start.Add(4 * time.Second))
	if s.Lost != 4 || s.Received != 2 || s.Late != 1 || s.Pending != 0 || s.LossEvents != 2 {
		t.Fatalf("%+v", s)
	}
}

func TestTimeoutBoundaryAndCancellation(t *testing.T) {
	start := time.Unix(1000, 0)
	tr := NewTracker(start, time.Second)
	tr.Sent(1, start)
	tr.Sent(2, start)
	if !tr.Reply(1, start.Add(time.Second)) {
		t.Fatal("reply at deadline should be accepted")
	}
	tr.Advance(start.Add(time.Second-time.Nanosecond), true)
	tr.Finish(start.Add(2*time.Second), true, nil)
	s := tr.Snapshot(start.Add(2 * time.Second))
	if s.Received != 1 || s.Pending != 1 || s.Lost != 0 || !s.Interrupted {
		t.Fatalf("%+v", s)
	}
}

func TestTimelyQueuedReplyUsesReceiptTimestamp(t *testing.T) {
	start := time.Unix(1000, 0)
	tr := NewTracker(start, time.Second)
	tr.Sent(1, start)
	// Processing is delayed past expiration, but the queued packet was received
	// before its deadline. Engine drains such replies before advancing cutoffs.
	tr.Reply(1, start.Add(900*time.Millisecond))
	tr.Advance(start.Add(2*time.Second), true)
	s := tr.Snapshot(start.Add(2 * time.Second))
	if s.Received != 1 || s.Lost != 0 || s.LastMS != 900 {
		t.Fatalf("%+v", s)
	}
}

func TestOngoingLossAndBoundedHistory(t *testing.T) {
	start := time.Unix(1000, 0)
	tr := NewTracker(start, time.Second)
	for i := uint64(1); i <= 10000; i++ {
		tr.Sent(i, start)
		if i%2 == 0 {
			tr.Reply(i, start)
		}
		tr.Advance(start.Add(time.Second), true)
	}
	s := tr.Snapshot(start)
	if len(tr.settled) > 1024 || len(s.RecentLosses) > 128 || len(s.History) > 40 || len(tr.probes) != 0 {
		t.Fatal("history grew beyond bounds")
	}
	if s.LossEvents != 5000 {
		t.Fatal(s.LossEvents)
	}
	tr.Sent(10001, start)
	tr.Sent(10002, start)
	tr.Advance(start.Add(time.Second), true)
	s = tr.Snapshot(start)
	if s.ActiveLoss == nil || s.ActiveLoss.Count != 2 {
		t.Fatalf("%+v", s)
	}
	tr.Finish(start.Add(2*time.Second), true, nil)
	s = tr.Snapshot(start)
	if s.RecentLosses[len(s.RecentLosses)-1].Recovered {
		t.Fatal("interruption fabricated recovery")
	}
}

func TestICMPIdentityAndSequenceWrap(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	p := ICMP{ip: ip, protocol: 1, reply: ipv4.ICMPTypeEchoReply, raw: true}
	copy(p.token[:], "random-token-1234")
	packet := func(id uint64, token []byte, seq int) []byte {
		data := make([]byte, 24)
		copy(data, token)
		binary.BigEndian.PutUint64(data[16:], id)
		m := icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: seq, Data: data}}
		b, err := m.Marshal(nil)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	source := &net.IPAddr{IP: net.ParseIP(ip.String())}
	now := time.Now()
	for _, id := range []uint64{1, 65535, 65536, 65537, 1 << 40} {
		r, ok := p.parse(packet(id, p.token[:], int(id&0xffff)), source, now)
		if !ok || r.ID != id {
			t.Fatalf("id %d failed", id)
		}
	}
	if _, ok := p.parse(packet(1, []byte("wrong session"), 1), source, now); ok {
		t.Error("accepted wrong token")
	}
	if _, ok := p.parse(packet(1, p.token[:], 2), source, now); ok {
		t.Error("accepted wrong sequence")
	}
	if _, ok := p.parse(packet(1, p.token[:], 1), &net.IPAddr{IP: net.ParseIP("192.0.2.2")}, now); ok {
		t.Error("accepted wrong source")
	}
	if _, ok := p.parse([]byte{1, 2, 3}, source, now); ok {
		t.Error("accepted malformed packet")
	}
}

type fakeTransport struct {
	replies chan Reply
	closed  chan struct{}
	once    sync.Once
	send    func(uint64) error
}

func (f *fakeTransport) Send(id uint64) error { return f.send(id) }
func (f *fakeTransport) Receive() (Reply, error) {
	select {
	case r := <-f.replies:
		return r, nil
	case <-f.closed:
		return Reply{}, net.ErrClosed
	}
}
func (f *fakeTransport) Close() error { f.once.Do(func() { close(f.closed) }); return nil }
func fake() *fakeTransport {
	return &fakeTransport{replies: make(chan Reply, 20), closed: make(chan struct{}), send: func(uint64) error { return nil }}
}

func TestEngineFiniteDrain(t *testing.T) {
	f := fake()
	f.send = func(id uint64) error {
		if id == 1 {
			f.replies <- Reply{ID: id, At: time.Now()}
		}
		return nil
	}
	opts := Options{Count: 3, Interval: 10 * time.Millisecond, Timeout: 30 * time.Millisecond}
	box := &Mailbox{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s := Run(ctx, f, opts, "test", "127.0.0.1", box)
	if s.Sent != 3 || s.Received != 1 || s.Lost != 2 || s.Pending != 0 || !s.Done || s.Error != "" || s.ElapsedSeconds < .04 {
		t.Fatalf("%+v", s)
	}
	_, events := box.Drain()
	if len(events) != 2 || events[1].Loss.Count != 2 || events[1].Loss.Recovered {
		t.Fatalf("%+v", events)
	}
	select {
	case <-f.closed:
	default:
		t.Error("transport not closed")
	}
}

func TestEngineCancellationAndSendFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := fake()
	f.send = func(uint64) error { cancel(); return nil }
	s := Run(ctx, f, Options{Interval: 10 * time.Millisecond, Timeout: time.Second}, "test", "test", &Mailbox{})
	if s.Sent != 1 || s.Pending != 1 || s.Lost != 0 || !s.Interrupted {
		t.Fatalf("%+v", s)
	}
	f = fake()
	f.send = func(uint64) error { return errors.New("write failed") }
	s = Run(context.Background(), f, Options{Interval: time.Second, Timeout: time.Second}, "test", "test", &Mailbox{})
	if s.Sent != 0 || s.Lost != 0 || s.Error == "" {
		t.Fatalf("%+v", s)
	}
}

func TestMailboxPreservesEventsAndCoalescesStatus(t *testing.T) {
	m := &Mailbox{}
	for i := 0; i < 100; i++ {
		if err := m.Publish(Snapshot{Sent: uint64(i)}, []Transition{{Kind: "end", Loss: Loss{First: uint64(i)}}}); err != nil {
			t.Fatal(err)
		}
	}
	s, e := m.Drain()
	if s.Sent != 99 || len(e) != 100 {
		t.Fatal(s, len(e))
	}
	_, e = m.Drain()
	if len(e) != 0 {
		t.Fatal("events replayed")
	}
}

func TestFinalLossTransitionOverflowIsReported(t *testing.T) {
	box := &Mailbox{}
	if err := box.Publish(Snapshot{}, make([]Transition, 1023)); err != nil {
		t.Fatal(err)
	}
	f := fake()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s := Run(ctx, f, Options{Count: 1, Interval: 10 * time.Millisecond, Timeout: 10 * time.Millisecond}, "test", "test", box)
	if !s.Done || s.Lost != 1 || !strings.Contains(s.Error, "output consumer stalled") {
		t.Fatalf("%+v", s)
	}
	published, _ := box.Drain()
	if published.Error != s.Error || !published.Done {
		t.Fatal("final overflow was not visible to consumer")
	}
}
