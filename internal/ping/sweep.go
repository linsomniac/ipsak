package ping

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"sync"
	"time"
)

const MaxSweepHosts = 65536
const maxSweepPending = 4096
const recentSweepProbes = 1024

type SweepOptions struct {
	Count             uint64
	Interval, Timeout time.Duration
	Rate, MaxHosts    int
}

// SweepRange validates before allocating targets or opening any sockets.
func SweepRange(prefix netip.Prefix, opts SweepOptions) (netip.Prefix, int, error) {
	if !prefix.IsValid() || prefix.Addr().Is4In6() {
		return prefix, 0, fmt.Errorf("use an IPv4 or native IPv6 CIDR (IPv4-mapped IPv6 CIDRs are unsupported)")
	}
	prefix = prefix.Masked()
	if opts.MaxHosts < 1 || opts.MaxHosts > MaxSweepHosts {
		return prefix, 0, fmt.Errorf("max-hosts must be between 1 and %d", MaxSweepHosts)
	}
	bits := prefix.Addr().BitLen() - prefix.Bits()
	if bits > 16 || 1<<bits > opts.MaxHosts {
		return prefix, 0, fmt.Errorf("%s exceeds --max-hosts %d; choose a smaller CIDR or raise --max-hosts (maximum %d)", prefix, opts.MaxHosts, MaxSweepHosts)
	}
	n := 1 << bits
	if opts.Count > math.MaxUint64/uint64(n) {
		return prefix, 0, fmt.Errorf("count times addresses is too large")
	}
	if opts.Rate < 1 || opts.Rate > 1000 {
		return prefix, 0, fmt.Errorf("rate must be between 1 and 1000 packets per second")
	}
	if opts.Interval < 10*time.Millisecond {
		return prefix, 0, fmt.Errorf("interval must be at least 10ms")
	}
	if opts.Timeout <= 0 || opts.Timeout > time.Hour {
		return prefix, 0, fmt.Errorf("ping timeout must be greater than zero and at most 1h")
	}
	ip := prefix.Addr()
	if ip.IsMulticast() || ip.IsUnspecified() || prefix.Contains(netip.MustParseAddr("255.255.255.255")) {
		return prefix, 0, fmt.Errorf("CIDR must contain only unicast destinations; multicast, unspecified and limited broadcast addresses cannot be swept")
	}
	if ip.Is6() && ip.IsLinkLocalUnicast() {
		return prefix, 0, fmt.Errorf("IPv6 link-local CIDRs require interface scope; ping individual addresses with a zone, for example fe80::1%%eth0")
	}
	return prefix, n, nil
}

// RTTStats uses Welford's algorithm; averages are weighted by accepted replies.
// A nil *RTTStats means that no timely replies were received.
type RTTStats struct {
	Samples  uint64  `json:"samples"`
	MinMS    float64 `json:"min_ms"`
	AvgMS    float64 `json:"avg_ms"`
	MaxMS    float64 `json:"max_ms"`
	StdDevMS float64 `json:"stddev_ms"`
	m2       float64
}

func (s *RTTStats) add(ms float64) {
	s.Samples++
	if s.Samples == 1 || ms < s.MinMS {
		s.MinMS = ms
	}
	if ms > s.MaxMS {
		s.MaxMS = ms
	}
	delta := ms - s.AvgMS
	s.AvgMS += delta / float64(s.Samples)
	s.m2 += delta * (ms - s.AvgMS)
	s.StdDevMS = math.Sqrt(math.Max(0, s.m2/float64(s.Samples)))
}

type SweepHost struct {
	Address     netip.Addr `json:"address"`
	Status      string     `json:"status"`
	Attempts    uint64     `json:"attempts"`
	Sent        uint64     `json:"sent"`
	Received    uint64     `json:"received"`
	Lost        uint64     `json:"lost"`
	Pending     uint64     `json:"pending"`
	Late        uint64     `json:"late"`
	SendErrors  uint64     `json:"send_errors"`
	LossPercent float64    `json:"loss_percent"`
	RTT         *RTTStats  `json:"rtt"`
	Error       string     `json:"error,omitempty"`
}

type SweepSnapshot struct {
	CIDR           string      `json:"cidr"`
	Total          int         `json:"total"`
	Probed         int         `json:"probed"`
	Completed      int         `json:"completed"`
	Responded      int         `json:"responded"`
	NoReply        int         `json:"no_reply"`
	Errors         int         `json:"errors"`
	Incomplete     int         `json:"incomplete"`
	Unprobed       int         `json:"unprobed"`
	Count          uint64      `json:"count_per_address"`
	Rate           int         `json:"rate_pps"`
	IntervalMS     float64     `json:"interval_ms"`
	TimeoutMS      float64     `json:"timeout_ms"`
	Planned        uint64      `json:"planned_probes"`
	Attempts       uint64      `json:"attempts"`
	Sent           uint64      `json:"sent"`
	Received       uint64      `json:"received"`
	Lost           uint64      `json:"lost"`
	Pending        uint64      `json:"pending"`
	Late           uint64      `json:"late"`
	SendErrors     uint64      `json:"send_errors"`
	RTT            *RTTStats   `json:"rtt"`
	ElapsedSeconds float64     `json:"elapsed_seconds"`
	Done           bool        `json:"done"`
	Partial        bool        `json:"partial"`
	StopReason     string      `json:"stop_reason,omitempty"`
	Error          string      `json:"error,omitempty"`
	Hosts          []SweepHost `json:"hosts"`
}

// SweepMailbox keeps only the latest immutable preview (at most 32 hosts).
// Full address tables travel only through the final result channel.
type SweepMailbox struct {
	mu sync.Mutex
	s  SweepSnapshot
}

func (b *SweepMailbox) Publish(s SweepSnapshot) { b.mu.Lock(); b.s = s; b.mu.Unlock() }
func (b *SweepMailbox) Snapshot() SweepSnapshot { b.mu.Lock(); defer b.mu.Unlock(); return b.s }

type SweepTransport interface {
	SendTo(uint64, netip.Addr) error
	Receive() (Reply, error)
	Close() error
}

type sweepProbe struct {
	host int
	sent time.Time
	late bool
	lost bool
}
type sweepTracker struct {
	start      time.Time
	opts       SweepOptions
	s          SweepSnapshot
	hosts      []SweepHost
	lastSent   []time.Time
	pending    map[uint64]sweepProbe
	recent     map[uint64]sweepProbe
	recentIDs  [recentSweepProbes]uint64
	recentNext int
}

func newSweepTracker(prefix netip.Prefix, n int, opts SweepOptions, start time.Time) *sweepTracker {
	t := &sweepTracker{start: start, opts: opts, hosts: make([]SweepHost, n), lastSent: make([]time.Time, n), pending: make(map[uint64]sweepProbe), recent: make(map[uint64]sweepProbe)}
	t.s = SweepSnapshot{CIDR: prefix.String(), Total: n, Count: opts.Count, Planned: uint64(n) * opts.Count, Rate: opts.Rate, IntervalMS: float64(opts.Interval) / float64(time.Millisecond), TimeoutMS: float64(opts.Timeout) / float64(time.Millisecond)}
	ip := prefix.Addr()
	for i := range t.hosts {
		t.hosts[i].Address = ip
		ip = ip.Next()
	}
	return t
}

func (t *sweepTracker) sent(id uint64, host int, now time.Time, err error) {
	h := &t.hosts[host]
	h.Attempts++
	t.s.Attempts++
	t.lastSent[host] = now
	if err != nil {
		h.SendErrors++
		t.s.SendErrors++
		h.Error = err.Error()
		return
	}
	h.Sent++
	t.s.Sent++
	h.Pending++
	t.s.Pending++
	t.pending[id] = sweepProbe{host: host, sent: now}
}

func (t *sweepTracker) remember(id uint64, p sweepProbe) {
	delete(t.recent, t.recentIDs[t.recentNext])
	t.recentIDs[t.recentNext] = id
	t.recentNext = (t.recentNext + 1) % recentSweepProbes
	t.recent[id] = p
}

func (t *sweepTracker) reply(r Reply) {
	p, ok := t.pending[r.ID]
	if !ok {
		p, ok = t.recent[r.ID]
		if ok && p.lost && !p.late && r.Address == t.hosts[p.host].Address && !r.At.Before(p.sent) {
			p.late = true
			t.recent[r.ID] = p
			t.hosts[p.host].Late++
			t.s.Late++
		}
		return
	}
	h := &t.hosts[p.host]
	if r.Address != h.Address || r.At.Before(p.sent) {
		return
	}
	if r.At.After(p.sent.Add(t.opts.Timeout)) {
		if !p.late {
			p.late = true
			t.pending[r.ID] = p
			h.Late++
			t.s.Late++
		}
		return
	}
	delete(t.pending, r.ID)
	t.remember(r.ID, p)
	h.Pending--
	t.s.Pending--
	h.Received++
	t.s.Received++
	ms := float64(r.At.Sub(p.sent)) / float64(time.Millisecond)
	if h.RTT == nil {
		h.RTT = &RTTStats{}
	}
	if t.s.RTT == nil {
		t.s.RTT = &RTTStats{}
	}
	h.RTT.add(ms)
	t.s.RTT.add(ms)
}

func (t *sweepTracker) expire(now time.Time) {
	for id, p := range t.pending {
		if now.Before(p.sent.Add(t.opts.Timeout)) {
			continue
		}
		h := &t.hosts[p.host]
		h.Pending--
		t.s.Pending--
		h.Lost++
		t.s.Lost++
		p.lost = true
		t.remember(id, p)
		delete(t.pending, id)
	}
}

func (t *sweepTracker) snapshot(now time.Time, full bool) SweepSnapshot {
	s := t.s
	s.ElapsedSeconds = now.Sub(t.start).Seconds()
	s.Hosts = []SweepHost{}
	if s.RTT != nil {
		r := *s.RTT
		s.RTT = &r
	}
	for _, h := range t.hosts {
		complete := t.opts.Count > 0 && h.Attempts == t.opts.Count && h.Pending == 0
		if complete {
			s.Completed++
		}
		if h.Attempts > 0 {
			s.Probed++
		}
		switch {
		case h.Received > 0:
			h.Status = "responded"
			s.Responded++
		case h.Attempts == 0:
			h.Status = "unprobed"
			s.Unprobed++
		case h.SendErrors > 0:
			h.Status = "error"
			s.Errors++
		case complete:
			h.Status = "no_reply"
			s.NoReply++
		default:
			h.Status = "incomplete"
			s.Incomplete++
		}
		if h.Sent > 0 {
			h.LossPercent = 100 * float64(h.Lost) / float64(h.Sent)
		}
		if full || (len(s.Hosts) < 32 && h.Received > 0) {
			if h.RTT != nil {
				r := *h.RTT
				h.RTT = &r
			}
			s.Hosts = append(s.Hosts, h)
		}
	}
	s.Partial = s.Completed != s.Total
	return s
}

// RunSweep owns and closes a single shared socket. Scheduling and accounting
// have one owner; output consumes coalesced snapshots independently of receipt.
func RunSweep(ctx context.Context, transport SweepTransport, prefix netip.Prefix, opts SweepOptions, box *SweepMailbox) SweepSnapshot {
	start := time.Now()
	prefix, n, err := SweepRange(prefix, opts)
	if err != nil {
		_ = transport.Close()
		s := SweepSnapshot{CIDR: prefix.String(), Done: true, Partial: true, Error: err.Error(), Hosts: []SweepHost{}}
		box.Publish(s)
		return s
	}
	t := newSweepTracker(prefix, n, opts, start)
	replies := make(chan Reply, maxSweepPending)
	readErrors := make(chan error, 1)
	stop := make(chan struct{})
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			r, err := transport.Receive()
			if err != nil {
				select {
				case readErrors <- err:
				default:
				}
				return
			}
			select {
			case replies <- r:
			case <-stop:
				return
			}
		}
	}()
	defer func() { close(stop); _ = transport.Close(); <-readDone }()
	gap := time.Second / time.Duration(opts.Rate)
	tick := gap / 4
	if tick > 10*time.Millisecond {
		tick = 10 * time.Millisecond
	}
	if tick < time.Millisecond {
		tick = time.Millisecond
	}
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	nextSend, nextPublish := start, start
	host := 0
	drain := func() {
		for available := len(replies); available > 0; available-- {
			t.reply(<-replies)
		}
	}
	for {
		if ctx.Err() != nil {
			if ctx.Err() == context.DeadlineExceeded {
				t.s.StopReason = "duration"
			} else {
				t.s.StopReason = "interrupted"
			}
			break
		}
		cutoff := time.Now()
		drain()
		t.expire(cutoff)
		if opts.Count > 0 && t.s.Attempts == t.s.Planned && len(t.pending) == 0 {
			break
		}
		now := time.Now()
		h := &t.hosts[host]
		if (opts.Count == 0 || t.s.Attempts < t.s.Planned) && len(t.pending) < maxSweepPending && h.Pending == 0 && !now.Before(nextSend) && !now.Before(t.lastSent[host].Add(opts.Interval)) {
			if t.s.Attempts == math.MaxUint64 {
				t.s.Error = "probe ID space exhausted"
				break
			}
			id := t.s.Attempts + 1
			err := transport.SendTo(id, h.Address)
			t.sent(id, host, now, err)
			// Pace from write completion, including after a blocked socket write.
			// RTT and the reply deadline still start at application send time.
			t.lastSent[host] = time.Now()
			nextSend = t.lastSent[host].Add(gap)
			host = (host + 1) % n
		}
		if !now.Before(nextPublish) {
			box.Publish(t.snapshot(now, false))
			nextPublish = now.Add(50 * time.Millisecond)
		}
		select {
		case <-ctx.Done():
		case err := <-readErrors:
			t.s.Error = fmt.Sprintf("receive ICMP: %v", err)
		case r := <-replies:
			t.reply(r)
		case <-ticker.C:
		}
		if t.s.Error != "" {
			break
		}
	}
	drain() // Do not turn unresolved probes into loss when stopping early.
	t.s.Done = true
	box.Publish(t.snapshot(time.Now(), false))
	return t.snapshot(time.Now(), true)
}
