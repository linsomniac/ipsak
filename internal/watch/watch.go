// Package watch monitors independent services with bounded concurrent checks.
package watch

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/linsomniac/ipsak/internal/probe"
	"github.com/miekg/dns"
)

type Target struct {
	Name    string `json:"target"`
	Kind    string `json:"kind"`
	Host    string `json:"-"`
	Address string `json:"-"`
	Qtype   uint16 `json:"-"`
}

func Parse(raw string) (Target, error) {
	t := Target{Name: raw}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return t, fmt.Errorf("use http(s)://host/path, tcp://host:port, dns://name?type=A, or icmp://host")
	}
	t.Kind = u.Scheme
	switch u.Scheme {
	case "http", "https":
		v, e := probe.HTTPURL(raw)
		if e != nil {
			return t, e
		}
		t.Address = v.String()
		t.Host = v.Hostname()
	case "tcp":
		if u.Path != "" || u.RawQuery != "" || u.Port() == "" {
			return t, fmt.Errorf("TCP target requires tcp://host:port")
		}
		t.Host, t.Address, err = probe.HostPort(u.Host, "")
	case "dns", "icmp":
		if u.Path != "" || u.Port() != "" {
			return t, fmt.Errorf("%s target takes a host without port or path", u.Scheme)
		}
		if u.Scheme == "dns" {
			if _, e := netip.ParseAddr(u.Hostname()); e == nil {
				return t, fmt.Errorf("use a DNS owner name, including a reverse zone for PTR")
			}
			t.Host, _, _, err = probe.DNSOptions(u.Hostname(), []string{"A"}, []string{"127.0.0.1"})
		} else {
			t.Host, err = probe.Host(u.Hostname())
		}
		if err != nil {
			return t, err
		}
		if u.Scheme == "icmp" {
			if u.RawQuery != "" {
				return t, fmt.Errorf("ICMP target has no query options")
			}
			if a, e := netip.ParseAddr(t.Host); e == nil && (a.IsUnspecified() || a.IsMulticast() || a == netip.MustParseAddr("255.255.255.255")) {
				return t, fmt.Errorf("ICMP requires a unicast destination")
			}
		} else {
			q, e := url.ParseQuery(u.RawQuery)
			if e != nil {
				return t, e
			}
			if len(q) > 1 || len(q["type"]) > 1 {
				return t, fmt.Errorf("DNS target accepts one type parameter")
			}
			for key := range q {
				if key != "type" {
					return t, fmt.Errorf("unknown DNS parameter %s", key)
				}
			}
			kind := strings.ToUpper(q.Get("type"))
			if kind == "" {
				kind = "A"
			}
			var ok bool
			t.Qtype, ok = dns.StringToType[kind]
			if !ok || !(kind == "A" || kind == "AAAA" || kind == "MX" || kind == "NS" || kind == "TXT" || kind == "SOA" || kind == "PTR" || kind == "CNAME" || kind == "SRV" || kind == "CAA") {
				return t, fmt.Errorf("unsupported DNS watch type")
			}
		}
	default:
		return t, fmt.Errorf("unsupported watch scheme %q", u.Scheme)
	}
	return t, err
}

type Options struct {
	Interval, Timeout, Duration time.Duration
	Count                       int
	Until                       string
	Concurrency                 int
}

func (o Options) Validate(targets []Target) error {
	if len(targets) < 1 || len(targets) > 128 {
		return fmt.Errorf("watch requires 1–128 targets")
	}
	if o.Interval < 100*time.Millisecond || o.Interval > time.Hour || o.Timeout <= 0 || o.Timeout > time.Minute || o.Duration < 0 || o.Duration > 24*time.Hour || o.Count < 0 || o.Count > 1000000 || o.Concurrency < 1 || o.Concurrency > 32 {
		return fmt.Errorf("invalid watch bounds: interval 100ms–1h, timeout (0,1m], duration 0–24h, count 0–1000000, concurrency 1–32")
	}
	if o.Until != "" && o.Until != "all-up" && o.Until != "any-down" {
		return fmt.Errorf("until must be all-up or any-down")
	}
	return nil
}

type Check struct {
	Detail string
	Err    error
}
type Checker func(context.Context, Target) Check
type State struct {
	Target      string     `json:"target"`
	Status      string     `json:"status"`
	InFlight    bool       `json:"in_flight"`
	Checks      uint64     `json:"checks"`
	Successes   uint64     `json:"successes"`
	Failures    uint64     `json:"failures"`
	Pending     uint64     `json:"pending"`
	Outages     uint64     `json:"outages"`
	LastMS      float64    `json:"last_ms"`
	Detail      string     `json:"detail,omitempty"`
	Error       string     `json:"error,omitempty"`
	LastChecked *time.Time `json:"last_checked,omitempty"`
}
type Event struct {
	Target string    `json:"target"`
	Kind   string    `json:"kind"`
	At     time.Time `json:"at"`
}
type Result struct {
	Started       time.Time `json:"started"`
	ElapsedMS     int64     `json:"elapsed_ms"`
	Rounds        int       `json:"rounds"`
	Status        string    `json:"status"`
	Condition     string    `json:"condition,omitempty"`
	ConditionMet  bool      `json:"condition_met"`
	Targets       []State   `json:"targets"`
	Events        []Event   `json:"events"`
	EventsDropped uint64    `json:"events_dropped"`
}

func (r Result) CompactLines() []string {
	lines := []string{fmt.Sprintf("%d targets · round %d · %.1fs · %s", len(r.Targets), r.Rounds, float64(r.ElapsedMS)/1000, r.Status)}
	for _, s := range r.Targets {
		state := s.Status
		if s.InFlight {
			state += " …"
		}
		lines = append(lines, fmt.Sprintf("%-10s %s", state, s.Target), fmt.Sprintf("  %.2f ms · %d checks · %d failures · %d outages", s.LastMS, s.Checks, s.Failures, s.Outages))
		if s.Error != "" {
			lines = append(lines, "  "+s.Error)
		}
	}
	for _, e := range r.Events[max(0, len(r.Events)-8):] {
		lines = append(lines, e.At.Local().Format("15:04:05")+"  "+e.Kind+" · "+e.Target)
	}
	return lines
}
func (r Result) clone() Result {
	r.Targets = append([]State(nil), r.Targets...)
	r.Events = append([]Event(nil), r.Events...)
	return r
}

func Run(ctx context.Context, targets []Target, o Options, check Checker, emit func(Result)) (Result, error) {
	r := Result{Started: time.Now().UTC(), Status: "running", Condition: o.Until, Targets: make([]State, len(targets)), Events: []Event{}}
	if err := o.Validate(targets); err != nil {
		return r, err
	}
	if check == nil {
		return r, fmt.Errorf("missing checker")
	}
	for i, t := range targets {
		r.Targets[i] = State{Target: t.Name, Status: "unprobed"}
	}
	var work context.Context
	var cancel context.CancelFunc
	if o.Duration > 0 {
		work, cancel = context.WithTimeout(ctx, o.Duration)
	} else {
		work, cancel = context.WithCancel(ctx)
	}
	defer cancel()
	update := func() {
		r.ElapsedMS = time.Since(r.Started).Milliseconds()
		if emit != nil {
			emit(r.clone())
		}
	}
	addEvent := func(t, kind string) {
		if len(r.Events) == 128 {
			copy(r.Events, r.Events[1:])
			r.Events = r.Events[:127]
			r.EventsDropped++
		}
		r.Events = append(r.Events, Event{t, kind, time.Now().UTC()})
	}
	var completed, failed uint64
	for o.Count == 0 || r.Rounds < o.Count {
		if work.Err() != nil {
			break
		}
		start := time.Now()
		r.Rounds++
		for i := range r.Targets {
			r.Targets[i].InFlight = true
		}
		update()
		type item struct {
			i       int
			c       Check
			ms      float64
			at      time.Time
			pending bool
		}
		jobs := make(chan int, len(targets))
		answers := make(chan item, len(targets))
		for i := range targets {
			jobs <- i
		}
		close(jobs)
		for range min(o.Concurrency, len(targets)) {
			go func() {
				for i := range jobs {
					if work.Err() != nil {
						answers <- item{i: i, pending: true}
						continue
					}
					qctx, stop := context.WithTimeout(work, o.Timeout)
					now := time.Now()
					c := check(qctx, targets[i])
					err := qctx.Err()
					stop()
					if c.Err == nil && err != nil {
						c.Err = err
					}
					pending := work.Err() != nil && (errors.Is(c.Err, context.Canceled) || errors.Is(c.Err, context.DeadlineExceeded))
					answers <- item{i: i, c: c, ms: float64(time.Since(now)) / float64(time.Millisecond), at: time.Now().UTC(), pending: pending}
				}
			}()
		}
		roundUp, roundDown := 0, 0
		for range targets {
			a := <-answers
			s := &r.Targets[a.i]
			s.InFlight = false
			if a.pending {
				s.Pending++
				update()
				continue
			}
			completed++
			s.Checks++
			s.LastMS = a.ms
			s.LastChecked = &a.at
			s.Detail = a.c.Detail
			if a.c.Err != nil {
				failed++
				roundDown++
				s.Failures++
				s.Error = a.c.Err.Error()
				if s.Status != "down" {
					s.Outages++
					addEvent(s.Target, "down")
				}
				s.Status = "down"
			} else {
				roundUp++
				s.Successes++
				s.Error = ""
				if s.Status == "down" {
					addEvent(s.Target, "recovered")
				}
				s.Status = "up"
			}
			update()
		}
		if o.Until == "all-up" && roundUp == len(targets) || o.Until == "any-down" && roundDown > 0 {
			r.ConditionMet = true
			break
		}
		if o.Count > 0 && r.Rounds >= o.Count {
			break
		}
		wait := time.Until(start.Add(o.Interval))
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-work.Done():
			case <-timer.C:
			}
			timer.Stop()
		}
	}
	r.Status = "completed"
	if ctx.Err() != nil {
		r.Status = "interrupted"
		update()
		return r, ctx.Err()
	}
	update()
	if o.Until == "all-up" && r.ConditionMet {
		return r, nil
	}
	if completed == 0 {
		return r, fmt.Errorf("no checks completed")
	}
	if o.Until != "" && !r.ConditionMet {
		return r, fmt.Errorf("readiness condition was not met")
	}
	if failed > 0 {
		return r, fmt.Errorf("%d service checks failed", failed)
	}
	return r, nil
}
