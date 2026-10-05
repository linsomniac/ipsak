package pathwatch

import (
	"context"
	"fmt"
	"net/netip"
	"time"
)

type Options struct {
	Hops, Count                 int
	Interval, Timeout, Duration time.Duration
}

func (o Options) Validate() error {
	if o.Hops < 1 || o.Hops > 64 || o.Count < 0 || o.Count > 1000000 || o.Interval < 100*time.Millisecond || o.Interval > time.Hour || o.Timeout <= 0 || o.Timeout > time.Minute || o.Duration < 0 || o.Duration > 24*time.Hour {
		return fmt.Errorf("require hops 1–64, count 0–1000000, interval 100ms–1h, timeout (0,1m], duration 0–24h")
	}
	return nil
}

type Hop struct {
	TTL            int      `json:"ttl"`
	Sent           uint64   `json:"sent"`
	Replies        uint64   `json:"replies"`
	Timeouts       uint64   `json:"timeouts"`
	Pending        uint64   `json:"pending"`
	Errors         uint64   `json:"errors"`
	Echoes         uint64   `json:"echoes"`
	LastStatus     string   `json:"last_status"`
	LastSource     string   `json:"last_source,omitempty"`
	Sources        []string `json:"sources"`
	SourcesOmitted uint64   `json:"sources_omitted"`
	Changes        uint64   `json:"changes"`
	LastMS         float64  `json:"last_ms"`
	MeanMS         float64  `json:"mean_ms"`
	Error          string   `json:"error,omitempty"`
}
type Change struct {
	TTL  int       `json:"ttl"`
	From string    `json:"from"`
	To   string    `json:"to"`
	At   time.Time `json:"at"`
}
type Result struct {
	Address        string    `json:"address"`
	Started        time.Time `json:"started"`
	ElapsedMS      int64     `json:"elapsed_ms"`
	Rounds         int       `json:"rounds"`
	Status         string    `json:"status"`
	ReachedTTL     int       `json:"reached_ttl,omitempty"`
	Hops           []Hop     `json:"hops"`
	Destination    Hop       `json:"destination"`
	Changes        []Change  `json:"changes"`
	ChangesDropped uint64    `json:"changes_dropped"`
}

func (r Result) clone() Result {
	r.Hops = append([]Hop(nil), r.Hops...)
	for i := range r.Hops {
		r.Hops[i].Sources = append([]string(nil), r.Hops[i].Sources...)
	}
	r.Destination.Sources = append([]string(nil), r.Destination.Sources...)
	r.Changes = append([]Change(nil), r.Changes...)
	return r
}
func (r Result) CompactLines() []string {
	d := r.Destination
	lines := []string{r.Address + " · " + r.Status, fmt.Sprintf("Destination: %d/%d echoes · %d timeouts · %.2f ms", d.Echoes, d.Sent, d.Timeouts, d.LastMS), "Hop responses do not measure forwarded packet loss.", "TTL  LAST / AVG ms    REPLIES/SENT  SOURCE"}
	for _, h := range r.Hops {
		if r.ReachedTTL > 0 && h.TTL > r.ReachedTTL {
			break
		}
		s := h.LastSource
		if s == "" {
			s = h.LastStatus
		}
		lines = append(lines, fmt.Sprintf("%3d  %6.2f / %6.2f  %d/%d  %s", h.TTL, h.LastMS, h.MeanMS, h.Replies, h.Sent, s))
		if h.Error != "" {
			lines = append(lines, "     "+h.Error)
		}
	}
	return lines
}

type MeasureFunc func(context.Context, netip.Addr, int, time.Duration) ([]Probe, error)

func Run(ctx context.Context, ip netip.Addr, o Options, measure MeasureFunc, emit func(Result)) (Result, error) {
	if err := o.Validate(); err != nil {
		return Result{}, err
	}
	r := Result{Address: ip.String(), Started: time.Now().UTC(), Status: "running", Hops: make([]Hop, o.Hops), Changes: []Change{}, Destination: Hop{TTL: 255, Sources: []string{}}}
	if measure == nil {
		measure = Measure
	}
	for i := range r.Hops {
		r.Hops[i] = Hop{TTL: i + 1, LastStatus: "unprobed", Sources: []string{}}
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
	for o.Count == 0 || r.Rounds < o.Count {
		if work.Err() != nil {
			break
		}
		start := time.Now()
		r.Rounds++
		probes, err := measure(work, ip, o.Hops, o.Timeout)
		r.ReachedTTL = 0
		for i, p := range probes {
			if i > o.Hops {
				break
			}
			var h *Hop
			if i == o.Hops {
				h = &r.Destination
			} else {
				h = &r.Hops[i]
			}
			h.LastStatus = p.Status
			h.Error = p.Error
			if p.Sent {
				h.Sent++
			}
			switch p.Status {
			case "pending":
				h.Pending++
			case "timeout":
				h.Timeouts++
			case "send_error":
				h.Errors++
			default:
				if !p.Sent {
					continue
				}
				h.Replies++
				h.LastMS = p.RTTMS
				h.MeanMS += (p.RTTMS - h.MeanMS) / float64(h.Replies)
				if p.Status == "echo" {
					h.Echoes++
					if i < o.Hops && (r.ReachedTTL == 0 || p.TTL < r.ReachedTTL) {
						r.ReachedTTL = p.TTL
					}
				}
				if h.LastSource != "" && p.Source != h.LastSource {
					h.Changes++
					if len(r.Changes) == 128 {
						copy(r.Changes, r.Changes[1:])
						r.Changes = r.Changes[:127]
						r.ChangesDropped++
					}
					r.Changes = append(r.Changes, Change{p.TTL, h.LastSource, p.Source, time.Now().UTC()})
				}
				h.LastSource = p.Source
				found := false
				for _, s := range h.Sources {
					if s == p.Source {
						found = true
					}
				}
				if !found {
					if len(h.Sources) < 8 {
						h.Sources = append(h.Sources, p.Source)
					} else {
						h.SourcesOmitted++
					}
				}
			}
		}
		update()
		if err != nil {
			if work.Err() != nil {
				break
			}
			r.Status = "failed"
			return r, err
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
	d := r.Destination
	if d.Echoes == 0 || d.Timeouts > 0 || d.Errors > 0 || d.Replies > d.Echoes {
		return r, fmt.Errorf("destination checks failed or no destination echo was received")
	}
	return r, nil
}
