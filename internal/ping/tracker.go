// Package ping implements ordered ICMP accounting independently of terminal rendering.
package ping

import (
	"fmt"
	"time"
)

type Loss struct {
	First     uint64     `json:"first_id"`
	Last      uint64     `json:"last_id"`
	Count     uint64     `json:"count"`
	Started   time.Time  `json:"started"`
	Ended     *time.Time `json:"ended,omitempty"`
	Recovered bool       `json:"recovered"`
}

type Transition struct {
	Kind string
	Loss Loss
}

type Snapshot struct {
	Target         string    `json:"target"`
	Address        string    `json:"address"`
	Sent           uint64    `json:"sent"`
	Received       uint64    `json:"received"`
	Lost           uint64    `json:"lost"`
	Pending        uint64    `json:"pending"`
	Late           uint64    `json:"late"`
	LossPercent    float64   `json:"loss_percent"`
	LastMS         float64   `json:"last_ms"`
	MinMS          float64   `json:"min_ms"`
	AvgMS          float64   `json:"avg_ms"`
	MaxMS          float64   `json:"max_ms"`
	ElapsedSeconds float64   `json:"elapsed_seconds"`
	LossEvents     uint64    `json:"loss_events"`
	RecentLosses   []Loss    `json:"recent_losses"`
	ActiveLoss     *Loss     `json:"active_loss,omitempty"`
	History        []float64 `json:"-"`
	Done           bool      `json:"done"`
	Interrupted    bool      `json:"interrupted"`
	Error          string    `json:"error,omitempty"`
}

type probe struct {
	sent  time.Time
	reply time.Time
}
type settled struct {
	sent time.Time
	late bool
	lost bool
}

type Tracker struct {
	timeout time.Duration
	start   time.Time
	next    uint64
	probes  map[uint64]*probe
	settled map[uint64]settled
	s       Snapshot
	sumMS   float64
}

func NewTracker(start time.Time, timeout time.Duration) *Tracker {
	return &Tracker{timeout: timeout, start: start, next: 1, probes: map[uint64]*probe{}, settled: map[uint64]settled{}, s: Snapshot{RecentLosses: []Loss{}, History: []float64{}}}
}
func (t *Tracker) Sent(id uint64, at time.Time) { t.probes[id] = &probe{sent: at}; t.s.Sent++ }

// Reply uses the receive timestamp, not the time at which a consumer processed
// the reply. A finalized deadline is never rewritten by a late packet.
func (t *Tracker) Reply(id uint64, at time.Time) bool {
	p, ok := t.probes[id]
	if !ok {
		if s, ok := t.settled[id]; ok && s.lost && !s.late {
			s.late = true
			t.settled[id] = s
			t.s.Late++
		}
		return false
	}
	if !p.reply.IsZero() || at.Before(p.sent) {
		return false
	}
	if at.After(p.sent.Add(t.timeout)) {
		if s, ok := t.settled[id]; !ok || !s.late {
			t.s.Late++
			t.settled[id] = settled{sent: p.sent, late: true}
		}
		return false
	}
	p.reply = at
	t.s.Received++
	rtt := float64(at.Sub(p.sent)) / float64(time.Millisecond)
	t.s.LastMS = rtt
	t.sumMS += rtt
	t.s.AvgMS = t.sumMS / float64(t.s.Received)
	if t.s.Received == 1 || rtt < t.s.MinMS {
		t.s.MinMS = rtt
	}
	if rtt > t.s.MaxMS {
		t.s.MaxMS = rtt
	}
	return true
}

// Advance commits outcomes in send order, keeping contiguous losses together
// even when later successful probes arrive first.
func (t *Tracker) Advance(now time.Time, expire bool) []Transition {
	var events []Transition
	for {
		p, ok := t.probes[t.next]
		if !ok {
			break
		}
		lost := p.reply.IsZero()
		if lost && (!expire || now.Before(p.sent.Add(t.timeout))) {
			break
		}
		id := t.next
		if lost {
			t.s.Lost++
			if t.s.ActiveLoss == nil {
				t.s.LossEvents++
				t.s.ActiveLoss = &Loss{First: id, Last: id, Count: 1, Started: p.sent}
				events = append(events, Transition{Kind: "start", Loss: *t.s.ActiveLoss})
			} else {
				t.s.ActiveLoss.Last = id
				t.s.ActiveLoss.Count++
			}
			t.s.History = append(t.s.History, -1)
		} else {
			if t.s.ActiveLoss != nil {
				loss := *t.s.ActiveLoss
				end := p.reply
				loss.Ended = &end
				loss.Recovered = true
				t.remember(loss)
				events = append(events, Transition{Kind: "end", Loss: loss})
				t.s.ActiveLoss = nil
			}
			t.s.History = append(t.s.History, float64(p.reply.Sub(p.sent))/float64(time.Millisecond))
		}
		if len(t.s.History) > 40 {
			t.s.History = t.s.History[len(t.s.History)-40:]
		}
		old := t.settled[id]
		old.sent = p.sent
		old.lost = lost
		t.settled[id] = old
		if id > 1024 {
			delete(t.settled, id-1024)
		}
		delete(t.probes, id)
		t.next++
	}
	return events
}
func (t *Tracker) remember(l Loss) {
	t.s.RecentLosses = append(t.s.RecentLosses, l)
	if len(t.s.RecentLosses) > 128 {
		t.s.RecentLosses = t.s.RecentLosses[len(t.s.RecentLosses)-128:]
	}
}
func (t *Tracker) Finish(now time.Time, interrupted bool, err error) []Transition {
	events := t.Advance(now, false)
	if t.s.ActiveLoss != nil {
		loss := *t.s.ActiveLoss
		loss.Ended = &now
		t.remember(loss)
		events = append(events, Transition{Kind: "end", Loss: loss})
		t.s.ActiveLoss = nil
	}
	t.s.Done = true
	t.s.Interrupted = interrupted
	if err != nil {
		t.s.Error = err.Error()
	}
	return events
}
func (t *Tracker) Snapshot(now time.Time) Snapshot {
	s := t.s
	s.Pending = s.Sent - s.Received - s.Lost
	s.ElapsedSeconds = now.Sub(t.start).Seconds()
	if s.Sent > 0 {
		s.LossPercent = 100 * float64(s.Lost) / float64(s.Sent)
	}
	s.History = append([]float64{}, s.History...)
	s.RecentLosses = append([]Loss{}, s.RecentLosses...)
	if s.ActiveLoss != nil {
		l := *s.ActiveLoss
		s.ActiveLoss = &l
	}
	return s
}

func LossText(l Loss) string {
	ending := " · ongoing"
	if l.Ended != nil {
		ending = " · ended without recovery"
		if l.Recovered {
			ending = " · recovered"
		}
	}
	return fmt.Sprintf("Lost %d packets, ids %d–%d%s", l.Count, l.First, l.Last, ending)
}
