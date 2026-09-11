package ping

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type Options struct {
	Count             uint64
	Interval, Timeout time.Duration
}

func (o Options) Validate() error {
	if o.Interval < 10*time.Millisecond {
		return fmt.Errorf("interval must be at least 10ms")
	}
	if o.Timeout <= 0 || o.Timeout > time.Hour {
		return fmt.Errorf("ping timeout must be greater than zero and at most 1h")
	}
	if o.Timeout/o.Interval > 4094 {
		return fmt.Errorf("timeout/interval allows too many pending probes (maximum 4094)")
	}
	return nil
}

// Mailbox coalesces status snapshots but preserves loss transitions. A stalled
// consumer fails explicitly after 1024 transitions instead of blocking ICMP or
// growing memory forever. Normal terminal refresh drains this every 50ms.
type Mailbox struct {
	mu       sync.Mutex
	snapshot Snapshot
	events   []Transition
}

func (m *Mailbox) Publish(s Snapshot, events []Transition) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshot = s
	if len(m.events)+len(events) > 1024 {
		return fmt.Errorf("output consumer stalled: more than 1024 pending loss transitions")
	}
	m.events = append(m.events, events...)
	return nil
}
func (m *Mailbox) Drain() (Snapshot, []Transition) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, e := m.snapshot, m.events
	m.events = nil
	return s, e
}

// Run owns and closes transport. UI rendering never runs on the receive or
// scheduling goroutine. The caller waits for completion after cancellation.
func Run(ctx context.Context, transport Transport, opts Options, target, address string, box *Mailbox) Snapshot {
	start := time.Now()
	tracker := NewTracker(start, opts.Timeout)
	tracker.s.Target = target
	tracker.s.Address = address
	if err := opts.Validate(); err != nil {
		_ = transport.Close()
		tracker.Finish(start, false, err)
		s := tracker.Snapshot(start)
		_ = box.Publish(s, nil)
		return s
	}
	replies := make(chan Reply, 4096)
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
	tick := opts.Interval / 4
	if tick > 10*time.Millisecond {
		tick = 10 * time.Millisecond
	}
	if tick < time.Millisecond {
		tick = time.Millisecond
	}
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	nextSend := start
	var runErr error
	interrupted := false
	publish := func(events []Transition) {
		if err := box.Publish(tracker.Snapshot(time.Now()), events); err != nil {
			runErr = err
		}
	}
	drain := func() {
		for {
			select {
			case r := <-replies:
				tracker.Reply(r.ID, r.At)
			default:
				return
			}
		}
	}
	for {
		if ctx.Err() != nil {
			interrupted = true
			break
		}
		// Freeze the expiration cutoff before draining replies. Every reply
		// already published by this cutoff is processed before its deadline.
		cutoff := time.Now()
		drain()
		events := tracker.Advance(cutoff, true)
		now := time.Now()
		if (opts.Count == 0 || tracker.s.Sent < opts.Count) && !now.Before(nextSend) {
			id := tracker.s.Sent + 1
			if err := transport.Send(id); err != nil {
				runErr = fmt.Errorf("send ICMP: %w", err)
				publish(events)
				break
			}
			tracker.Sent(id, now)
			nextSend = now.Add(opts.Interval)
		}
		publish(events)
		if runErr != nil {
			break
		}
		if opts.Count > 0 && tracker.s.Sent == opts.Count && len(tracker.probes) == 0 {
			break
		}
		select {
		case <-ctx.Done():
			interrupted = true
		case err := <-readErrors:
			runErr = fmt.Errorf("receive ICMP: %w", err)
		case r := <-replies:
			tracker.Reply(r.ID, r.At)
		case <-ticker.C:
		}
		if interrupted || runErr != nil {
			break
		}
	}
	drain()
	events := tracker.Finish(time.Now(), interrupted, runErr)
	s := tracker.Snapshot(time.Now())
	if err := box.Publish(s, events); err != nil {
		if s.Error != "" {
			s.Error += "; "
		}
		s.Error += err.Error()
		// The final snapshot must carry the queue failure even when the final
		// loss transition itself cannot fit. Publishing no events always fits.
		_ = box.Publish(s, nil)
	}
	return s
}
