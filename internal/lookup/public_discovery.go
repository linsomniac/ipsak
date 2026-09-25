package lookup

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// One discovery belongs to one task graph. Both families start together; the
// first success unlocks enrichment without canceling the other family.
type publicDiscovery struct {
	once    sync.Once
	ready   [3]chan struct{} // first success, IPv4, IPv6
	results [3]publicResult
	lookups [2]func(context.Context) (any, error)
}

type publicResult struct {
	data any
	err  error
}

func newPublicDiscovery(v4, v6 func(context.Context) (any, error)) *publicDiscovery {
	d := &publicDiscovery{lookups: [2]func(context.Context) (any, error){v4, v6}}
	for i := range d.ready {
		d.ready[i] = make(chan struct{})
	}
	return d
}

func (d *publicDiscovery) result(ctx context.Context, index int) (any, error) {
	d.once.Do(func() { go d.run(ctx) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.ready[index]:
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r := d.results[index]
	if index != 0 && r.err != nil {
		// A missing family is optional only when discovery succeeded overall.
		if _, err := d.result(ctx, 0); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, r.err
		}
		return nil, Skip(fmt.Sprintf("IPv%d discovery unavailable: %s", index*2+2, r.err))
	}
	return r.data, r.err
}

func (d *publicDiscovery) run(parent context.Context) {
	type response struct {
		index int
		publicResult
	}
	responses := make(chan response, 2)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	for i, lookup := range d.lookups {
		go func() {
			data, err := lookup(ctx)
			responses <- response{i + 1, publicResult{data, err}}
		}()
	}
	var finished [3]bool
	publish := func(index int, r publicResult) {
		d.results[index] = r
		finished[index] = true
		close(d.ready[index])
	}
	var grace <-chan time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for remaining := 2; remaining > 0; {
		var stopErr error
		select {
		case r := <-responses:
			publish(r.index, r.publicResult)
			remaining--
			if r.err == nil && !finished[0] {
				publish(0, r.publicResult)
				if remaining > 0 {
					// Preserve the overall deadline until an address is found;
					// then bound the wait for a potentially unavailable family.
					timer = time.NewTimer(2 * time.Second)
					grace = timer.C
				}
			}
		case <-parent.Done():
			stopErr = parent.Err()
		case <-grace:
			stopErr = fmt.Errorf("no response within 2s of the first public address")
		}
		if stopErr != nil {
			cancel()
			for i := 1; i <= 2; i++ {
				if !finished[i] {
					publish(i, publicResult{err: stopErr})
				}
			}
			break
		}
	}
	if !finished[0] {
		publish(0, publicResult{err: fmt.Errorf("public IP discovery failed: IPv4: %v; IPv6: %v", d.results[1].err, d.results[2].err)})
	}
}
