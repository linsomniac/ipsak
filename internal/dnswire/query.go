// Package dnswire supplies deadline- and cancellation-aware DNS exchanges.
package dnswire

import (
	"context"
	"github.com/miekg/dns"
	"time"
)

// Exchange retries a truncated UDP response over TCP within the same context.
func Exchange(ctx context.Context, q *dns.Msg, server string) (*dns.Msg, error) {
	r, err := once(ctx, q, server, "udp")
	if err == nil && r.Truncated {
		return once(ctx, q, server, "tcp")
	}
	return r, err
}
func once(ctx context.Context, q *dns.Msg, server, network string) (*dns.Msg, error) {
	c := dns.Client{Net: network}
	if deadline, ok := ctx.Deadline(); ok {
		c.Timeout = time.Until(deadline)
		if c.Timeout <= 0 {
			return nil, context.DeadlineExceeded
		}
	}
	conn, err := c.DialContext(ctx, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { conn.Close(); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	r, _, err := c.ExchangeWithConnContext(ctx, q, conn)
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	return r, err
}
