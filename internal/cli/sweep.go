package cli

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/linsomniac/ipsak/internal/ping"
	"github.com/linsomniac/ipsak/internal/ui"
	"github.com/spf13/cobra"
)

func runSweepCommand(cmd *cobra.Command, c config, prefix netip.Prefix, opts ping.SweepOptions, duration time.Duration, all bool, open func(netip.Addr) (ping.SweepTransport, error)) error {
	prefix, n, err := ping.SweepRange(prefix, opts)
	if err != nil {
		return err
	}
	if cmd.Context().Err() != nil {
		return &ExitError{130, "ping interrupted"}
	}
	live, theme, width := terminal(cmd.InOrStdin(), cmd.OutOrStdout(), c)
	if !c.json {
		count := fmt.Sprintf("%d attempts/address", opts.Count)
		if opts.Count == 0 {
			count = "continuous"
		}
		controls := "Ctrl-C to stop"
		if live {
			controls = "q / Esc / Ctrl-C to stop"
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\n%s\n%s\n\n", theme.Heading("ipsak  /  PING SWEEP  ·  "+prefix.String()), fmt.Sprintf("%d addresses · %s · up to %d packets/s", n, count, opts.Rate), theme.Muted(fmt.Sprintf("every %s/address or slower · timeout %s · %s", opts.Interval, opts.Timeout, controls)))
		if err != nil {
			return err
		}
	}
	transport, err := open(prefix.Addr())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	if duration > 0 {
		var deadlineCancel context.CancelFunc
		ctx, deadlineCancel = context.WithTimeout(ctx, duration)
		defer deadlineCancel()
	}
	box := &ping.SweepMailbox{}
	done := make(chan ping.SweepSnapshot, 1)
	go func() { done <- ping.RunSweep(ctx, transport, prefix, opts, box) }()
	var s ping.SweepSnapshot
	if live {
		err = ui.Sweep(box, cancel, cmd.InOrStdin(), cmd.OutOrStdout(), theme, width)
		cancel()
		s = <-done
	} else {
		s = <-done
		width = 0
	}
	if err != nil {
		return err
	}
	if c.json {
		err = writeJSON(cmd.OutOrStdout(), struct {
			SchemaVersion int                `json:"schema_version"`
			Command       string             `json:"command"`
			Sweep         ping.SweepSnapshot `json:"sweep"`
		}{1, "ping", s})
	} else {
		if live {
			_, _, width = terminal(cmd.InOrStdin(), cmd.OutOrStdout(), c)
		}
		_, err = fmt.Fprint(cmd.OutOrStdout(), theme.SweepSummary(s, all, width))
	}
	if err != nil {
		return err
	}
	if s.Error != "" {
		return &ExitError{2, s.Error}
	}
	if s.StopReason == "interrupted" {
		return &ExitError{130, "ping sweep interrupted"}
	}
	if s.Responded == 0 {
		if s.SendErrors > 0 {
			return &ExitError{2, "no replies received; some probes could not be sent"}
		}
		return &ExitError{1, "no ICMP replies received"}
	}
	return nil
}
