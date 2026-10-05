package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/linsomniac/ipsak/internal/ui"
	"github.com/spf13/cobra"
)

// runSession retains one immutable snapshot. A slow terminal cannot hold up
// probes; the last snapshot is always published before the channel is closed.
// The engine owns planned duration limits; cancel here means user interruption.
func runSession(cmd *cobra.Command, c config, target, title string, run func(context.Context, func(any)) (any, error)) error {
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	key := cmd.Name()
	r := lookup.NewReport(key, target, []lookup.Task{{Key: key, Title: title}})
	updates := make(chan lookup.Section, 1)
	done := make(chan error, 1)
	publish := func(s lookup.Section) {
		select {
		case updates <- s:
			return
		default:
		}
		select {
		case <-updates:
		default:
		}
		updates <- s // Only this worker publishes; the buffer now has room.
	}
	go func() {
		data, err := run(ctx, func(data any) {
			publish(lookup.Section{Key: key, Title: title, Status: "ok", Data: data})
		})
		s := lookup.Section{Key: key, Title: title, Status: "ok", Data: data}
		if err != nil {
			s.Status, s.Error = "error", err.Error()
		}
		publish(s)
		done <- err
		close(updates)
	}()
	live, theme, width := terminal(cmd.InOrStdin(), cmd.OutOrStdout(), c)
	var outputErr error
	if live {
		r, outputErr = ui.Info(r, updates, cancel, cmd.InOrStdin(), cmd.OutOrStdout(), theme, width)
	} else {
		for s := range updates {
			r.Apply(s)
		}
	}
	runErr := <-done
	if outputErr != nil {
		return outputErr
	}
	if c.json {
		outputErr = writeJSON(cmd.OutOrStdout(), r)
	} else {
		if !live {
			width = 0
		}
		_, outputErr = fmt.Fprint(cmd.OutOrStdout(), theme.Report(r, width, 0))
	}
	if outputErr != nil {
		return outputErr
	}
	if ctx.Err() == context.Canceled {
		return &ExitError{130, key + " interrupted"}
	}
	if runErr != nil {
		var code *ExitError
		if errors.As(runErr, &code) {
			return code
		}
		return &ExitError{1, runErr.Error()}
	}
	return nil
}
