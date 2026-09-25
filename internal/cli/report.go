package cli

import (
	"context"
	"fmt"

	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/linsomniac/ipsak/internal/ui"
	"github.com/spf13/cobra"
)

// runReport keeps finite diagnostics consistent: concurrent work, stable result
// order, partial results, one JSON document, and an optional live terminal view.
func runReport(cmd *cobra.Command, c config, target string, tasks []lookup.Task) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), c.timeout)
	defer cancel()
	ch, err := lookup.Run(ctx, tasks)
	if err != nil {
		return err
	}
	r := lookup.NewReport(cmd.Name(), target, tasks)
	live, theme, width := terminal(cmd.InOrStdin(), cmd.OutOrStdout(), c)
	if live {
		r, err = ui.Info(r, ch, cancel, cmd.InOrStdin(), cmd.OutOrStdout(), theme, width)
	} else {
		for section := range ch {
			r.Apply(section)
		}
	}
	if err != nil {
		return err
	}
	if c.json {
		err = writeJSON(cmd.OutOrStdout(), r)
	} else {
		if !live {
			width = 0
		}
		_, err = fmt.Fprint(cmd.OutOrStdout(), theme.Report(r, width, 0))
	}
	if err != nil {
		return err
	}
	if ctx.Err() == context.Canceled {
		return &ExitError{130, cmd.Name() + " interrupted"}
	}
	failed := 0
	for _, section := range r.Sections {
		if section.Status == "error" {
			failed++
		}
	}
	if failed != 0 {
		return &ExitError{1, fmt.Sprintf("%d check(s) failed; partial results are shown", failed)}
	}
	// A deadline may race with a provider returning partial data without an error.
	if ctx.Err() == context.DeadlineExceeded {
		return &ExitError{1, cmd.Name() + " deadline exceeded"}
	}
	return nil
}
