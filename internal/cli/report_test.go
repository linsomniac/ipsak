package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/spf13/cobra"
)

func TestReportParallelStablePartial(t *testing.T) {
	started := make(chan string, 2)
	release := make(chan struct{})
	tasks := []lookup.Task{
		{Key: "slow", Title: "Slow", Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) {
			started <- "slow"
			select {
			case <-release:
				return map[string]int{"retained": 42}, errors.New("fixture failed")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}},
		{Key: "fast", Title: "Fast", Run: func(context.Context, map[string]lookup.Section) (any, error) {
			started <- "fast"
			return "done", nil
		}},
	}
	var out bytes.Buffer
	cmd := &cobra.Command{Use: "fixture"}
	cmd.SetContext(context.Background())
	cmd.SetIn(strings.NewReader(""))
	cmd.SetOut(&out)
	done := make(chan error, 1)
	go func() { done <- runReport(cmd, config{json: true, timeout: time.Second}, "host", tasks) }()
	for range 2 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("providers did not start concurrently")
		}
	}
	close(release)
	var exit *ExitError
	if err := <-done; !errors.As(err, &exit) || exit.Code != 1 {
		t.Fatalf("partial report exit = %v", err)
	}
	var r lookup.Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Command != "fixture" || r.SchemaVersion != 1 || len(r.Sections) != 2 || r.Sections[0].Key != "slow" || r.Sections[0].Data == nil || r.Sections[0].Status != "error" || r.Sections[1].Status != "ok" {
		t.Fatal(out.String())
	}
}

func TestReportCancellationDeadlineAndOutput(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if cancelEarly {
			cancel()
		}
		var out bytes.Buffer
		cmd := &cobra.Command{Use: "fixture"}
		cmd.SetContext(ctx)
		cmd.SetIn(strings.NewReader(""))
		cmd.SetOut(&out)
		tasks := []lookup.Task{{Key: "wait", Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) {
			<-ctx.Done()
			return "partial", ctx.Err()
		}}}
		err := runReport(cmd, config{json: true, timeout: 10 * time.Millisecond}, "", tasks)
		cancel()
		want := 1
		if cancelEarly {
			want = 130
		}
		var exit *ExitError
		if !errors.As(err, &exit) || exit.Code != want || !json.Valid(out.Bytes()) {
			t.Fatalf("canceled=%v error=%v output=%s", cancelEarly, err, &out)
		}
	}
	cmd := &cobra.Command{Use: "fixture"}
	cmd.SetContext(context.Background())
	cmd.SetOut(reportFailWriter{})
	cmd.SetIn(strings.NewReader(""))
	if err := runReport(cmd, config{json: true, timeout: time.Second}, "", nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}

type reportFailWriter struct{}

func (reportFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
