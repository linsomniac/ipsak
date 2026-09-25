package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/linsomniac/ipsak/internal/stream"
	"github.com/linsomniac/ipsak/internal/ui"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type streamReport struct {
	SchemaVersion int                 `json:"schema_version"`
	Command       string              `json:"command"`
	Status        string              `json:"status"`
	Local         string              `json:"local,omitempty"`
	Remote        string              `json:"remote,omitempty"`
	Output        string              `json:"output,omitempty"`
	Elapsed       float64             `json:"elapsed_seconds"`
	Stream        *stream.Stats       `json:"stream,omitempty"`
	Server        *stream.ServerStats `json:"server,omitempty"`
	Error         string              `json:"error,omitempty"`
}

type optionalDurationValue struct{ value *time.Duration }

func (v optionalDurationValue) String() string { return v.value.String() }
func (v optionalDurationValue) Type() string   { return "duration" }
func (v optionalDurationValue) Set(s string) error {
	if n, err := strconv.ParseFloat(s, 64); err == nil && n == 0 {
		*v.value = 0
		return nil
	}
	if n, err := time.ParseDuration(s); err == nil && n == 0 {
		*v.value = 0
		return nil
	}
	return (durationValue{v.value}).Set(s)
}
func sessionContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout > 0 {
		return context.WithTimeout(parent, timeout)
	}
	return context.WithCancel(parent)
}

func addStreamCommands(root *cobra.Command, c *config) {
	for _, name := range []string{"connect", "listen"} {
		addRawCommand(root, c, name)
	}
	for _, name := range []string{"send", "receive"} {
		addTransferCommand(root, c, name)
	}
	addServeCommand(root, c)
}

func streamReady(cmd *cobra.Command, name string) func(string) error {
	return func(address string) error {
		_, err := fmt.Fprintf(cmd.ErrOrStderr(), "%s listening on %s\n", name, ui.Clean(address))
		return err
	}
}

func finishStream(cmd *cobra.Command, c config, report streamReport, started time.Time, err error) error {
	if cmd.Context().Err() != nil {
		err = cmd.Context().Err()
	}
	report.Elapsed = time.Since(started).Seconds()
	report.Status = "ok"
	if err != nil {
		report.Status = "error"
		report.Error = err.Error()
	}
	if errors.Is(cmd.Context().Err(), context.Canceled) {
		report.Status = "interrupted"
		report.Error = "interrupted"
		err = cmd.Context().Err()
	}
	if c.json {
		if writeErr := writeJSON(cmd.OutOrStdout(), report); writeErr != nil {
			return writeErr
		}
	} else if report.Stream != nil {
		_, writeErr := fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s · sent %d bytes · received %d bytes\n", report.Command, report.Status, report.Stream.Sent, report.Stream.Received)
		if writeErr != nil {
			return writeErr
		}
		if report.Stream.Verified {
			if _, writeErr = fmt.Fprintf(cmd.ErrOrStderr(), "SHA-256 %s · verified%s\n", report.Stream.SHA256, map[bool]string{true: " and committed", false: ""}[report.Stream.Committed]); writeErr != nil {
				return writeErr
			}
		}
	} else if report.Server != nil {
		_, writeErr := fmt.Fprintf(cmd.ErrOrStderr(), "serve: %s · %d requests · %d rejected · %d errors\n", report.Status, report.Server.Requests, report.Server.Rejected, report.Server.Errors)
		if writeErr != nil {
			return writeErr
		}
	}
	if errors.Is(cmd.Context().Err(), context.Canceled) {
		return &ExitError{130, report.Command + " interrupted"}
	}
	if err != nil {
		return &ExitError{1, err.Error()}
	}
	return nil
}

func addRawCommand(root *cobra.Command, c *config, name string) {
	var output string
	var force bool
	var timeout time.Duration
	cmd := &cobra.Command{Use: name + " <host:port>", Short: "Exchange raw TCP bytes through stdin and stdout", Args: cobra.ExactArgs(1)}
	if name == "listen" {
		cmd.Use = "listen [port|address]"
		cmd.Short = "Accept one raw TCP session (default loopback:9000)"
		cmd.Args = cobra.MaximumNArgs(1)
	}
	cmd.Long = cmd.Short + ".\n\nTCP only. EOF on stdin half-closes writes and drains the peer response.\nBoth TCP halves finish independently; --timeout optionally bounds the session.\nConnections have a 10s dial deadline; sessions otherwise run until EOF or Ctrl-C.\nPayload stays on stdout; metadata uses stderr. --json requires --output."
	cmd.Flags().VarP(optionalDurationValue{&timeout}, "timeout", "T", "Overall session deadline (seconds or Go duration; 0: unlimited)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Capture received bytes atomically in this file")
	cmd.Flags().BoolVar(&force, "force", false, "Replace an existing output file on successful completion")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if c.json && (output == "" || output == "-") {
			return fmt.Errorf("--json requires --output FILE so payload never shares stdout with JSON")
		}
		if output == "-" {
			return fmt.Errorf("omit --output to write raw bytes to stdout")
		}
		if force && output == "" {
			return fmt.Errorf("--force requires --output FILE")
		}
		endpoint := stream.Endpoint{}
		if name == "connect" {
			endpoint.Connect = args[0]
		} else {
			endpoint.Listen = "9000"
			if len(args) > 0 {
				endpoint.Listen = args[0]
			}
		}
		if err := endpoint.Validate(); err != nil {
			return err
		}
		started := time.Now()
		report := streamReport{SchemaVersion: 1, Command: name, Output: output}
		if cmd.Context().Err() != nil {
			return finishStream(cmd, *c, report, started, cmd.Context().Err())
		}
		var capture *stream.Output
		writer := cmd.OutOrStdout()
		if output != "" {
			var err error
			capture, err = stream.NewOutput(output, force)
			if err != nil {
				return finishStream(cmd, *c, report, started, err)
			}
			defer capture.Abort()
			writer = capture.File
		}
		ctx, cancel := sessionContext(cmd.Context(), timeout)
		defer cancel()
		conn, err := stream.Open(ctx, endpoint, streamReady(cmd, name))
		if err != nil {
			return finishStream(cmd, *c, report, started, err)
		}
		report.Local = conn.LocalAddr().String()
		report.Remote = conn.RemoteAddr().String()
		stats, err := stream.Duplex(ctx, conn, cmd.InOrStdin(), writer)
		_ = conn.Close()
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err == nil && capture != nil {
			err = capture.Commit()
			stats.Committed = err == nil
		}
		report.Stream = &stats
		return finishStream(cmd, *c, report, started, err)
	}
	root.AddCommand(cmd)
}

func transferProgress(cmd *cobra.Command, c config, name string) (stream.Progress, func() error) {
	f, ok := cmd.ErrOrStderr().(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) || c.plain || c.json || os.Getenv("TERM") == "dumb" {
		return nil, func() error { return nil }
	}
	last := time.Time{}
	started := time.Now()
	return func(n int64) error {
			if time.Since(last) < 200*time.Millisecond {
				return nil
			}
			last = time.Now()
			_, err := fmt.Fprintf(f, "\r%s: %d bytes · %.1f KiB/s", name, n, float64(n)/1024/max(time.Since(started).Seconds(), 0.001))
			return err
		}, func() error {
			if last.IsZero() {
				return nil
			}
			_, err := fmt.Fprintln(f)
			return err
		}
}

func addTransferCommand(root *cobra.Command, c *config, name string) {
	var endpoint stream.Endpoint
	var force bool
	var maxBytes int64
	var timeout time.Duration
	cmd := &cobra.Command{Use: name + " [file|-]", Short: "Transfer a file or standard stream with SHA-256 verification", Args: cobra.MaximumNArgs(1)}
	cmd.Long = cmd.Short + ".\n\nOmit the filename (or use -) for stdin/send or stdout/receive. Exactly one\nof --listen ADDRESS or --connect HOST:PORT is required on each peer.\nEither sender or receiver can listen. Pair with ipsak send/receive only;\nthis framed TCP protocol is unencrypted. --timeout optionally bounds the session.\nDial deadline: 10s; default session: until completion or Ctrl-C."
	cmd.Flags().VarP(optionalDurationValue{&timeout}, "timeout", "T", "Overall session deadline (seconds or Go duration; 0: unlimited)")
	cmd.Flags().StringVar(&endpoint.Listen, "listen", "", "Accept one peer at port or address (bare port binds loopback)")
	cmd.Flags().StringVar(&endpoint.Connect, "connect", "", "Connect to peer at host:port")
	if name == "receive" {
		cmd.Flags().BoolVar(&force, "force", false, "Replace an existing file only after transfer verification")
		cmd.Flags().Int64Var(&maxBytes, "max-bytes", 0, "Maximum received payload bytes (0: unlimited)")
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		filename := ""
		if len(args) > 0 && args[0] != "-" {
			filename = args[0]
		}
		if err := endpoint.Validate(); err != nil {
			return err
		}
		if maxBytes < 0 {
			return fmt.Errorf("max-bytes cannot be negative")
		}
		if name == "receive" && c.json && filename == "" {
			return fmt.Errorf("receive --json requires a filename so payload never shares stdout with JSON")
		}
		if force && filename == "" {
			return fmt.Errorf("--force requires a filename")
		}
		started := time.Now()
		report := streamReport{SchemaVersion: 1, Command: name}
		if cmd.Context().Err() != nil {
			return finishStream(cmd, *c, report, started, cmd.Context().Err())
		}
		reader := cmd.InOrStdin()
		writer := cmd.OutOrStdout()
		var capture *stream.Output
		if filename != "" {
			if name == "send" {
				// A FIFO passed as a filename must not block before the session
				// context exists. Nonblocking open also closes the Stat/Open race.
				file, err := os.OpenFile(filename, os.O_RDONLY|syscall.O_NONBLOCK, 0)
				if err != nil {
					return finishStream(cmd, *c, report, started, err)
				}
				defer file.Close()
				st, err := file.Stat()
				if err != nil {
					return finishStream(cmd, *c, report, started, err)
				}
				if !st.Mode().IsRegular() {
					return finishStream(cmd, *c, report, started, fmt.Errorf("source filename must be a regular file; use stdin for pipes"))
				}
				reader = file
			} else {
				var err error
				capture, err = stream.NewOutput(filename, force)
				if err != nil {
					return finishStream(cmd, *c, report, started, err)
				}
				defer capture.Abort()
				writer = capture.File
				report.Output = filename
			}
		}
		ctx, cancel := sessionContext(cmd.Context(), timeout)
		defer cancel()
		conn, err := stream.Open(ctx, endpoint, streamReady(cmd, name))
		if err != nil {
			return finishStream(cmd, *c, report, started, err)
		}
		report.Local = conn.LocalAddr().String()
		report.Remote = conn.RemoteAddr().String()
		progress, finishProgress := transferProgress(cmd, *c, name)
		var stats stream.Stats
		if name == "send" {
			stats, err = stream.Send(ctx, conn, reader, progress)
		} else {
			var commit func() error
			if capture != nil {
				commit = capture.Commit
			}
			stats, err = stream.Receive(ctx, conn, writer, maxBytes, commit, progress)
		}
		_ = conn.Close()
		if progressErr := finishProgress(); progressErr != nil && err == nil {
			err = progressErr
		}
		report.Stream = &stats
		return finishStream(cmd, *c, report, started, err)
	}
	root.AddCommand(cmd)
}

func addServeCommand(root *cobra.Command, c *config) {
	o := stream.ServerOptions{Status: 200, MaxBody: 65536, MaxConnections: 32}
	var duration time.Duration
	cmd := &cobra.Command{Use: "serve [port|address]", Short: "Run an HTTP diagnostic echo server (default loopback:8080)", Args: cobra.MaximumNArgs(1)}
	cmd.Long = cmd.Short + ".\n\nEchoes request metadata and base64 body, or a configured literal --body.\nNo filesystem is shared. Bind readiness goes to stderr; --json writes one\nfinal server summary to stdout on shutdown. --timeout bounds each request."
	cmd.Flags().IntVar(&o.Status, "status", 200, "HTTP response status (200–599)")
	cmd.Flags().StringVar(&o.Body, "body", "", "Literal response body instead of request echo")
	cmd.Flags().DurationVar(&o.Delay, "delay", 0, "Delay before responding (at most 1m, shorter than timeout)")
	cmd.Flags().Int64Var(&o.MaxBody, "max-body", 65536, "Maximum accepted request body bytes (0–16777216)")
	cmd.Flags().IntVar(&o.MaxConnections, "max-connections", 32, "Maximum simultaneous connections (1–1024)")
	cmd.Flags().DurationVar(&duration, "duration", 0, "Stop successfully after this duration (0: until interrupted)")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		o.Address = "8080"
		if len(args) > 0 {
			o.Address = args[0]
		}
		o.Timeout = c.timeout
		o.BodySet = cmd.Flags().Changed("body")
		if duration < 0 || duration > 24*time.Hour {
			return fmt.Errorf("duration must be between zero and 24h")
		}
		if err := o.Validate(); err != nil {
			return err
		}
		if cmd.Context().Err() != nil {
			return finishStream(cmd, *c, streamReport{SchemaVersion: 1, Command: "serve"}, time.Now(), cmd.Context().Err())
		}
		ctx := cmd.Context()
		cancel := func() {}
		if duration > 0 {
			ctx, cancel = context.WithTimeout(ctx, duration)
		}
		defer cancel()
		started := time.Now()
		stats, err := stream.Serve(ctx, o, streamReady(cmd, "serve"))
		if duration > 0 && errors.Is(err, context.DeadlineExceeded) && cmd.Context().Err() == nil {
			err = nil
		}
		return finishStream(cmd, *c, streamReport{SchemaVersion: 1, Command: "serve", Server: &stats}, started, err)
	}
	root.AddCommand(cmd)
}
