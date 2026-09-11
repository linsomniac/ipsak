package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/linsomniac/ipsak/internal/ping"
	"github.com/linsomniac/ipsak/internal/ui"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type ExitError struct {
	Code    int
	Message string
}

func (e *ExitError) Error() string { return e.Message }

type durationValue struct{ value *time.Duration }

func (d durationValue) String() string { return d.value.String() }
func (d durationValue) Type() string   { return "duration" }
func (d durationValue) Set(s string) error {
	if seconds, err := strconv.ParseFloat(s, 64); err == nil {
		if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 || seconds > 86400 {
			return fmt.Errorf("duration in seconds must be greater than zero and at most 86400")
		}
		*d.value = time.Duration(seconds * float64(time.Second))
		if *d.value <= 0 {
			return fmt.Errorf("duration is too small")
		}
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	if v <= 0 || v > 24*time.Hour {
		return fmt.Errorf("duration must be greater than zero and at most 24h")
	}
	*d.value = v
	return nil
}

type config struct {
	json, plain, noColor bool
	timeout              time.Duration
}

func terminal(in io.Reader, out io.Writer, c config) (bool, ui.Theme, int) {
	stdin, iok := in.(*os.File)
	stdout, ook := out.(*os.File)
	interactive := iok && ook && term.IsTerminal(int(stdin.Fd())) && term.IsTerminal(int(stdout.Fd())) && os.Getenv("TERM") != "dumb" && !c.plain && !c.json
	width := 80
	if ook {
		if w, _, err := term.GetSize(int(stdout.Fd())); err == nil && w > 0 {
			width = w
		}
	}
	_, noColor := os.LookupEnv("NO_COLOR")
	return interactive, ui.Theme{Color: interactive && !c.noColor && !noColor}, width
}
func writeJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func New(version string) *cobra.Command {
	return newCommand(version, func(ip netip.Addr) (ping.SweepTransport, error) { return ping.OpenSweep(ip) })
}

func newCommand(version string, openSweep func(netip.Addr) (ping.SweepTransport, error)) *cobra.Command {
	c := config{timeout: 10 * time.Second}
	root := &cobra.Command{Use: "ipsak", Short: "A little clarity for your network.", Long: "ipsak — the IP Swiss Army Knife\n\nExplore an address, inspect DNS, or watch a connection breathe.\n\n  ipsak info 8.8.8.8\n  ipsak ping example.com\n  ipsak calc 2001:db8::/64", Version: version, SilenceUsage: true, SilenceErrors: true, Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return fmt.Errorf("use an explicit subcommand: ipsak info %s", ui.Clean(args[0]))
		}
		return nil
	}, RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() }}
	root.SetVersionTemplate("ipsak {{.Version}}\n")
	root.Flags().BoolP("version", "V", false, "Show version")
	root.PersistentFlags().BoolVarP(&c.json, "json", "j", false, "Write one final JSON document")
	root.PersistentFlags().BoolVar(&c.plain, "plain", false, "Use plain text without live updates")
	root.PersistentFlags().BoolVar(&c.noColor, "no-color", false, "Disable terminal colors")
	root.PersistentFlags().VarP(durationValue{&c.timeout}, "timeout", "T", "Overall lookup deadline, or ping reply timeout (seconds or Go duration)")
	for _, spec := range []struct{ name, use, help string }{{"info", "info <ip|cidr|domain>", "Explore DNS, ASN, registration, location, routes and reputation"}, {"dns", "dns <ip|domain>", "Inspect DNS records or reverse DNS"}, {"whois", "whois <ip|domain>", "Look up registration through RDAP"}, {"calc", "calc <cidr>", "Calculate IPv4 and IPv6 subnet ranges instantly"}, {"trace", "trace <ip|domain>", "Follow the network path with the system traceroute"}, {"myip", "myip", "Discover local interfaces and explore your public IP"}} {
		opts := lookup.Options{Probes: 3}
		spec := spec
		cmd := &cobra.Command{Use: spec.use, Short: spec.help, Args: cobra.ExactArgs(1)}
		if spec.name == "myip" {
			cmd.Args = cobra.NoArgs
		}
		if spec.name == "info" {
			cmd.Flags().BoolVarP(&opts.Trace, "trace", "t", false, "Include traceroute")
		}
		if spec.name == "trace" || spec.name == "info" {
			cmd.Flags().IntVarP(&opts.Probes, "probes", "q", 3, "Probes per traceroute hop (1–10)")
			cmd.Flags().BoolVarP(&opts.TraceASN, "asn", "a", false, "Look up ASN for traceroute hops")
		}
		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			if opts.Probes < 1 || opts.Probes > 10 {
				return fmt.Errorf("probes must be between 1 and 10")
			}
			var target lookup.Target
			var err error
			if len(args) > 0 {
				target, err = lookup.ParseTarget(args[0])
				if err != nil {
					return err
				}
			}
			service := lookup.NewService()
			tasks, err := service.Tasks(spec.name, target, opts)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), c.timeout)
			defer cancel()
			ch, err := lookup.Run(ctx, tasks)
			if err != nil {
				return err
			}
			r := lookup.NewReport(spec.name, target.Name, tasks)
			live, theme, width := terminal(cmd.InOrStdin(), cmd.OutOrStdout(), c)
			if live {
				r, err = ui.Info(r, ch, cancel, cmd.InOrStdin(), cmd.OutOrStdout(), theme, width)
			} else {
				for s := range ch {
					r.Apply(s)
				}
			}
			if err != nil {
				return err
			}
			if c.json {
				if err = writeJSON(cmd.OutOrStdout(), r); err != nil {
					return err
				}
			} else {
				if !live {
					width = 0
				}
				if _, err = fmt.Fprint(cmd.OutOrStdout(), theme.Report(r, width, 0)); err != nil {
					return err
				}
			}
			if ctx.Err() == context.Canceled {
				return &ExitError{130, "lookup interrupted"}
			}
			failed := 0
			for _, s := range r.Sections {
				if s.Status == "error" {
					failed++
				}
			}
			if failed > 0 {
				return &ExitError{1, fmt.Sprintf("%d lookup(s) failed; partial results are shown", failed)}
			}
			return nil
		}
		root.AddCommand(cmd)
	}
	var count uint64
	interval := time.Second
	pingTimeout := time.Second
	var ipv4, ipv6 bool
	var duration time.Duration
	var rate, maxHosts int
	var all bool
	pc := &cobra.Command{Use: "ping <ip|cidr|domain>", Short: "Watch a connection or discover a network's ping responders", Long: "Watch one connection continuously, or sweep every address in a CIDR.\n\nCIDRs default to 3 probes per address, paced at up to 100 packets/second.\nAll addresses are included, including network endpoints. No reply does not\nnecessarily mean an address is down. Use --all to include silent addresses.\n\n  ipsak ping 192.168.1.0/24\n  ipsak ping 192.168.1.0/24 -c 1\n  ipsak ping 192.168.1.0/24 -c 0 --duration 1m", Args: cobra.ExactArgs(1)}
	pc.Flags().Uint64VarP(&count, "count", "c", 0, "Probes per address (host default: continuous; CIDR: 3; 0: continuous)")
	pc.Flags().VarP(durationValue{&interval}, "interval", "i", "Minimum time between probes to each address (minimum 10ms)")
	pc.Flags().IntVar(&rate, "rate", 100, "CIDR only: maximum packets per second across all addresses (1–1000)")
	pc.Flags().IntVar(&maxHosts, "max-hosts", 4096, "CIDR only: address limit (1–65536)")
	pc.Flags().BoolVar(&all, "all", false, "CIDR only: also list addresses with no replies in the final report")
	pc.Flags().VarP(durationValue{&pingTimeout}, "timeout", "T", "Per-probe reply timeout (seconds or Go duration)")
	pc.Flags().DurationVar(&duration, "duration", 0, "Stop after this elapsed time (for example 5m)")
	pc.Flags().BoolVarP(&ipv4, "ipv4", "4", false, "Use IPv4")
	pc.Flags().BoolVarP(&ipv6, "ipv6", "6", false, "Use IPv6")
	pc.RunE = func(cmd *cobra.Command, args []string) error {
		if cmd.Context().Err() != nil {
			return &ExitError{130, "ping interrupted"}
		}
		if ipv4 && ipv6 {
			return fmt.Errorf("choose only one of -4 and -6")
		}
		if duration < 0 {
			return fmt.Errorf("duration cannot be negative")
		}
		timeout := pingTimeout
		opts := ping.Options{Count: count, Interval: interval, Timeout: timeout}
		t, err := lookup.ParseTarget(args[0])
		if err != nil {
			return err
		}
		if t.Prefix.IsValid() {
			if ipv4 && !t.IP.Is4() || ipv6 && !t.IP.Is6() {
				return fmt.Errorf("target does not match requested address family")
			}
			sweepCount := count
			if !cmd.Flags().Changed("count") {
				sweepCount = 3
			}
			return runSweepCommand(cmd, c, t.Prefix, ping.SweepOptions{Count: sweepCount, Interval: interval, Timeout: timeout, Rate: rate, MaxHosts: maxHosts}, duration, all, openSweep)
		}
		for _, name := range []string{"rate", "max-hosts", "all"} {
			if cmd.Flags().Changed(name) {
				return fmt.Errorf("--%s requires a CIDR target", name)
			}
		}
		if err := opts.Validate(); err != nil {
			return err
		}
		family := "ip"
		if ipv4 {
			family = "ip4"
		}
		if ipv6 {
			family = "ip6"
		}
		resolveCtx, resolveCancel := context.WithTimeout(cmd.Context(), 10*time.Second)
		t, err = lookup.Resolve(resolveCtx, t, family)
		resolveCancel()
		if err != nil {
			if cmd.Context().Err() != nil {
				return &ExitError{130, "ping interrupted"}
			}
			return err
		}
		if t.IP.IsMulticast() || t.IP.IsUnspecified() || t.Class == "Limited broadcast" {
			return fmt.Errorf("ping requires a unicast destination")
		}
		transport, err := ping.Open(t.IP)
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
		box := &ping.Mailbox{}
		done := make(chan ping.Snapshot, 1)
		go func() { done <- ping.Run(ctx, transport, opts, t.Name, t.IP.String(), box) }()
		live, theme, width := terminal(cmd.InOrStdin(), cmd.OutOrStdout(), c)
		if !c.json {
			controls := "Ctrl-C to stop"
			if live {
				controls = "q / Ctrl-C to stop"
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\n%s\n\n", theme.Heading("ipsak  /  PING  ·  "+ui.Clean(t.Name)), theme.Muted(ui.Clean(fmt.Sprintf("%s · every %s · timeout %s · %s", t.IP, interval, timeout, controls))))
			if err != nil {
				cancel()
				<-done
				return err
			}
		}
		if live {
			err = ui.Ping(box, cancel, cmd.InOrStdin(), cmd.OutOrStdout(), theme, width)
		} else {
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()
			for {
				<-ticker.C
				s, events := box.Drain()
				if !c.json {
					for _, e := range events {
						if e.Kind == "start" {
							_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s  Loss started at id %d\n", e.Loss.Started.Local().Format("15:04:05"), e.Loss.First)
						} else {
							_, err = fmt.Fprintln(cmd.OutOrStdout(), ping.LossText(e.Loss))
						}
						if err != nil {
							break
						}
					}
				}
				if s.Done || err != nil {
					break
				}
			}
		}
		cancel()
		s := <-done
		if err != nil {
			return err
		}
		if c.json {
			err = writeJSON(cmd.OutOrStdout(), struct {
				SchemaVersion int           `json:"schema_version"`
				Command       string        `json:"command"`
				Ping          ping.Snapshot `json:"ping"`
			}{1, "ping", s})
		} else {
			_, err = fmt.Fprint(cmd.OutOrStdout(), theme.PingSummary(s))
		}
		if err != nil {
			return err
		}
		if s.Error != "" {
			return &ExitError{2, s.Error}
		}
		if s.Interrupted && ctx.Err() != context.DeadlineExceeded {
			return &ExitError{130, "ping interrupted"}
		}
		if s.Lost > 0 || s.Received == 0 {
			return &ExitError{1, "packet loss or no replies received"}
		}
		return nil
	}
	root.AddCommand(pc)
	return root
}

func Execute(ctx context.Context, args []string, in io.Reader, out, stderr io.Writer, version string) int {
	cmd := New(version)
	cmd.SetArgs(args)
	cmd.SetIn(in)
	cmd.SetOut(out)
	cmd.SetErr(stderr)
	if err := cmd.ExecuteContext(ctx); err != nil {
		code := 2
		var exit *ExitError
		if errors.As(err, &exit) {
			code = exit.Code
		}
		fmt.Fprintln(stderr, "ipsak:", ui.Clean(err.Error()))
		return code
	}
	return 0
}
