package cli

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/linsomniac/ipsak/internal/bandwidth"
	"github.com/linsomniac/ipsak/internal/dnstrace"
	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/linsomniac/ipsak/internal/pathwatch"
	"github.com/linsomniac/ipsak/internal/probe"
	"github.com/linsomniac/ipsak/internal/stream"
	"github.com/linsomniac/ipsak/internal/ui"
	"github.com/linsomniac/ipsak/internal/watch"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

func addSessionCommands(root *cobra.Command, c *config) {
	addWatchCommand(root, c)
	addDNSTraceCommand(root, c)
	addBandwidthCommand(root, c)
	addPathwatchCommand(root, c)
}

func addPathwatchCommand(root *cobra.Command, c *config) {
	o := pathwatch.Options{Hops: 30, Interval: time.Second, Timeout: time.Second}
	var v4, v6 bool
	cmd := &cobra.Command{Use: "pathwatch <host>", Short: "Watch hop responses and destination health over time", Long: "Probe all hop limits concurrently with raw ICMP, plus a separate destination\nprobe. Intermediate silence does not measure forwarded packet loss.\nRequires CAP_NET_RAW on Linux or elevated privileges on macOS.\nUse --count or --duration for finite JSON runs. Exit 1 means a completed\ndestination probe failed, or no destination echo was received.\n\n  ipsak pathwatch example.com --count 5\n  ipsak pathwatch ::1 -6 --duration 10s --json", Args: cobra.ExactArgs(1)}
	cmd.Flags().IntVar(&o.Hops, "max-hops", 30, "Maximum traced TTL (1–64)")
	cmd.Flags().IntVarP(&o.Count, "count", "c", 0, "Rounds (0 runs until stopped)")
	cmd.Flags().Var(durationValue{&o.Interval}, "interval", "Minimum gap between rounds (100ms–1h)")
	cmd.Flags().VarP(durationValue{&o.Timeout}, "timeout", "T", "Response budget per round (at most 1m)")
	cmd.Flags().Var(optionalDurationValue{&o.Duration}, "duration", "Planned duration (0 until stopped)")
	cmd.Flags().BoolVarP(&v4, "ipv4", "4", false, "Use IPv4")
	cmd.Flags().BoolVarP(&v6, "ipv6", "6", false, "Use IPv6")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if v4 && v6 {
			return fmt.Errorf("choose only one of -4 and -6")
		}
		if err := o.Validate(); err != nil {
			return err
		}
		t, err := lookup.ParseTarget(args[0])
		if err != nil {
			return err
		}
		if t.Prefix.IsValid() {
			return fmt.Errorf("pathwatch requires one host")
		}
		if t.IP.IsValid() && (t.IP.IsMulticast() || t.IP.IsUnspecified() || t.Class == "Limited broadcast") {
			return fmt.Errorf("pathwatch requires a unicast address")
		}
		return runSession(cmd, *c, t.Name, "Network path watch", func(ctx context.Context, emit func(any)) (any, error) {
			family := "ip"
			if v4 {
				family = "ip4"
			}
			if v6 {
				family = "ip6"
			}
			resolveCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			resolved, e := lookup.Resolve(resolveCtx, t, family)
			cancel()
			if e != nil {
				return nil, e
			}
			r, e := pathwatch.Run(ctx, resolved.IP, o, nil, func(r pathwatch.Result) { emit(r) })
			var opening *pathwatch.OpenError
			if errors.As(e, &opening) {
				return r, &ExitError{2, e.Error()}
			}
			return r, e
		})
	}
	root.AddCommand(cmd)
}

func addBandwidthCommand(root *cobra.Command, c *config) {
	o := bandwidth.Options{Duration: 5 * time.Second, MaxDuration: time.Minute, Direction: "both"}
	var endpoint stream.Endpoint
	var timeout time.Duration
	cmd := &cobra.Command{Use: "bandwidth", Short: "Measure TCP throughput with a cooperating ipsak peer", Long: "Run a listener on one machine and a connector on another. Directions are\nrelative to the connector; both tests upload then download sequentially.\nThe rate uses receiver-observed payload bytes and timing, one TCP stream.\nThis diagnostic protocol is unencrypted and does not authenticate peers.\nA bare listening port binds loopback. Listener accepts one session.\n\n  ipsak bandwidth --listen 0.0.0.0:9000\n  ipsak bandwidth --connect peer:9000 --duration 5s --json", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&endpoint.Listen, "listen", "", "Accept one peer at port or address")
	cmd.Flags().StringVar(&endpoint.Connect, "connect", "", "Connect to peer host:port")
	cmd.Flags().Var(durationValue{&o.Duration}, "duration", "Requested time per direction (1ms–1m; connector)")
	cmd.Flags().Var(durationValue{&o.MaxDuration}, "max-duration", "Maximum accepted time per direction (1ms–1m; listener)")
	cmd.Flags().StringVar(&o.Direction, "direction", "both", "Connector direction: upload, download, both")
	cmd.Flags().VarP(optionalDurationValue{&timeout}, "timeout", "T", "Overall session deadline (0 unlimited, including accept)")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		if err := o.Validate(); err != nil {
			return err
		}
		if endpoint.Listen != "" && (cmd.Flags().Changed("direction") || cmd.Flags().Changed("duration")) {
			return fmt.Errorf("listener uses the connector's direction and duration; use --max-duration to cap requests")
		}
		return runSession(cmd, *c, endpoint.Connect, "TCP throughput", func(ctx context.Context, emit func(any)) (any, error) {
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}
			var outputErr error
			conn, err := stream.Open(ctx, endpoint, func(address string) error {
				_, outputErr = fmt.Fprintln(cmd.ErrOrStderr(), "bandwidth listening on "+ui.Clean(address))
				return outputErr
			})
			if outputErr != nil {
				return nil, &ExitError{2, outputErr.Error()}
			}
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			return bandwidth.Run(ctx, conn, endpoint.Connect != "", o, func(r bandwidth.Result) { emit(r) })
		})
	}
	root.AddCommand(cmd)
}
func addWatchCommand(root *cobra.Command, c *config) {
	o := watch.Options{Interval: time.Second, Concurrency: 16}
	var resolver string
	cmd := &cobra.Command{Use: "watch <url> [url...]", Short: "Monitor services together with quiet outage and recovery history", Long: "Monitor http(s)://host/path, tcp://host:port, dns://name?type=A, or icmp://host.\nIndependent checks run concurrently. HTTP 200–399 is healthy; redirects are not followed.\nUse --count or --duration for a finite run, or --until all-up for a readiness gate.\n--timeout bounds each check; duration expiry preserves pending checks.\nFinite runs fail if any completed check failed, except successful --until all-up.\n\n  ipsak watch https://example.com tcp://localhost:5432\n  ipsak watch 'dns://example.com?type=AAAA' --count 3 --json", Args: cobra.RangeArgs(1, 128)}
	cmd.Flags().Var(durationValue{&o.Interval}, "interval", "Minimum gap between rounds (100ms–1h)")
	cmd.Flags().Var(optionalDurationValue{&o.Duration}, "duration", "Planned session duration (0 runs until stopped)")
	cmd.Flags().IntVarP(&o.Count, "count", "c", 0, "Rounds (0 runs until stopped)")
	cmd.Flags().IntVar(&o.Concurrency, "concurrency", 16, "Maximum simultaneous checks (1–32)")
	cmd.Flags().StringVar(&o.Until, "until", "", "Stop condition: all-up or any-down")
	cmd.Flags().StringVar(&resolver, "resolver", "", "DNS resolver IP[:port] (default first system resolver)")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		targets := make([]watch.Target, len(args))
		for i, s := range args {
			t, e := watch.Parse(s)
			if e != nil {
				return e
			}
			targets[i] = t
		}
		o.Timeout = c.timeout
		if err := o.Validate(targets); err != nil {
			return err
		}
		server := resolver
		if server != "" {
			_, _, ss, e := probe.DNSOptions("example.com", []string{"A"}, []string{server})
			if e != nil {
				return e
			}
			server = ss[0]
		}
		check, closeIdle, err := watch.NewChecker(server)
		if err != nil {
			return err
		}
		defer closeIdle()
		return runSession(cmd, *c, strings.Join(args, ", "), "Service watch", func(ctx context.Context, emit func(any)) (any, error) {
			return watch.Run(ctx, targets, o, check, func(r watch.Result) { emit(r) })
		})
	}
	root.AddCommand(cmd)
}
func addDNSTraceCommand(root *cobra.Command, c *config) {
	o := dnstrace.Options{Type: dns.TypeA, MaxHops: 32, QueryTimeout: 2 * time.Second}
	var roots []string
	var kind string
	cmd := &cobra.Command{Use: "dnstrace <name>", Short: "Follow DNS delegation from root to authoritative answer", Long: "Trace nonrecursive DNS queries, racing servers at each delegation.\nGlue is restricted to the delegated zone. Missing nameserver addresses use\nthe system resolver, explicitly shown in the report. DNSSEC is not validated.\nAuthoritative NXDOMAIN and NODATA are completed trace outcomes, not failures.", Args: cobra.ExactArgs(1)}
	cmd.Flags().StringVar(&kind, "type", "A", "DNS record type")
	cmd.Flags().StringSliceVar(&roots, "root", nil, "Starting root IP[:port], repeat/comma-separate (default root hints)")
	cmd.Flags().IntVar(&o.MaxHops, "max-hops", 32, "Maximum delegation and alias steps (1–64)")
	cmd.Flags().Var(durationValue{&o.QueryTimeout}, "query-timeout", "Timeout per server query (at most 1m)")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if _, err := netip.ParseAddr(args[0]); err == nil {
			return fmt.Errorf("dnstrace requires a DNS name; use the reverse zone name for PTR")
		}
		var ok bool
		o.Type, ok = dns.StringToType[strings.ToUpper(kind)]
		if !ok {
			return fmt.Errorf("unknown DNS type %q", kind)
		}
		o.Roots = append([]string(nil), dnstrace.DefaultRoots...)
		if len(roots) > 0 {
			o.Roots = roots
		}
		name, _, servers, err := probe.DNSOptions(args[0], []string{"A"}, o.Roots)
		if err != nil {
			return err
		}
		o.Roots = servers
		if err = o.Validate(); err != nil {
			return err
		}
		return runReport(cmd, *c, name, []lookup.Task{{Key: "delegation", Title: "DNS delegation trace", Source: "direct DNS · recursion disabled", Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) {
			return (dnstrace.Resolver{}).Trace(ctx, name, o)
		}}})
	}
	root.AddCommand(cmd)
}
