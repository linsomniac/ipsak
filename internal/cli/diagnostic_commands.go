package cli

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/linsomniac/ipsak/internal/diagnose"
	"github.com/linsomniac/ipsak/internal/hostnet"
	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/linsomniac/ipsak/internal/mtu"
	"github.com/spf13/cobra"
)

func addDiagnosticCommands(root *cobra.Command, c *config) {
	doctor := &cobra.Command{
		Use: "doctor [host|url]", Short: "Diagnose a connection with parallel DNS, route, TCP, TLS, and HTTP checks",
		Long: "Check a web service and suggest next steps for failed checks.\nThe default target is https://example.com. A bare host uses HTTPS.\nChecks connect directly, without HTTP proxy environment settings.\n\n  ipsak doctor\n  ipsak doctor https://example.com/health --json\n  ipsak doctor http://127.0.0.1:8080/",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var raw string
			if len(args) > 0 {
				raw = args[0]
			}
			e, err := diagnose.ParseEndpoint(raw)
			if err != nil {
				return err
			}
			tasks := diagnose.Tasks(e, diagnose.Dependencies{
				Interfaces: func(ctx context.Context) (any, error) { return hostnet.Interfaces(ctx, "") },
				Route:      func(ctx context.Context, ip netip.Addr) (any, error) { return hostnet.Route(ctx, ip.String()) },
			})
			return runReport(cmd, *c, e.URL, tasks)
		},
	}
	root.AddCommand(doctor)

	var minSize, maxSize, attempts int
	var ipv4, ipv6 bool
	probeTimeout := time.Second
	mtuCmd := &cobra.Command{
		Use: "mtu <host>", Short: "Measure path MTU with explicit size evidence and confirmed bounds",
		Long: "Probe without IP fragmentation. Sizes include IP and ICMP headers.\nA timeout is inconclusive; only matching packet-too-big errors lower the bound.\nRequires raw ICMP privileges: CAP_NET_RAW on Linux or elevated privileges on macOS.\n\n  ipsak mtu example.com\n  ipsak mtu ::1 -6 --max 9000 --json",
		Args: cobra.ExactArgs(1),
	}
	mtuCmd.Flags().IntVar(&minSize, "min", 0, "Smallest probe including headers (default: IPv4 576, IPv6 1280)")
	mtuCmd.Flags().IntVar(&maxSize, "max", 1500, "Largest probe including headers (up to 65535)")
	mtuCmd.Flags().IntVar(&attempts, "attempts", 2, "Attempts for an unanswered size (1–3)")
	mtuCmd.Flags().Var(durationValue{&probeTimeout}, "probe-timeout", "Deadline per probe (seconds or Go duration, at most 1m)")
	mtuCmd.Flags().BoolVarP(&ipv4, "ipv4", "4", false, "Use IPv4")
	mtuCmd.Flags().BoolVarP(&ipv6, "ipv6", "6", false, "Use IPv6")
	mtuCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if ipv4 && ipv6 {
			return fmt.Errorf("choose only one of -4 and -6")
		}
		t, err := lookup.ParseTarget(args[0])
		if err != nil {
			return err
		}
		if t.Prefix.IsValid() {
			return fmt.Errorf("mtu requires one host, not a CIDR")
		}
		if t.IP.IsValid() && (t.IP.IsMulticast() || t.IP.IsUnspecified() || t.Class == "Limited broadcast") {
			return fmt.Errorf("mtu requires a unicast destination")
		}
		// Reject family-independent argument errors before resolving or opening a socket.
		initialMin := minSize
		if !cmd.Flags().Changed("min") {
			initialMin = 68
		}
		if err := (mtu.Options{Min: initialMin, Max: maxSize, Attempts: attempts, ProbeTimeout: probeTimeout}).Validate(false); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), c.timeout)
		defer cancel()
		original := cmd.Context()
		cmd.SetContext(ctx)
		defer cmd.SetContext(original)
		resolveFailure := func(resolveErr error) error {
			return runReport(cmd, *c, t.Name, []lookup.Task{{Key: "target", Title: "Resolve MTU destination", Source: "system resolver", Run: func(context.Context, map[string]lookup.Section) (any, error) { return t, resolveErr }}})
		}
		if ctx.Err() != nil {
			return resolveFailure(ctx.Err())
		}
		family := "ip"
		if ipv4 {
			family = "ip4"
		} else if ipv6 {
			family = "ip6"
		}
		t, err = lookup.Resolve(ctx, t, family)
		if err != nil {
			return resolveFailure(err)
		}
		if ctx.Err() != nil {
			return resolveFailure(ctx.Err())
		}
		minimum := minSize
		if !cmd.Flags().Changed("min") {
			minimum = 576
			if t.IP.Is6() {
				minimum = 1280
			}
		}
		opts := mtu.Options{Min: minimum, Max: maxSize, Attempts: attempts, ProbeTimeout: probeTimeout}
		if err := opts.Validate(t.IP.Is6()); err != nil {
			return err
		}
		p, err := mtu.Open(t.IP)
		if err != nil {
			return err
		}
		defer p.Close()
		return runReport(cmd, *c, t.Name, []lookup.Task{{Key: "mtu", Title: "Path MTU", Source: "ICMP with fragmentation disabled", Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) {
			return mtu.Search(ctx, p, t.IP.String(), t.IP.Is6(), opts)
		}}})
	}
	root.AddCommand(mtuCmd)
}
