package cli

import (
	"context"
	"fmt"

	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/linsomniac/ipsak/internal/probe"
	"github.com/spf13/cobra"
)

func addProbeCommands(root *cobra.Command, c *config) {
	var serverName string
	var verbose bool
	tlsCmd := &cobra.Command{Use: "tlscert <host[:port]>", Short: "Inspect a TLS certificate chain and verify its identity and trust", Args: cobra.ExactArgs(1)}
	tlsCmd.Flags().StringVar(&serverName, "server-name", "", "TLS server name and certificate identity (defaults to target host)")
	tlsCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show the full certificate chain (JSON always includes it)")
	tlsCmd.RunE = func(cmd *cobra.Command, args []string) error {
		host, address, err := probe.HostPort(args[0], "443")
		if err != nil {
			return err
		}
		name := host
		if serverName != "" {
			name, err = probe.Host(serverName)
			if err != nil {
				return err
			}
		}
		view := *c
		view.verbose = verbose
		return runReport(cmd, view, address, []lookup.Task{{Key: "tls", Title: "TLS certificate and trust", Source: address, Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) {
			return probe.TLS(ctx, address, name, nil)
		}}})
	}
	root.AddCommand(tlsCmd)
	var redirects int
	var bodyLimit int64
	httpCmd := &cobra.Command{Use: "httpinfo <url|host>", Short: "Inspect HTTP headers, redirects, and per-hop timings", Args: cobra.ExactArgs(1)}
	httpCmd.Flags().IntVar(&redirects, "max-redirects", 5, "Maximum redirects to follow (0–10)")
	httpCmd.Flags().Int64Var(&bodyLimit, "max-body", 65536, "Maximum sampled body bytes per hop (0–1048576; one extra byte detects truncation)")
	httpCmd.RunE = func(cmd *cobra.Command, args []string) error {
		u, err := probe.HTTPURL(args[0])
		if err != nil {
			return err
		}
		if redirects < 0 || redirects > 10 || bodyLimit < 0 || bodyLimit > 1048576 {
			return fmt.Errorf("max-redirects must be 0–10 and max-body 0–1048576")
		}
		return runReport(cmd, *c, u.String(), []lookup.Task{{Key: "http", Title: "HTTP response and timing", Source: u.Host, Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) {
			return probe.HTTP(ctx, u.String(), redirects, bodyLimit)
		}}})
	}
	root.AddCommand(httpCmd)
	var recordTypes, resolvers []string
	dnsCmd := &cobra.Command{Use: "dnscheck <name|ip>", Short: "Compare DNS answers and failures across resolvers", Args: cobra.ExactArgs(1)}
	dnsCmd.Flags().StringSliceVar(&recordTypes, "type", nil, "Record types (default A,AAAA or PTR for an IP; at most 8)")
	dnsCmd.Flags().StringSliceVar(&resolvers, "resolver", nil, "Resolver IP[:port], repeat or comma-separate (default system resolvers; at most 8)")
	dnsCmd.RunE = func(cmd *cobra.Command, args []string) error {
		name, types, servers, err := probe.DNSOptions(args[0], recordTypes, resolvers)
		if err != nil {
			return err
		}
		return runReport(cmd, *c, args[0], []lookup.Task{{Key: "dnscheck", Title: "DNS resolver comparison", Source: "DNS wire queries", Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) {
			return probe.DNS(ctx, name, types, servers)
		}}})
	}
	root.AddCommand(dnsCmd)
	ntpCmd := &cobra.Command{Use: "ntptime [server[:port]]", Short: "Measure NTP time offset without changing the system clock", Args: cobra.MaximumNArgs(1)}
	ntpCmd.RunE = func(cmd *cobra.Command, args []string) error {
		server := "pool.ntp.org"
		if len(args) > 0 {
			server = args[0]
		}
		_, address, err := probe.HostPort(server, "123")
		if err != nil {
			return err
		}
		return runReport(cmd, *c, address, []lookup.Task{{Key: "ntp", Title: "NTP time sample", Source: address, Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) { return probe.NTP(ctx, address) }}})
	}
	root.AddCommand(ntpCmd)
	var providers []string
	var limit int
	var collector string
	lgCmd := &cobra.Command{Use: "lookingglass <ip|cidr>", Aliases: []string{"looking-glass", "lg"}, Short: "Query public RIPE RIS and NLNOG BGP looking glasses", Long: "Query BGP routes observed by public collectors. This does not run remote ping or traceroute. Providers are best-effort services; empty observations do not establish global route absence.", Args: cobra.ExactArgs(1)}
	lgCmd.Flags().StringSliceVar(&providers, "provider", []string{"ripe", "nlnog"}, "Providers ripe,nlnog or adapter=HTTPS-URL overrides (at most 4)")
	lgCmd.Flags().IntVar(&limit, "limit", 50, "Maximum displayed routes per provider (1–1000)")
	lgCmd.Flags().StringVar(&collector, "collector", "", "Filter RIPE collector, for example rrc00 (NLNOG unaffected)")
	lgCmd.RunE = func(cmd *cobra.Command, args []string) error {
		resource, selected, err := probe.LookingGlassOptions(args[0], providers, limit, collector)
		if err != nil {
			return err
		}
		tasks := []lookup.Task{}
		for i, p := range selected {
			tasks = append(tasks, lookup.Task{Key: fmt.Sprintf("lookingglass_%d_%s", i+1, p.Kind), Title: "BGP observations · " + p.Kind, Source: p.URL, Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) {
				return probe.LookingGlass(ctx, resource, p, limit, collector)
			}})
		}
		return runReport(cmd, *c, resource, tasks)
	}
	root.AddCommand(lgCmd)
}
