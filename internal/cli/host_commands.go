package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/linsomniac/ipsak/internal/hostnet"
	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/spf13/cobra"
)

func hostTask(key, title, source string, fn func(context.Context) (any, error)) lookup.Task {
	return lookup.Task{Key: key, Title: title, Source: source, Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) { return fn(ctx) }}
}

func addHostCommands(root *cobra.Command, c *config) {
	socketOpts := hostnet.SocketOptions{Protocol: "all"}
	sockets := &cobra.Command{Use: "sockets", Short: "Inspect local TCP and UDP endpoints and available process owners", Long: "Inspect local TCP and UDP endpoints using Linux ss or macOS lsof.\nProcess information depends on OS permissions; macOS lists accessible process\nsocket files. UDP UNCONN entries are bound sockets, not proof of readiness.", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := socketOpts.Validate(); err != nil {
			return err
		}
		return runReport(cmd, *c, "", []lookup.Task{hostTask("sockets", "Local sockets", "Operating system socket table", func(ctx context.Context) (any, error) { return hostnet.Sockets(ctx, socketOpts) })})
	}}
	sockets.Flags().StringVar(&socketOpts.Protocol, "protocol", "all", "Protocol: all, tcp, or udp")
	sockets.Flags().BoolVarP(&socketOpts.Listening, "listening", "l", false, "Show TCP listeners and unconnected bound UDP sockets")
	sockets.Flags().IntVarP(&socketOpts.Port, "port", "p", 0, "Filter local or remote port (0 selects all)")
	root.AddCommand(sockets)

	route := &cobra.Command{Use: "route <ip|domain>", Short: "Show the OS-selected route, source address and next hop", Long: "Show the route selected by the operating system for the first resolved address.\nLinux requires ip from iproute2; macOS uses route. Matching prefix and source\navailability are explicit. Route selection does not establish reachability.", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		t, err := lookup.ParseTarget(args[0])
		if err != nil {
			return err
		}
		if t.Prefix.IsValid() {
			return fmt.Errorf("route requires a host address or domain, not a CIDR")
		}
		if t.IP.IsValid() && (t.IP.IsUnspecified() || t.IP.IsMulticast() || t.Class == "Limited broadcast") {
			return fmt.Errorf("route requires a unicast destination")
		}
		return runReport(cmd, *c, args[0], []lookup.Task{hostTask("route", "Selected route", "Operating system routing table", func(ctx context.Context) (any, error) { return hostnet.Route(ctx, args[0]) })})
	}}
	root.AddCommand(route)

	var iface string
	var sample time.Duration
	interfaces := &cobra.Command{Use: "interfaces", Short: "Inspect interfaces, addresses, MTUs and traffic counters", Long: "Inspect interface addresses, flags and MTUs. Linux also supplies traffic\ncounters and operational state from sysfs. --sample measures byte rates over\na bounded interval; unsupported counters are explicitly unavailable.", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if cmd.Flags().Changed("sample") && (sample < 100*time.Millisecond || sample > 30*time.Second) {
			return fmt.Errorf("sample interval must be between 100ms and 30s")
		}
		return runReport(cmd, *c, iface, []lookup.Task{hostTask("interfaces", "Network interfaces", "Operating system interface inventory", func(ctx context.Context) (any, error) {
			if sample > 0 {
				return hostnet.SampleInterfaces(ctx, iface, sample)
			}
			return hostnet.Interfaces(ctx, iface)
		})})
	}}
	interfaces.Flags().StringVarP(&iface, "interface", "i", "", "Inspect only this interface")
	interfaces.Flags().DurationVar(&sample, "sample", 0, "Measure throughput over this interval (100ms–30s; within --timeout)")
	root.AddCommand(interfaces)

	nopts := hostnet.NeighborOptions{}
	neighbors := &cobra.Command{Use: "neighbors", Aliases: []string{"neighbours"}, Short: "Inspect cached IPv4 ARP and IPv6 NDP neighbors", Long: "Inspect cached IPv4 ARP and IPv6 NDP entries, including incomplete and failed\nentries. This is a cache snapshot, not active host discovery. Uses Linux ip\nfrom iproute2 or the macOS arp and ndp utilities.", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := nopts.Validate(); err != nil {
			return err
		}
		return runReport(cmd, *c, nopts.Interface, []lookup.Task{hostTask("neighbors", "Neighbor cache", "Operating system ARP and NDP cache", func(ctx context.Context) (any, error) { return hostnet.Neighbors(ctx, nopts) })})
	}}
	neighbors.Flags().StringVarP(&nopts.Interface, "interface", "i", "", "Inspect only this interface")
	neighbors.Flags().BoolVarP(&nopts.IPv4, "ipv4", "4", false, "Show IPv4 ARP entries")
	neighbors.Flags().BoolVarP(&nopts.IPv6, "ipv6", "6", false, "Show IPv6 NDP entries")
	root.AddCommand(neighbors)

	wopts := hostnet.WakeOptions{Destination: "255.255.255.255", Port: 9, Count: 1, Interval: 100 * time.Millisecond}
	wake := &cobra.Command{Use: "wake <mac>", Short: "Send Wake-on-LAN magic packets over IPv4 UDP", Long: "Send a 102-byte magic packet to an IPv4 broadcast or unicast destination.\nSuccess means the local socket accepted the packet; delivery and device wake-up\nare not confirmed. --interface selects an IPv4 source address; the OS chooses\nthe outgoing route. Repeated packets are paced and bounded by --timeout.", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		wopts.MAC = args[0]
		if err := wopts.Validate(); err != nil {
			return err
		}
		return runReport(cmd, *c, args[0], []lookup.Task{hostTask("wake", "Wake-on-LAN transmission", "Local UDP socket", func(ctx context.Context) (any, error) { return hostnet.Wake(ctx, wopts) })})
	}}
	wake.Flags().StringVarP(&wopts.Destination, "destination", "d", wopts.Destination, "Numeric IPv4 broadcast or unicast destination")
	wake.Flags().IntVarP(&wopts.Port, "port", "p", wopts.Port, "Destination UDP port (1–65535)")
	wake.Flags().StringVarP(&wopts.Interface, "interface", "i", "", "Use this interface's IPv4 source address")
	wake.Flags().IntVarP(&wopts.Count, "count", "c", wopts.Count, "Packets to send (1–100)")
	wake.Flags().Var(durationValue{&wopts.Interval}, "interval", "Delay between packets (10ms–1m)")
	root.AddCommand(wake)
}
