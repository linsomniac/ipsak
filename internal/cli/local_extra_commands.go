package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/linsomniac/ipsak/internal/dhcpdiag"
	"github.com/linsomniac/ipsak/internal/discovery"
	"github.com/linsomniac/ipsak/internal/ipconflict"
	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/linsomniac/ipsak/internal/pcapture"
	"github.com/spf13/cobra"
)

func addLocalExtraCommands(root *cobra.Command, c *config) {
	addCaptureCommand(root, c)
	addDHCPCommand(root, c)
	addIPConflictCommand(root, c)
	addDiscoverCommand(root, c)
}
func localSessionContext(cmd *cobra.Command, c config, ctx context.Context) (context.Context, context.CancelFunc) {
	if cmd.Flags().Changed("timeout") {
		return context.WithTimeout(ctx, c.timeout)
	}
	return context.WithCancel(ctx)
}

func addCaptureCommand(root *cobra.Command, c *config) {
	o := pcapture.Options{Count: 100, ScanLimit: 100000, Snaplen: 256, Duration: 5 * time.Second}
	cmd := &cobra.Command{Use: "capture", Short: "Capture readable packet evidence or inspect a classic pcap", Long: "Capture bounded packet summaries using tcpdump on Linux/macOS, or read classic pcap\nwithout privileges. Live capture selects the first up non-loopback interface unless\n--interface is given, and requires tcpdump/capture permissions. Payload is never\nprinted. --write atomically saves matched packets to a private classic pcap.\nUnsupported pcapng or link types fail explicitly. Duration or count ends a session;\nan explicitly supplied --timeout may impose a shorter overall deadline.", Args: cobra.NoArgs}
	cmd.Flags().StringVarP(&o.Interface, "interface", "i", "", "Interface for live capture")
	cmd.Flags().StringVarP(&o.Read, "read", "r", "", "Read a regular classic-pcap file instead of capturing")
	cmd.Flags().StringVarP(&o.Write, "write", "w", "", "Save matched packets atomically to a private pcap file")
	cmd.Flags().BoolVar(&o.Force, "force", false, "Replace an existing --write file on successful capture")
	cmd.Flags().IntVarP(&o.Count, "count", "c", 100, "Maximum matched packet summaries (1–10000)")
	cmd.Flags().IntVar(&o.ScanLimit, "scan-limit", 100000, "Maximum records examined (at least count, at most 1000000)")
	cmd.Flags().IntVar(&o.Snaplen, "snaplen", 256, "Captured bytes per live packet (64–65535)")
	cmd.Flags().Var(durationValue{&o.Duration}, "duration", "Live observation window (greater than zero, at most 1m)")
	cmd.Flags().StringVar(&o.Filter.Protocol, "protocol", "", "Filter tcp, udp, icmp, icmp6, or arp")
	cmd.Flags().StringVar(&o.Filter.Host, "host", "", "Filter either endpoint by numeric IP")
	cmd.Flags().IntVar(&o.Filter.Port, "port", 0, "Filter either TCP/UDP port (1–65535)")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if err := o.Validate(); err != nil {
			return err
		}
		if cmd.Flags().Changed("port") && o.Filter.Port == 0 {
			return fmt.Errorf("port filter must be 1–65535")
		}
		target := o.Interface
		if o.Read != "" {
			target = o.Read
		}
		return runSession(cmd, *c, target, "Packet capture", func(ctx context.Context, emit func(any)) (any, error) {
			ctx, cancel := localSessionContext(cmd, *c, ctx)
			defer cancel()
			return pcapture.Run(ctx, o, func(r pcapture.Result) { emit(r) })
		})
	}
	root.AddCommand(cmd)
}

func addDHCPCommand(root *cobra.Command, c *config) {
	var iface, path string
	var probe bool
	duration := 5 * time.Second
	cmd := &cobra.Command{Use: "dhcp", Short: "Inspect DHCPv4 leases and optionally collect offers without accepting a lease", Long: "Read DHCPv4 lease evidence from systemd-networkd/NetworkManager on Linux or\nipconfig getpacket on macOS. --lease-file accepts systemd, dhclient, nmcli, or\nmacOS packet text. Records may be historical. --probe explicitly sends only\nDHCPDISCOVER on one Ethernet interface; it never accepts or configures a lease.\nIt requires exclusive UDP port 68 and broadcast/raw-interface privileges; an\nexisting DHCP client may prevent probing. --timeout bounds all inspection/probing.", Args: cobra.NoArgs}
	cmd.Flags().StringVarP(&iface, "interface", "i", "", "Inspect/probe this interface (default inspection: up non-loopback interfaces)")
	cmd.Flags().StringVar(&path, "lease-file", "", "Inspect bounded local lease/packet text without querying the OS")
	cmd.Flags().BoolVar(&probe, "probe", false, "Send up to three DISCOVER messages and collect offers; never request a lease")
	cmd.Flags().Var(durationValue{&duration}, "duration", "Offer observation window (1s–30s; increase --timeout if needed)")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if probe && iface == "" {
			return fmt.Errorf("--probe requires --interface")
		}
		if probe && path != "" {
			return fmt.Errorf("--lease-file cannot be combined with --probe")
		}
		if duration < time.Second || duration > 30*time.Second {
			return fmt.Errorf("duration must be 1s–30s")
		}
		names := []string{}
		if iface != "" {
			names = append(names, iface)
		}
		tasks := []lookup.Task{{Key: "leases", Title: "Local DHCPv4 lease evidence", Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) {
			return dhcpdiag.Inspect(ctx, names, path)
		}}}
		if probe {
			tasks = append(tasks, lookup.Task{Key: "offers", Title: "DHCPDISCOVER offers (no lease accepted)", Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) {
				return dhcpdiag.Probe(ctx, iface, duration, nil)
			}})
		}
		return runReport(cmd, *c, iface, tasks)
	}
	root.AddCommand(cmd)
}

func addIPConflictCommand(root *cobra.Command, c *config) {
	o := ipconflict.Options{Count: 3, Interval: time.Second, Duration: 4 * time.Second}
	cmd := &cobra.Command{Use: "ipconflict <ip>", Short: "Probe a local link for ARP or IPv6 neighbor owner evidence", Long: "Send active owner probes through one explicit Ethernet interface. IPv4 requires\niputils arping (Linux) or Thomas Habets arping (Linux/macOS/Homebrew); IPv6 uses\nnative raw ICMPv6 and requires raw-socket privileges on Linux/macOS. Interface\nconfiguration is unchanged. This is owner observation, not full RFC DAD. Silence\nis inconclusive; an observed owner means in-use; distinct owners or an external\nowner of a locally configured address produce conflict evidence and exit 1.\nAn explicit --timeout may impose a shorter overall deadline.", Args: cobra.ExactArgs(1)}
	cmd.Flags().StringVarP(&o.Interface, "interface", "i", "", "Required local Ethernet interface")
	cmd.Flags().IntVarP(&o.Count, "count", "c", 3, "Number of probes (1–10)")
	cmd.Flags().Var(durationValue{&o.Interval}, "interval", "Probe interval (200ms–5s; iputils requires whole seconds)")
	cmd.Flags().Var(durationValue{&o.Duration}, "duration", "Observation window (1s–30s, long enough for all probes)")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		o.Target = args[0]
		if err := o.Validate(); err != nil {
			return err
		}
		return runSession(cmd, *c, o.Target, "Active address-owner evidence", func(ctx context.Context, emit func(any)) (any, error) {
			ctx, cancel := localSessionContext(cmd, *c, ctx)
			defer cancel()
			return ipconflict.Run(ctx, o, func(r ipconflict.Result) { emit(r) })
		})
	}
	root.AddCommand(cmd)
}

func addDiscoverCommand(root *cobra.Command, c *config) {
	o := discovery.Options{Duration: 5 * time.Second}
	cmd := &cobra.Command{Use: "discover", Short: "Browse and resolve local mDNS/DNS-SD service instances", Long: "Browse multicast DNS on up multicast-capable interfaces, then resolve discovered\nPTR instances through SRV/TXT and A/AAAA records. Defaults include HTTP, HTTPS,\nSSH, IPP and service-type enumeration. Results retain interface scope, IPv6 zones,\nand incomplete instances. Linux/macOS multicast UDP is used without raw privileges.\nSilence does not establish absence. --duration controls the observation window;\nan explicitly supplied --timeout may impose a shorter overall deadline.", Args: cobra.NoArgs}
	cmd.Flags().StringSliceVarP(&o.Interfaces, "interface", "i", nil, "Interfaces to browse (repeat or comma-separate, at most 8)")
	cmd.Flags().StringSliceVar(&o.Types, "type", nil, "Service types such as _http._tcp (repeat or comma-separate, at most 16)")
	cmd.Flags().Var(durationValue{&o.Duration}, "duration", "Observation and resolution window (1s–30s)")
	cmd.Flags().BoolVarP(&o.IPv4, "ipv4", "4", false, "Use IPv4 multicast only")
	cmd.Flags().BoolVarP(&o.IPv6, "ipv6", "6", false, "Use IPv6 multicast only")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if err := o.Validate(); err != nil {
			return err
		}
		return runSession(cmd, *c, "local multicast", "mDNS service discovery", func(ctx context.Context, emit func(any)) (any, error) {
			ctx, cancel := localSessionContext(cmd, *c, ctx)
			defer cancel()
			return discovery.Run(ctx, o, func(r discovery.Result) { emit(r) })
		})
	}
	root.AddCommand(cmd)
}
