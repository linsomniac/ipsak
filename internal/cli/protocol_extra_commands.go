package cli

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"unicode"

	"github.com/linsomniac/ipsak/internal/dnssec"
	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/linsomniac/ipsak/internal/mailcheck"
	"github.com/linsomniac/ipsak/internal/natprobe"
	"github.com/linsomniac/ipsak/internal/probe"
	"github.com/linsomniac/ipsak/internal/sshkey"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

func addProtocolExtraCommands(root *cobra.Command, c *config) {
	var mailResolver, selector string
	var smtp, starttls bool
	var smtpPort int
	mail := &cobra.Command{Use: "mailcheck <domain>", Short: "Inspect MX, SPF, DMARC, DKIM and optional SMTP/STARTTLS", Long: "Inspect published mail DNS policy. DKIM requires a supplied selector. SMTP and STARTTLS are opt-in greeting/EHLO probes; no authentication or mail is sent. This is not a full SPF evaluator or deliverability test.", Args: cobra.ExactArgs(1)}
	mail.Flags().StringVar(&mailResolver, "resolver", "", "DNS resolver IP[:port] (default first system resolver)")
	mail.Flags().StringVar(&selector, "selector", "", "DKIM selector to query (not discovered automatically)")
	mail.Flags().BoolVar(&smtp, "smtp", false, "Connect to at most three published MX servers for greeting and EHLO")
	mail.Flags().BoolVar(&starttls, "starttls", false, "Also negotiate STARTTLS and verify certificate identity/trust (implies --smtp)")
	mail.Flags().IntVar(&smtpPort, "smtp-port", 25, "Port used for optional SMTP probes")
	mail.RunE = func(cmd *cobra.Command, args []string) error {
		domain, err := probe.Host(args[0])
		if err != nil {
			return err
		}
		if _, err := netip.ParseAddr(domain); err == nil {
			return fmt.Errorf("mailcheck requires a domain, not an IP")
		}
		if smtpPort < 1 || smtpPort > 65535 {
			return fmt.Errorf("smtp-port must be 1–65535")
		}
		if len(selector) > 128 || strings.IndexFunc(selector, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || unicode.IsDigit(r) && r < 128 || r == '-' || r == '_' || r == '.')
		}) >= 0 || strings.HasPrefix(selector, ".") || strings.HasSuffix(selector, ".") || strings.Contains(selector, "..") {
			return fmt.Errorf("invalid DKIM selector")
		}
		if _, ok := dns.IsDomainName(dns.Fqdn(selector + "._domainkey." + domain)); selector != "" && !ok {
			return fmt.Errorf("selector and domain exceed DNS name limits")
		}
		servers := []string{}
		if mailResolver != "" {
			servers = append(servers, mailResolver)
		}
		name, _, servers, err := probe.DNSOptions(domain, []string{"MX"}, servers)
		if err != nil {
			return err
		}
		o := mailcheck.Options{Domain: name, Resolver: servers[0], Selector: selector, SMTP: smtp, STARTTLS: starttls, Port: smtpPort}
		return runReport(cmd, *c, domain, []lookup.Task{{Key: "mail", Title: "Mail DNS and SMTP posture", Source: servers[0], Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) { return mailcheck.Check(ctx, o) }}})
	}
	root.AddCommand(mail)
	var stunServers []string
	nat := &cobra.Command{Use: "nat", Short: "Observe public UDP mappings using parallel STUN servers", Long: "Compare STUN-observed mappings on a shared socket per address family. Observations do not definitively classify NAT type or establish inbound reachability. STUN replies are unauthenticated.", Args: cobra.NoArgs}
	nat.Flags().StringSliceVar(&stunServers, "server", []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"}, "STUN host[:port], repeat or comma-separate (at most 8)")
	nat.RunE = func(cmd *cobra.Command, _ []string) error {
		if len(stunServers) == 0 || len(stunServers) > 8 {
			return fmt.Errorf("configure one to eight STUN servers")
		}
		servers := []string{}
		seen := map[string]bool{}
		for _, raw := range stunServers {
			_, address, err := probe.HostPort(raw, "3478")
			if err != nil {
				return err
			}
			if !seen[address] {
				seen[address] = true
				servers = append(servers, address)
			}
		}
		return runReport(cmd, *c, "UDP mappings", []lookup.Task{{Key: "nat", Title: "STUN mapping observations", Source: strings.Join(servers, ", "), Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) {
			return natprobe.Observe(ctx, servers)
		}}})
	}
	root.AddCommand(nat)
	var dnsResolver, dnsType string
	secure := &cobra.Command{Use: "dnssec <name>", Short: "Cryptographically validate a positive DNS RRset to IANA root anchors", Long: "Validate exact-owner positive RRsets using local DNSSEC signature checks and a DNSKEY/DS chain to bundled IANA root anchors. Resolver AD is not trusted. CNAME paths, wildcard expansion and general denial/NSEC3 proofs are reported inconclusive; only exact NSEC unsigned-delegation proofs can establish insecure.", Args: cobra.ExactArgs(1)}
	secure.Flags().StringVar(&dnsResolver, "resolver", "", "DNS resolver IP[:port] used as untrusted transport (default first system resolver)")
	secure.Flags().StringVar(&dnsType, "type", "A", "RRset type: A,AAAA,MX,TXT,NS,SOA,CAA,DNSKEY,DS")
	secure.RunE = func(cmd *cobra.Command, args []string) error {
		allowed := map[string]uint16{"A": dns.TypeA, "AAAA": dns.TypeAAAA, "MX": dns.TypeMX, "TXT": dns.TypeTXT, "NS": dns.TypeNS, "SOA": dns.TypeSOA, "CAA": dns.TypeCAA, "DNSKEY": dns.TypeDNSKEY, "DS": dns.TypeDS}
		typ, ok := allowed[strings.ToUpper(dnsType)]
		if !ok {
			return fmt.Errorf("unsupported DNSSEC RRset type %q", dnsType)
		}
		if _, err := netip.ParseAddr(args[0]); err == nil {
			return fmt.Errorf("dnssec requires a DNS name")
		}
		servers := []string{}
		if dnsResolver != "" {
			servers = append(servers, dnsResolver)
		}
		name, _, servers, err := probe.DNSOptions(args[0], []string{"A"}, servers)
		if err != nil {
			return err
		}
		return runReport(cmd, *c, name, []lookup.Task{{Key: "dnssec", Title: "Local DNSSEC validation", Source: servers[0], Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) {
			return dnssec.Validate(ctx, name, typ, servers[0])
		}}})
	}
	root.AddCommand(secure)
	var pin string
	key := &cobra.Command{Use: "sshkey <host[:port]>", Short: "Observe an SSH host key without logging in", Args: cobra.ExactArgs(1)}
	key.Flags().StringVar(&pin, "fingerprint", "", "Expected OpenSSH SHA256 fingerprint; mismatch fails with observed key retained")
	key.RunE = func(cmd *cobra.Command, args []string) error {
		_, address, err := probe.HostPort(args[0], "22")
		if err != nil {
			return err
		}
		if err = sshkey.ValidatePin(pin); err != nil {
			return err
		}
		return runReport(cmd, *c, address, []lookup.Task{{Key: "sshkey", Title: "SSH host key observation", Source: address, Run: func(ctx context.Context, _ map[string]lookup.Section) (any, error) {
			return sshkey.Observe(ctx, address, pin)
		}}})
	}
	root.AddCommand(key)
}
