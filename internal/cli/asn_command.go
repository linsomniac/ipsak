package cli

import (
	"fmt"
	"net/netip"

	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/spf13/cobra"
)

// newService is a parameter so tests can substitute local provider fixtures.
func addASNCommand(root *cobra.Command, c *config, newService func() *lookup.Service) {
	var limit int
	cmd := &cobra.Command{Use: "asn <as-number|ip>", Short: "Describe an autonomous system: holder, registration, BGP neighbours and visibility", Long: "Describe an autonomous system from public sources: its name and registry\n(Team Cymru), registration and abuse contacts (RDAP), and BGP neighbours and\nrouting visibility (RIPEstat). Sources are queried concurrently and fail\nindependently. RIPEstat can take over 30 seconds for a large network; raise\n--timeout if its sections report a deadline.\n\nNeighbours are AS-path positions observed by RIPE RIS collectors, not\nconfirmed business relationships. For an IP address, Team Cymru supplies the origin AS.\nIf it lists several origins, the report describes the first.\n\n  ipsak asn 8.8.8.8\n  ipsak asn AS15169\n  ipsak asn 15169 --limit 5 --json", Args: cobra.ExactArgs(1)}
	cmd.Flags().IntVar(&limit, "limit", 10, "Maximum neighbours listed in each direction (1–100)")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if limit < 1 || limit > 100 {
			return fmt.Errorf("limit must be 1–100")
		}
		ip, err := netip.ParseAddr(args[0])
		var number uint32
		target := args[0]
		if err != nil {
			number, err = lookup.ParseASN(args[0])
			if err != nil {
				return fmt.Errorf("expected an AS number or IP address")
			}
			target = fmt.Sprintf("AS%d", number)
		}
		return runReport(cmd, *c, target, newService().ASNTasks(number, ip, limit))
	}
	root.AddCommand(cmd)
}
