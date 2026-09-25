package hostnet

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"strings"
)

type Neighbor struct {
	Address   string   `json:"address"`
	Family    string   `json:"family"`
	Interface string   `json:"interface"`
	MAC       *string  `json:"mac"`
	States    []string `json:"states"`
	Router    bool     `json:"router"`
}
type NeighborReport struct {
	Neighbors []Neighbor `json:"neighbors"`
	Count     int        `json:"count"`
	Note      string     `json:"note"`
}
type NeighborOptions struct {
	Interface  string
	IPv4, IPv6 bool
}

func (o NeighborOptions) Validate() error {
	if o.IPv4 && o.IPv6 {
		return fmt.Errorf("choose only one of --ipv4 and --ipv6")
	}
	return nil
}
func Neighbors(ctx context.Context, opts NeighborOptions) (NeighborReport, error) {
	r := NeighborReport{Neighbors: []Neighbor{}, Note: "Cached ARP/NDP entries only; entries and states do not establish current host reachability."}
	if err := opts.Validate(); err != nil {
		return r, err
	}
	if opts.Interface != "" {
		if _, err := net.InterfaceByName(opts.Interface); err != nil {
			return r, err
		}
	}
	if runtime.GOOS == "darwin" {
		var err error
		r.Neighbors, err = darwinNeighbors(ctx, opts)
		r.Count = len(r.Neighbors)
		return r, err
	}
	if runtime.GOOS != "linux" {
		return r, fmt.Errorf("neighbors is unsupported on %s; supported systems are Linux and macOS", runtime.GOOS)
	}
	args := []string{"-j"}
	if opts.IPv4 {
		args = append(args, "-4")
	}
	if opts.IPv6 {
		args = append(args, "-6")
	}
	args = append(args, "neighbor", "show")
	if opts.Interface != "" {
		args = append(args, "dev", opts.Interface)
	}
	b, err := command(ctx, "ip", args...)
	if err != nil {
		return r, err
	}
	r.Neighbors, err = parseNeighbors(b)
	r.Count = len(r.Neighbors)
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	return r, err
}
func parseNeighbors(data []byte) ([]Neighbor, error) {
	var raw []struct {
		Address string   `json:"dst"`
		Device  string   `json:"dev"`
		MAC     string   `json:"lladdr"`
		States  []string `json:"state"`
		Router  bool     `json:"router"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid neighbor JSON: %w", err)
	}
	rows := []Neighbor{}
	if len(raw) > maxRows {
		return rows, fmt.Errorf("neighbor table exceeds %d entries", maxRows)
	}
	for i, v := range raw {
		a, err := netip.ParseAddr(v.Address)
		if err != nil || v.Device == "" {
			return rows, fmt.Errorf("invalid address or interface in neighbor row %d", i+1)
		}
		family := "ipv6"
		if a.Is4() {
			family = "ipv4"
		}
		n := Neighbor{Address: a.String(), Family: family, Interface: v.Device, States: v.States, Router: v.Router}
		if len(n.States) == 0 {
			n.States = []string{"UNKNOWN"}
		}
		for j := range n.States {
			n.States[j] = strings.ToUpper(n.States[j])
		}
		if v.MAC != "" {
			m, err := net.ParseMAC(v.MAC)
			if err != nil {
				return rows, fmt.Errorf("invalid link address in neighbor row %d", i+1)
			}
			s := m.String()
			n.MAC = &s
		}
		rows = append(rows, n)
	}
	sortNeighbors(rows)
	return rows, nil
}
func sortNeighbors(rows []Neighbor) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Interface != rows[j].Interface {
			return rows[i].Interface < rows[j].Interface
		}
		a, _ := netip.ParseAddr(rows[i].Address)
		b, _ := netip.ParseAddr(rows[j].Address)
		return a.Less(b)
	})
}
