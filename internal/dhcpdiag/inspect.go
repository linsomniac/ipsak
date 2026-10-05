package dhcpdiag

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/linsomniac/ipsak/internal/localnet"
)

type Inspection struct {
	Leases      []Lease  `json:"leases"`
	Unavailable []string `json:"unavailable"`
	Note        string   `json:"note"`
}

func (r Inspection) CompactLines() []string {
	lines := []string{r.Note}
	for _, l := range r.Leases {
		lines = append(lines, fmt.Sprintf("%s  %s  server %s · %s", l.Interface, l.Address, l.Server, l.Source), fmt.Sprintf("  gateway %s · DNS %s · lease %ds", strings.Join(l.Routers, ", "), strings.Join(l.DNS, ", "), l.LeaseSeconds))
	}
	return append(lines, r.Unavailable...)
}
func ReadLeaseFile(path, iface string) (Lease, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return Lease{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return Lease{}, fmt.Errorf("lease input must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, (256<<10)+1))
	if err != nil {
		return Lease{}, err
	}
	return ParseLease(data, iface, path)
}
func inspectInterface(ctx context.Context, iface net.Interface, goos string, runner localnet.Runner, read func(string, string) (Lease, error)) (Lease, error) {
	if err := ctx.Err(); err != nil {
		return Lease{}, err
	}
	if goos == "linux" {
		path := fmt.Sprintf("/run/systemd/netif/leases/%d", iface.Index)
		lease, fileErr := read(path, iface.Name)
		if fileErr == nil {
			return lease, nil
		}
		result, err := runner(ctx, "nmcli", "--escape", "no", "--get-values", "DHCP4.OPTION", "device", "show", iface.Name)
		if err != nil {
			return Lease{}, fmt.Errorf("%s: systemd lease unavailable (%v); NetworkManager evidence unavailable (%v)", iface.Name, fileErr, err)
		}
		return ParseLease(result.Stdout, iface.Name, "NetworkManager DHCP4.OPTION")
	}
	if goos == "darwin" {
		result, err := runner(ctx, "/usr/sbin/ipconfig", "getpacket", iface.Name)
		if err != nil {
			return Lease{}, err
		}
		return ParseLease(result.Stdout, iface.Name, "ipconfig getpacket")
	}
	return Lease{}, fmt.Errorf("DHCP lease inspection supports Linux and macOS, not %s", goos)
}
func Inspect(ctx context.Context, names []string, path string) (Inspection, error) {
	r := Inspection{Leases: []Lease{}, Unavailable: []string{}, Note: "DHCPv4 lease records are local evidence, potentially historical; this does not renew, release, or configure a lease."}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	if path != "" {
		iface := "file"
		if len(names) == 1 {
			iface = names[0]
		}
		lease, err := ReadLeaseFile(path, iface)
		if err != nil {
			return r, err
		}
		r.Leases = append(r.Leases, lease)
		return r, nil
	}
	ifaces, err := localnet.Interfaces(names, false)
	if err != nil {
		return r, err
	}
	type row struct {
		lease Lease
		err   error
	}
	rows := make([]row, len(ifaces))
	var wg sync.WaitGroup
	for i, iface := range ifaces {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rows[i].lease, rows[i].err = inspectInterface(ctx, iface, runtime.GOOS, localnet.Run, ReadLeaseFile)
		}()
	}
	wg.Wait()
	for i, row := range rows {
		if row.err != nil {
			r.Unavailable = append(r.Unavailable, ifaces[i].Name+": "+row.err.Error())
		} else {
			r.Leases = append(r.Leases, row.lease)
		}
	}
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	if len(r.Leases) == 0 {
		return r, fmt.Errorf("no DHCPv4 lease evidence found; interfaces may use static addressing or an unsupported lease manager")
	}
	return r, nil
}
