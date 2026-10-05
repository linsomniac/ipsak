// Package ipconflict collects active, interface-scoped ARP/NDP owner evidence.
package ipconflict

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/linsomniac/ipsak/internal/localnet"
)

type Options struct {
	Target, Interface  string
	Count              int
	Interval, Duration time.Duration
}

func (o Options) Validate() error {
	a, err := netip.ParseAddr(o.Target)
	if err != nil || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() || a.Unmap().String() == "255.255.255.255" {
		return fmt.Errorf("target must be a unicast local-link IP")
	}
	if a.Zone() != "" && a.Zone() != o.Interface {
		return fmt.Errorf("IPv6 zone must match --interface")
	}
	if err := localnet.ValidInterfaceName(o.Interface); err != nil {
		return fmt.Errorf("--interface is required: %w", err)
	}
	if o.Count < 1 || o.Count > 10 {
		return fmt.Errorf("count must be 1–10")
	}
	if o.Interval < 200*time.Millisecond || o.Interval > 5*time.Second {
		return fmt.Errorf("interval must be 200ms–5s")
	}
	if o.Duration < time.Second || o.Duration > 30*time.Second {
		return fmt.Errorf("duration must be 1s–30s")
	}
	if time.Duration(o.Count-1)*o.Interval >= o.Duration {
		return fmt.Errorf("duration must allow all requested probes")
	}
	return nil
}

type Owner struct {
	MAC          string `json:"mac"`
	Source       string `json:"source"`
	Observations int    `json:"observations"`
}
type Result struct {
	Target            string  `json:"target"`
	Interface         string  `json:"interface"`
	Protocol          string  `json:"protocol"`
	Method            string  `json:"method"`
	ConfiguredLocally bool    `json:"configured_locally"`
	Owners            []Owner `json:"owners"`
	Status            string  `json:"status"`
	Sent              int     `json:"probes_sent"`
	Ignored           int     `json:"ignored"`
	Note              string  `json:"note"`
}

func (r Result) CompactLines() []string {
	lines := []string{fmt.Sprintf("%s on %s · %s · %s", r.Target, r.Interface, r.Protocol, r.Status), r.Note}
	for _, o := range r.Owners {
		lines = append(lines, fmt.Sprintf("%s  %d observations  %s", o.MAC, o.Observations, o.Source))
	}
	return lines
}
func classify(r *Result) {
	r.Status = "inconclusive"
	if len(r.Owners) > 0 {
		r.Status = "address_in_use"
	}
	if len(r.Owners) > 1 || r.ConfiguredLocally && len(r.Owners) > 0 {
		r.Status = "conflict_evidence"
	}
	sort.Slice(r.Owners, func(i, j int) bool { return r.Owners[i].MAC < r.Owners[j].MAC })
}
func addOwner(r *Result, mac, source, ownMAC string) error {
	hardware, err := net.ParseMAC(mac)
	if err != nil || len(hardware) != 6 || hardware[0]&1 != 0 {
		return fmt.Errorf("invalid owner MAC")
	}
	mac = hardware.String()
	if mac == ownMAC || mac == "00:00:00:00:00:00" {
		r.Ignored++
		return nil
	}
	for i := range r.Owners {
		if r.Owners[i].MAC == mac {
			r.Owners[i].Observations++
			return nil
		}
	}
	if len(r.Owners) >= 128 {
		return fmt.Errorf("owner observation limit reached")
	}
	r.Owners = append(r.Owners, Owner{MAC: mac, Source: source, Observations: 1})
	return nil
}

var iputilsReply = regexp.MustCompile(`^(?:Unicast|Broadcast) (?:reply|request) from ([0-9.]+) \[([0-9A-Fa-f:]+)\]`)
var habetsReply = regexp.MustCompile(`^[0-9]+ bytes from ([0-9A-Fa-f:]+) \(([0-9.]+)\):`)
var iputilsSent = regexp.MustCompile(`(?m)^Sent ([0-9]+) probes`)
var habetsSent = regexp.MustCompile(`(?m)^([0-9]+) packets transmitted,`)

func parseARP(data []byte, flavor, target, own string, r *Result) error {
	if len(data) > 256<<10 {
		return fmt.Errorf("ARP output exceeds limit")
	}
	summary := iputilsSent
	if flavor == "habets" {
		summary = habetsSent
	}
	sent := summary.FindSubmatch(data)
	if len(sent) != 2 {
		return fmt.Errorf("unrecognized %s arping summary", flavor)
	}
	n, err := strconv.Atoi(string(sent[1]))
	if err != nil || n < 1 || n > 10 {
		return fmt.Errorf("invalid arping sent count")
	}
	r.Sent = n
	for _, line := range strings.Split(string(data), "\n") {
		match := iputilsReply.FindStringSubmatch(line)
		address, mac := "", ""
		if flavor == "habets" {
			match = habetsReply.FindStringSubmatch(line)
			if len(match) == 3 {
				mac, address = match[1], match[2]
			}
		} else if len(match) == 3 {
			address, mac = match[1], match[2]
		}
		if len(match) == 0 {
			continue
		}
		a, err := netip.ParseAddr(address)
		if err != nil || a.String() != target {
			return fmt.Errorf("arping returned unrelated address")
		}
		if err := addOwner(r, mac, "validated "+flavor+" arping reply", own); err != nil {
			return err
		}
	}
	return nil
}
func probeARP(ctx context.Context, o Options, iface net.Interface, r *Result, runner localnet.Runner) error {
	help, err := runner(ctx, "arping", "--help")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	text := string(help.Stdout) + string(help.Stderr)
	flavor := ""
	if strings.Contains(text, "-I <device>") || strings.Contains(text, "iputils") {
		flavor = "iputils"
	} else if strings.Contains(text, "-i interface") || strings.Contains(text, "-i <interface>") || strings.Contains(text, "Thomas Habets") {
		flavor = "habets"
	}
	if flavor == "" {
		return fmt.Errorf("supported arping is required: Linux iputils or Thomas Habets arping (macOS Homebrew); detection: %v", err)
	}
	seconds := strconv.Itoa(int((o.Duration + time.Second - 1) / time.Second))
	args := []string{}
	if flavor == "iputils" {
		if o.Interval%time.Second != 0 {
			return fmt.Errorf("iputils arping requires a whole-second --interval")
		}
		args = []string{"-b", "-I", iface.Name, "-c", strconv.Itoa(o.Count), "-w", seconds, "-i", strconv.Itoa(int(o.Interval / time.Second)), r.Target}
	} else {
		args = []string{"-i", iface.Name, "-c", strconv.Itoa(o.Count), "-w", seconds, "-W", strconv.FormatFloat(o.Interval.Seconds(), 'f', 3, 64), r.Target}
	}
	result, runErr := runner(ctx, "arping", args...)
	r.Method = flavor + " arping"
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if runErr != nil && (result.Code != 1 || len(strings.TrimSpace(string(result.Stderr))) > 0) {
		return fmt.Errorf("active ARP probe requires capture/raw privileges: %w", runErr)
	}
	if err := parseARP(result.Stdout, flavor, r.Target, iface.HardwareAddr.String(), r); err != nil {
		return err
	}
	return nil
}
func Run(parent context.Context, o Options, emit func(Result)) (r Result, err error) {
	r = Result{Target: o.Target, Interface: o.Interface, Owners: []Owner{}, Status: "inconclusive", Note: "Active owner observations, not a full duplicate-address-detection state machine. Silence never proves an address free; proxy ARP/NDP and virtual MACs can affect evidence."}
	if err = o.Validate(); err != nil {
		return r, err
	}
	if err = parent.Err(); err != nil {
		return r, err
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return r, fmt.Errorf("ipconflict supports Linux and macOS")
	}
	ifaces, err := localnet.Interfaces([]string{o.Interface}, false)
	if err != nil {
		return r, err
	}
	iface := ifaces[0]
	if len(iface.HardwareAddr) != 6 {
		return r, fmt.Errorf("an Ethernet interface with a six-byte MAC is required")
	}
	target, _ := netip.ParseAddr(o.Target)
	target = target.Unmap().WithZone("")
	r.Target = target.String()
	addresses, err := iface.Addrs()
	if err != nil {
		return r, err
	}
	for _, address := range addresses {
		if prefix, e := netip.ParsePrefix(address.String()); e == nil && prefix.Addr().Unmap() == target {
			r.ConfiguredLocally = true
		}
	}
	ctx, cancel := context.WithTimeout(parent, o.Duration+time.Second)
	defer cancel()
	if target.Is4() {
		r.Protocol = "ARP"
		err = probeARP(ctx, o, iface, &r, localnet.Run)
	} else {
		r.Protocol = "NDP"
		r.Method = "native ICMPv6 neighbor solicitation"
		err = probeND(ctx, o, iface, target, &r, emit)
	}
	classify(&r)
	if parent.Err() != nil {
		return r, parent.Err()
	}
	if err != nil {
		return r, err
	}
	if r.Status == "conflict_evidence" {
		return r, fmt.Errorf("conflicting owner evidence observed")
	}
	return r, nil
}
