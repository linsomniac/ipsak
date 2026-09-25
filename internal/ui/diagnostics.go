package ui

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/linsomniac/ipsak/internal/hostnet"
)

// Inventory rows keep interactive views readable without changing the complete
// structured data used by JSON or the detailed, untruncated plain renderer.
func diagnosticLines(value any) ([]string, bool) {
	var lines []string
	switch r := value.(type) {
	case hostnet.SocketReport:
		lines = append(lines, fmt.Sprintf("%d sockets", r.Count))
		for _, s := range r.Sockets {
			lines = append(lines, fmt.Sprintf("%s · %s · %s → %s", s.Protocol, s.State, socketAddress(s.Local), socketAddress(s.Remote)))
			owners := []string{}
			for _, p := range s.Processes {
				owners = append(owners, fmt.Sprintf("%s (%d)", p.Name, p.PID))
			}
			owner := "ownership " + s.ProcessStatus
			if len(owners) > 0 {
				owner = strings.Join(owners, ", ")
			} else if s.ProcessStatus == "" {
				owner = "ownership unavailable"
			}
			lines = append(lines, "  "+s.Family+" · "+owner)
		}
		lines = append(lines, r.Notes...)
	case hostnet.NeighborReport:
		lines = append(lines, fmt.Sprintf("%d cached neighbors", r.Count))
		for _, n := range r.Neighbors {
			mac := "MAC unavailable"
			if n.MAC != nil {
				mac = *n.MAC
			}
			lines = append(lines, n.Address+" · "+mac)
			state := strings.Join(n.States, ", ")
			if state == "" {
				state = "state unavailable"
			}
			if n.Router {
				state += " · router"
			}
			lines = append(lines, "  "+n.Interface+" · "+state)
		}
		if r.Note != "" {
			lines = append(lines, r.Note)
		}
	case hostnet.InterfaceReport:
		for _, i := range r.Interfaces {
			state := "down"
			if i.Up {
				state = "up"
			}
			lines = append(lines, fmt.Sprintf("%s · %s · MTU %d · %s", i.Name, state, i.MTU, i.OperationalState))
			if i.MAC != "" {
				lines = append(lines, "  MAC "+i.MAC)
			}
			if len(i.Flags) > 0 {
				lines = append(lines, "  "+strings.Join(i.Flags, ", "))
			}
			for _, a := range i.Addresses {
				lines = append(lines, "  "+a)
			}
			if i.AddressError != "" {
				lines = append(lines, "  "+i.AddressError)
			}
			if i.Counters == nil {
				lines = append(lines, "  counters: "+i.CountersStatus)
			} else {
				c := i.Counters
				lines = append(lines, "  received "+byteCount(c.RXBytes)+" · sent "+byteCount(c.TXBytes))
				lines = append(lines, fmt.Sprintf("  packets ↓%d ↑%d · errors ↓%d ↑%d · drops ↓%d ↑%d", c.RXPackets, c.TXPackets, c.RXErrors, c.TXErrors, c.RXDropped, c.TXDropped))
			}
			if i.Throughput != nil {
				lines = append(lines, fmt.Sprintf("  rate ↓%.1f KiB/s ↑%.1f KiB/s", i.Throughput.RXBytesPerSecond/1024, i.Throughput.TXBytesPerSecond/1024))
			} else if i.ThroughputStatus != "not sampled" && i.ThroughputStatus != "" {
				lines = append(lines, "  rate: "+i.ThroughputStatus)
			}
		}
		lines = append(lines, r.Notes...)
	default:
		return nil, false
	}
	for i := range lines {
		lines[i] = Clean(lines[i])
	}
	return lines, true
}

func socketAddress(e hostnet.Endpoint) string {
	port := "*"
	if e.Port != nil {
		port = strconv.Itoa(int(*e.Port))
	}
	return net.JoinHostPort(e.Address, port)
}

func byteCount(n uint64) string {
	const units = "KMGTPE"
	v := float64(n)
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	for i := 0; i < len(units); i++ {
		v /= 1024
		if v < 1024 || i == len(units)-1 {
			return fmt.Sprintf("%.1f %ciB", v, units[i])
		}
	}
	return ""
}
