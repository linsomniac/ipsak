package hostnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
)

// lsof -F0 emits NUL fields and a newline after each process/file set.
func parseLsof(data []byte) ([]Socket, error) {
	rows := []Socket{}
	pid := 0
	name := ""
	fields := map[byte]string{}
	flush := func() error {
		if len(fields) == 0 {
			return nil
		}
		if len(rows) >= maxRows {
			return fmt.Errorf("socket table exceeds %d entries", maxRows)
		}
		fd, err := strconv.Atoi(fields['f'])
		if err != nil || fd < 0 || pid <= 0 {
			return fmt.Errorf("invalid lsof process or file descriptor")
		}
		protocol := strings.ToLower(fields['P'])
		family := strings.ToLower(fields['t'])
		if (protocol != "tcp" && protocol != "udp") || (family != "ipv4" && family != "ipv6") {
			return fmt.Errorf("unrecognized lsof socket type or protocol")
		}
		localText, remoteText, connected := strings.Cut(fields['n'], "->")
		local, err := parseEndpoint(localText)
		if err != nil {
			return fmt.Errorf("invalid lsof local endpoint: %w", err)
		}
		remote := Endpoint{Address: "*"}
		if connected {
			remote, err = parseEndpoint(remoteText)
			if err != nil {
				return fmt.Errorf("invalid lsof remote endpoint: %w", err)
			}
		}
		state := fields['T']
		if state == "" {
			state = "UNKNOWN"
			if protocol == "udp" {
				state = "UNCONN"
				if connected {
					state = "CONNECTED"
				}
			}
		}
		rows = append(rows, Socket{Protocol: protocol, Family: family, State: state, Local: local, Remote: remote, Processes: []Process{{PID: pid, Name: name, FD: fd}}, ProcessStatus: "available"})
		fields = map[byte]string{}
		return nil
	}
	if len(data) > 0 && !bytes.Contains(data, []byte{0}) {
		return rows, fmt.Errorf("lsof did not return NUL-delimited fields")
	}
	for _, raw := range bytes.Split(data, []byte{0}) {
		raw = bytes.TrimLeft(raw, "\n")
		if len(raw) == 0 {
			continue
		}
		key := raw[0]
		value := string(raw[1:])
		switch key {
		case 'p':
			if err := flush(); err != nil {
				return rows, err
			}
			v, err := strconv.Atoi(value)
			if err != nil || v <= 0 {
				return rows, fmt.Errorf("invalid lsof process identifier")
			}
			pid = v
			name = ""
		case 'c':
			name = value
		case 'f':
			if err := flush(); err != nil {
				return rows, err
			}
			fields[key] = value
		case 'P', 't', 'n', 'T':
			if key == 'T' {
				if !strings.HasPrefix(value, "ST=") {
					continue
				}
				value = strings.TrimPrefix(value, "ST=")
			}
			if _, ok := fields['f']; !ok {
				return rows, fmt.Errorf("lsof socket field precedes file descriptor")
			}
			if old, ok := fields[key]; ok && old != value {
				return rows, fmt.Errorf("conflicting lsof fields")
			}
			fields[key] = value
		}
	}
	err := flush()
	return rows, err
}

func darwinNeighbors(ctx context.Context, opts NeighborOptions) ([]Neighbor, error) {
	type result struct {
		rows []Neighbor
		err  error
	}
	var results [2]result
	var wg sync.WaitGroup
	for i, name := range []string{"arp", "ndp"} {
		if i == 0 && opts.IPv6 || i == 1 && opts.IPv4 {
			continue
		}
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			b, err := command(ctx, name, "-an")
			if err == nil {
				if i == 0 {
					results[i].rows, err = parseDarwinARP(b)
				} else {
					results[i].rows, err = parseDarwinNDP(b)
				}
			}
			results[i].err = err
		}(i, name)
	}
	wg.Wait()
	rows := []Neighbor{}
	var combined error
	for _, r := range results {
		combined = errors.Join(combined, r.err)
		for _, v := range r.rows {
			if opts.Interface == "" || opts.Interface == v.Interface {
				rows = append(rows, v)
			}
		}
	}
	sortNeighbors(rows)
	return rows, errors.Join(combined, ctx.Err())
}
func parseDarwinARP(data []byte) ([]Neighbor, error) {
	rows := []Neighbor{}
	for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if len(rows) >= maxRows {
			return rows, fmt.Errorf("ARP table exceeds %d entries", maxRows)
		}
		f := strings.Fields(line)
		if len(f) < 6 || f[2] != "at" || f[4] != "on" {
			return rows, fmt.Errorf("unrecognized ARP row %d", i+1)
		}
		a, err := netip.ParseAddr(strings.Trim(f[1], "()"))
		if err != nil || !a.Is4() {
			return rows, fmt.Errorf("invalid ARP address at row %d", i+1)
		}
		n := Neighbor{Address: a.String(), Family: "ipv4", Interface: f[5], States: []string{"CACHED"}}
		if f[3] == "(incomplete)" {
			n.States = []string{"INCOMPLETE"}
		} else {
			m, err := darwinMAC(f[3])
			if err != nil {
				return rows, fmt.Errorf("invalid ARP link address at row %d", i+1)
			}
			n.MAC = &m
		}
		for _, flag := range f[6:] {
			if flag == "permanent" {
				n.States = append(n.States, "PERMANENT")
			}
		}
		rows = append(rows, n)
	}
	return rows, nil
}
func parseDarwinNDP(data []byte) ([]Neighbor, error) {
	rows := []Neighbor{}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return rows, nil
	}
	if !strings.HasPrefix(lines[0], "Neighbor") || !strings.Contains(lines[0], "Netif") || !strings.Contains(lines[0], "St") {
		return rows, fmt.Errorf("unrecognized NDP table header")
	}
	states := map[string]string{"N": "NONE", "I": "INCOMPLETE", "R": "REACHABLE", "S": "STALE", "D": "DELAY", "P": "PROBE", "?": "UNKNOWN"}
	for i, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if len(rows) >= maxRows {
			return rows, fmt.Errorf("NDP table exceeds %d entries", maxRows)
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			return rows, fmt.Errorf("unrecognized NDP row %d", i+2)
		}
		a, err := netip.ParseAddr(f[0])
		if err != nil || !a.Is6() {
			return rows, fmt.Errorf("invalid NDP address at row %d", i+2)
		}
		n := Neighbor{Address: a.String(), Family: "ipv6", Interface: f[2], States: []string{"UNKNOWN"}}
		if a.Zone() != "" && a.Zone() != n.Interface {
			return rows, fmt.Errorf("NDP scope and interface disagree at row %d", i+2)
		}
		if f[1] == "(incomplete)" {
			n.States = []string{"INCOMPLETE"}
		} else {
			m, err := darwinMAC(f[1])
			if err != nil {
				return rows, fmt.Errorf("invalid NDP link address at row %d", i+2)
			}
			n.MAC = &m
		}
		if len(f) >= 5 {
			state, ok := states[f[4]]
			if !ok {
				return rows, fmt.Errorf("unknown NDP state at row %d", i+2)
			}
			n.States = []string{state}
			if f[3] == "permanent" {
				n.States = append(n.States, "PERMANENT")
			}
			if len(f) > 5 {
				n.Router = strings.Contains(f[5], "R")
			}
		}
		rows = append(rows, n)
	}
	return rows, nil
}
func darwinMAC(value string) (string, error) {
	// Apple's arp/ndp use %x, without leading zeroes on individual octets.
	parts := strings.Split(value, ":")
	if len(parts) != 6 && len(parts) != 8 {
		return "", fmt.Errorf("unexpected link address length")
	}
	for i, p := range parts {
		if len(p) < 1 || len(p) > 2 {
			return "", fmt.Errorf("invalid link octet")
		}
		n, e := strconv.ParseUint(p, 16, 8)
		if e != nil {
			return "", e
		}
		parts[i] = fmt.Sprintf("%02x", n)
	}
	m, err := net.ParseMAC(strings.Join(parts, ":"))
	if err != nil {
		return "", err
	}
	return m.String(), nil
}
