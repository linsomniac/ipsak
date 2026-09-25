package hostnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

type Endpoint struct {
	Address string  `json:"address"`
	Port    *uint16 `json:"port"`
}
type Process struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	FD   int    `json:"fd"`
}
type Socket struct {
	Protocol      string    `json:"protocol"`
	Family        string    `json:"family"`
	State         string    `json:"state"`
	Local         Endpoint  `json:"local"`
	Remote        Endpoint  `json:"remote"`
	ReceiveQueue  *uint64   `json:"receive_queue"`
	SendQueue     *uint64   `json:"send_queue"`
	Processes     []Process `json:"processes"`
	ProcessStatus string    `json:"process_status"`
}
type SocketOptions struct {
	Protocol  string
	Listening bool
	Port      int
}

func (o SocketOptions) Validate() error {
	if o.Protocol != "all" && o.Protocol != "tcp" && o.Protocol != "udp" {
		return fmt.Errorf("protocol must be all, tcp, or udp")
	}
	if o.Port < 0 || o.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, or 0 for any")
	}
	return nil
}

type SocketReport struct {
	Sockets []Socket `json:"sockets"`
	Count   int      `json:"count"`
	Notes   []string `json:"notes"`
}

// Sockets lists TCP and UDP endpoints in the current network namespace.
func Sockets(ctx context.Context, opts SocketOptions) (SocketReport, error) {
	r := SocketReport{Sockets: []Socket{}, Notes: []string{"Process ownership is available only where permitted by the operating system. UDP UNCONN entries are bound sockets, not proof of a listening application."}}
	if err := opts.Validate(); err != nil {
		return r, err
	}
	type result struct {
		rows []Socket
		err  error
	}
	var results [2]result
	switch runtime.GOOS {
	case "linux":
		var wg sync.WaitGroup
		for i, family := range []string{"4", "6"} {
			wg.Add(1)
			go func(i int, family string) {
				defer wg.Done()
				data, err := command(ctx, "ss", "-H", "-n", "-a", "-t", "-u", "-p", "-O", "-"+family)
				if err == nil {
					results[i].rows, err = parseSockets(data, "ipv"+family)
				}
				results[i].err = err
			}(i, family)
		}
		wg.Wait()
	case "darwin":
		r.Notes = append(r.Notes, "macOS lists accessible process-owned socket files through lsof; kernel-only or inaccessible sockets may be absent. Each PID/file descriptor is a row. Unavailable queue lengths are null.")
		data, err := commandOutput(ctx, true, "lsof", "-nP", "-iTCP", "-iUDP", "-F0pcfPtTn")
		if err == nil {
			results[0].rows, err = parseLsof(data)
		}
		results[0].err = err
	default:
		return r, fmt.Errorf("sockets is unsupported on %s; supported systems are Linux and macOS", runtime.GOOS)
	}
	var firstErr error
	for _, result := range results {
		firstErr = errors.Join(firstErr, result.err)
		for _, s := range result.rows {
			if opts.Protocol != "all" && opts.Protocol != s.Protocol {
				continue
			}
			if opts.Listening && s.State != "LISTEN" && !(s.Protocol == "udp" && s.State == "UNCONN") {
				continue
			}
			if opts.Port != 0 && (s.Local.Port == nil || int(*s.Local.Port) != opts.Port) && (s.Remote.Port == nil || int(*s.Remote.Port) != opts.Port) {
				continue
			}
			r.Sockets = append(r.Sockets, s)
		}
	}
	sort.Slice(r.Sockets, func(i, j int) bool {
		a, b := r.Sockets[i], r.Sockets[j]
		return fmt.Sprintf("%s/%s/%s/%05d/%s/%05d/%s", a.Protocol, a.Family, a.Local.Address, portNumber(a.Local), a.Remote.Address, portNumber(a.Remote), a.State) < fmt.Sprintf("%s/%s/%s/%05d/%s/%05d/%s", b.Protocol, b.Family, b.Local.Address, portNumber(b.Local), b.Remote.Address, portNumber(b.Remote), b.State)
	})
	r.Count = len(r.Sockets)
	return r, errors.Join(firstErr, ctx.Err())
}
func portNumber(e Endpoint) int {
	if e.Port == nil {
		return -1
	}
	return int(*e.Port)
}

var processPattern = regexp.MustCompile(`\("([^"\r\n]*)",pid=([0-9]+),fd=([0-9]+)\)`)

func parseSockets(data []byte, family string) ([]Socket, error) {
	rows := []Socket{}
	for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if len(rows) >= maxRows {
			return rows, fmt.Errorf("socket table exceeds %d entries", maxRows)
		}
		f := strings.Fields(line)
		if len(f) < 6 || (f[0] != "tcp" && f[0] != "udp") {
			return rows, fmt.Errorf("unrecognized ss row %d", i+1)
		}
		rx, e1 := strconv.ParseUint(f[2], 10, 64)
		tx, e2 := strconv.ParseUint(f[3], 10, 64)
		local, e3 := parseEndpoint(f[4])
		remote, e4 := parseEndpoint(f[5])
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
			return rows, fmt.Errorf("invalid ss row %d: numeric queue or endpoint expected", i+1)
		}
		s := Socket{Protocol: f[0], Family: family, State: f[1], Local: local, Remote: remote, ReceiveQueue: &rx, SendQueue: &tx, Processes: []Process{}, ProcessStatus: "unavailable (permission, kernel-owned, or no current owner)"}
		for _, p := range processPattern.FindAllStringSubmatch(strings.Join(f[6:], " "), -1) {
			pid, ep := strconv.Atoi(p[2])
			fd, ef := strconv.Atoi(p[3])
			if ep != nil || ef != nil {
				return rows, fmt.Errorf("invalid process identifier in ss row %d", i+1)
			}
			s.Processes = append(s.Processes, Process{PID: pid, Name: p[1], FD: fd})
		}
		if len(s.Processes) > 0 {
			s.ProcessStatus = "available"
			sort.Slice(s.Processes, func(i, j int) bool {
				if s.Processes[i].PID != s.Processes[j].PID {
					return s.Processes[i].PID < s.Processes[j].PID
				}
				return s.Processes[i].FD < s.Processes[j].FD
			})
		}
		rows = append(rows, s)
	}
	return rows, nil
}
func parseEndpoint(s string) (Endpoint, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		i := strings.LastIndexByte(s, ':')
		if i < 0 {
			return Endpoint{}, err
		}
		host, port = s[:i], s[i+1:]
	}
	// ss writes device bindings after IPv6 brackets ([fe80::1]%eth0:546),
	// while ordinary socket syntax puts the zone inside ([fe80::1%eth0]:546).
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		if end < 0 {
			return Endpoint{}, fmt.Errorf("invalid endpoint brackets")
		}
		suffix := host[end+1:]
		if suffix != "" && !strings.HasPrefix(suffix, "%") {
			return Endpoint{}, fmt.Errorf("invalid endpoint suffix")
		}
		host = host[1:end] + suffix
	}
	if strings.ContainsAny(host, "[]") {
		return Endpoint{}, fmt.Errorf("invalid endpoint brackets")
	}
	address, scope, scoped := strings.Cut(host, "%")
	if scoped && (scope == "" || strings.Contains(scope, "%") || strings.IndexFunc(scope, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0) {
		return Endpoint{}, fmt.Errorf("invalid endpoint interface scope")
	}
	if address != "*" {
		if _, err := netip.ParseAddr(address); err != nil {
			return Endpoint{}, err
		}
	}
	e := Endpoint{Address: host}
	if port != "*" {
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return Endpoint{}, err
		}
		n := uint16(p)
		e.Port = &n
	}
	return e, nil
}
