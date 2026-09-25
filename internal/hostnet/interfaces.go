package hostnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Counters struct {
	RXBytes   uint64 `json:"rx_bytes"`
	TXBytes   uint64 `json:"tx_bytes"`
	RXPackets uint64 `json:"rx_packets"`
	TXPackets uint64 `json:"tx_packets"`
	RXErrors  uint64 `json:"rx_errors"`
	TXErrors  uint64 `json:"tx_errors"`
	RXDropped uint64 `json:"rx_dropped"`
	TXDropped uint64 `json:"tx_dropped"`
}
type Throughput struct {
	ElapsedSeconds   float64 `json:"elapsed_seconds"`
	RXBytesPerSecond float64 `json:"rx_bytes_per_second"`
	TXBytesPerSecond float64 `json:"tx_bytes_per_second"`
}
type Interface struct {
	Name             string      `json:"name"`
	Index            int         `json:"index"`
	MTU              int         `json:"mtu"`
	MAC              string      `json:"mac,omitempty"`
	Up               bool        `json:"up"`
	Flags            []string    `json:"flags"`
	Addresses        []string    `json:"addresses"`
	AddressError     string      `json:"address_error,omitempty"`
	OperationalState string      `json:"operational_state"`
	Counters         *Counters   `json:"counters"`
	CountersStatus   string      `json:"counters_status"`
	Throughput       *Throughput `json:"throughput"`
	ThroughputStatus string      `json:"throughput_status"`
}
type InterfaceReport struct {
	Interfaces []Interface `json:"interfaces"`
	Notes      []string    `json:"notes"`
}

// Interfaces is shared with doctor. An empty name selects every interface.
func Interfaces(ctx context.Context, name string) (InterfaceReport, error) {
	r := InterfaceReport{Interfaces: []Interface{}, Notes: []string{}}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	list, err := net.Interfaces()
	if err != nil {
		return r, err
	}
	if len(list) > 4096 {
		return r, fmt.Errorf("interface table exceeds 4096 entries")
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Index < list[j].Index })
	var addressErr error
	for _, v := range list {
		if err = ctx.Err(); err != nil {
			return r, err
		}
		if name != "" && v.Name != name {
			continue
		}
		entry := Interface{Name: v.Name, Index: v.Index, MTU: v.MTU, MAC: v.HardwareAddr.String(), Up: v.Flags&net.FlagUp != 0, Addresses: []string{}, Flags: []string{}, OperationalState: "unavailable", CountersStatus: "unavailable on " + runtime.GOOS, ThroughputStatus: "not sampled"}
		if v.Flags != 0 {
			entry.Flags = strings.Split(v.Flags.String(), "|")
		}
		addrs, e := v.Addrs()
		if e != nil {
			entry.AddressError = e.Error()
			addressErr = errors.Join(addressErr, fmt.Errorf("interface %s addresses: %w", v.Name, e))
		} else {
			for _, a := range addrs {
				entry.Addresses = append(entry.Addresses, a.String())
			}
			sort.Strings(entry.Addresses)
		}
		if runtime.GOOS == "linux" {
			base := filepath.Join("/sys/class/net", v.Name)
			if b, e := readSmall(filepath.Join(base, "operstate")); e == nil {
				entry.OperationalState = strings.TrimSpace(string(b))
			}
			c, e := readCounters(base)
			if e != nil {
				entry.CountersStatus = "unavailable: " + e.Error()
			} else {
				entry.Counters = c
				entry.CountersStatus = "available"
			}
		}
		r.Interfaces = append(r.Interfaces, entry)
	}
	if name != "" && len(r.Interfaces) == 0 {
		return r, fmt.Errorf("interface %q does not exist", name)
	}
	return r, errors.Join(addressErr, ctx.Err())
}
func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil {
		return nil, err
	}
	if len(b) > 1024 {
		return nil, fmt.Errorf("oversize counter file")
	}
	return b, nil
}
func readCounters(base string) (*Counters, error) {
	c := &Counters{}
	for _, field := range []struct {
		name  string
		value *uint64
	}{{"rx_bytes", &c.RXBytes}, {"tx_bytes", &c.TXBytes}, {"rx_packets", &c.RXPackets}, {"tx_packets", &c.TXPackets}, {"rx_errors", &c.RXErrors}, {"tx_errors", &c.TXErrors}, {"rx_dropped", &c.RXDropped}, {"tx_dropped", &c.TXDropped}} {
		b, err := readSmall(filepath.Join(base, "statistics", field.name))
		if err != nil {
			return nil, err
		}
		value, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid %s counter", field.name)
		}
		*field.value = value
	}
	return c, nil
}
func SampleInterfaces(ctx context.Context, name string, interval time.Duration) (InterfaceReport, error) {
	if interval < 100*time.Millisecond || interval > 30*time.Second {
		return InterfaceReport{}, fmt.Errorf("sample interval must be between 100ms and 30s")
	}
	first, err := Interfaces(ctx, name)
	if err != nil {
		return first, err
	}
	start := time.Now()
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return first, ctx.Err()
	case <-timer.C:
	}
	second, err := Interfaces(ctx, name)
	if err != nil {
		return first, err
	}
	return mergeSamples(first, second, time.Since(start)), nil
}
func mergeSamples(first, second InterfaceReport, elapsed time.Duration) InterfaceReport {
	prior := map[string]Interface{}
	for _, v := range first.Interfaces {
		prior[v.Name] = v
	}
	seen := map[string]bool{}
	for i := range second.Interfaces {
		v := &second.Interfaces[i]
		seen[v.Name] = true
		old, ok := prior[v.Name]
		v.ThroughputStatus = "unavailable: interface appeared or changed identity"
		if !ok || old.Index != v.Index {
			continue
		}
		v.ThroughputStatus = "unavailable: counters are unavailable"
		if old.Counters == nil || v.Counters == nil {
			continue
		}
		v.ThroughputStatus = "unavailable: counters reset or wrapped"
		if v.Counters.RXBytes < old.Counters.RXBytes || v.Counters.TXBytes < old.Counters.TXBytes {
			continue
		}
		if elapsed <= 0 {
			v.ThroughputStatus = "unavailable: invalid sample duration"
			continue
		}
		seconds := elapsed.Seconds()
		v.Throughput = &Throughput{ElapsedSeconds: seconds, RXBytesPerSecond: float64(v.Counters.RXBytes-old.Counters.RXBytes) / seconds, TXBytesPerSecond: float64(v.Counters.TXBytes-old.Counters.TXBytes) / seconds}
		v.ThroughputStatus = "available"
	}
	for _, v := range first.Interfaces {
		if !seen[v.Name] {
			v.Throughput = nil
			v.ThroughputStatus = "unavailable: interface disappeared; counters are from first sample"
			second.Interfaces = append(second.Interfaces, v)
		}
	}
	sort.Slice(second.Interfaces, func(i, j int) bool { return second.Interfaces[i].Index < second.Interfaces[j].Index })
	return second
}
