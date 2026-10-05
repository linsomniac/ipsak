// Package natprobe reports STUN mappings. It does not classify NAT behavior.
package natprobe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const cookie uint32 = 0x2112a442

type Observation struct {
	Server      string  `json:"server"`
	Endpoint    string  `json:"endpoint,omitempty"`
	Family      string  `json:"family,omitempty"`
	LocalSocket string  `json:"local_socket,omitempty"`
	Mapping     string  `json:"mapping,omitempty"`
	DurationMS  float64 `json:"duration_ms"`
	Error       string  `json:"error,omitempty"`
}
type Comparison struct {
	Family           string `json:"family"`
	Status           string `json:"status"`
	Responses        int    `json:"responses"`
	DistinctMappings int    `json:"distinct_mappings"`
}
type Result struct {
	Observations []Observation `json:"observations"`
	Comparisons  []Comparison  `json:"comparisons"`
	Note         string        `json:"note"`
}

func (r Result) CompactLines() []string {
	lines := []string{fmt.Sprintf("%d STUN server observations", len(r.Observations))}
	for _, observation := range r.Observations {
		line := observation.Server
		if observation.Endpoint != "" && observation.Endpoint != observation.Server {
			line += " → " + observation.Endpoint
		}
		if observation.Family != "" {
			line += " · " + observation.Family
		}
		lines = append(lines, line)
		if observation.Mapping != "" {
			lines = append(lines, fmt.Sprintf("  Mapping %s · %.2f ms", observation.Mapping, observation.DurationMS))
		}
		if observation.LocalSocket != "" {
			lines = append(lines, "  Local socket "+observation.LocalSocket)
		}
		if observation.Error != "" {
			lines = append(lines, "  Error: "+observation.Error)
		}
	}
	for _, comparison := range r.Comparisons {
		lines = append(lines, fmt.Sprintf("%s · %s · %d replies · %d distinct mappings", comparison.Family, strings.ReplaceAll(comparison.Status, "_", " "), comparison.Responses, comparison.DistinctMappings))
	}
	if r.Note != "" {
		lines = append(lines, r.Note)
	}
	return lines
}

func Observe(ctx context.Context, servers []string) (Result, error) {
	r := Result{Observations: make([]Observation, len(servers)), Comparisons: []Comparison{}, Note: "Unauthenticated STUN mapping observations, compared only on the same UDP socket/address family. Equal or different mappings do not establish a NAT type or inbound reachability."}
	if len(servers) == 0 || len(servers) > 8 {
		return r, fmt.Errorf("configure one to eight STUN servers")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	addresses := make([]*net.UDPAddr, len(servers))
	var wg sync.WaitGroup
	for i, server := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Observations[i].Server = server
			host, port, err := net.SplitHostPort(server)
			if err != nil {
				r.Observations[i].Error = err.Error()
				return
			}
			p, e := strconv.Atoi(port)
			if e != nil || p < 1 || p > 65535 {
				r.Observations[i].Error = "invalid STUN port"
				return
			}
			ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if e != nil || len(ips) == 0 {
				r.Observations[i].Error = fmt.Sprintf("resolve STUN server: %v", e)
				return
			}
			ip := ips[0].Unmap()
			addresses[i] = net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(p)))
			r.Observations[i].Endpoint = addresses[i].String()
			r.Observations[i].Family = "udp6"
			if ip.Is4() {
				r.Observations[i].Family = "udp4"
			}
		}()
	}
	wg.Wait()
	groups := map[string][]int{}
	for i, observation := range r.Observations {
		groups[observation.Family] = append(groups[observation.Family], i)
	}
	for _, family := range []string{"udp4", "udp6"} {
		indices := groups[family]
		if len(indices) == 0 {
			continue
		}
		wg.Add(1)
		go func() { defer wg.Done(); observeFamily(ctx, family, indices, addresses, r.Observations) }()
	}
	wg.Wait()
	failed := 0
	for _, o := range r.Observations {
		if o.Error != "" {
			failed++
		}
	}
	for _, family := range []string{"udp4", "udp6"} {
		c := Comparison{Family: family, Status: "insufficient_data"}
		maps := map[string]bool{}
		for _, o := range r.Observations {
			if o.Family == family && o.Mapping != "" {
				c.Responses++
				maps[o.Mapping] = true
			}
		}
		c.DistinctMappings = len(maps)
		if c.Responses >= 2 {
			c.Status = "same_observed_mapping"
			if len(maps) > 1 {
				c.Status = "different_observed_mappings"
			}
		}
		if c.Responses > 0 {
			r.Comparisons = append(r.Comparisons, c)
		}
	}
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	if failed > 0 {
		return r, fmt.Errorf("%d of %d STUN servers failed", failed, len(servers))
	}
	return r, nil
}

func observeFamily(parent context.Context, family string, indices []int, addresses []*net.UDPAddr, out []Observation) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	conn, err := net.ListenUDP(family, nil)
	if err != nil {
		for _, i := range indices {
			out[i].Error = err.Error()
		}
		return
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	type transaction struct {
		index    int
		packet   []byte
		start    time.Time
		next     time.Time
		attempts int
	}
	pending := map[[12]byte]*transaction{}
	for _, i := range indices {
		out[i].LocalSocket = conn.LocalAddr().String()
		p := make([]byte, 20)
		binary.BigEndian.PutUint16(p, 1)
		binary.BigEndian.PutUint32(p[4:], cookie)
		if _, err := rand.Read(p[8:]); err != nil {
			out[i].Error = err.Error()
			continue
		}
		var id [12]byte
		copy(id[:], p[8:])
		pending[id] = &transaction{index: i, packet: p, start: time.Now()}
	}
	buf := make([]byte, 65535) // Holds a complete UDP datagram; never parse silently truncated data.
	for len(pending) > 0 && ctx.Err() == nil {
		now := time.Now()
		for id, t := range pending {
			if !now.Before(t.next) && t.attempts < 3 {
				if _, e := conn.WriteToUDP(t.packet, addresses[t.index]); e != nil {
					out[t.index].Error = e.Error()
					delete(pending, id)
					continue
				}
				t.attempts++
				t.next = now.Add(time.Duration(1<<uint(t.attempts-1)) * 500 * time.Millisecond)
			}
		}
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				continue
			}
			break
		}
		if n < 20 {
			continue
		}
		var id [12]byte
		copy(id[:], buf[8:20])
		t, ok := pending[id]
		if !ok || src.AddrPort() != addresses[t.index].AddrPort() {
			continue
		}
		mapping, err := parseResponse(buf[:n], id)
		if err != nil {
			out[t.index].Error = err.Error()
		} else {
			out[t.index].Mapping = mapping.String()
		}
		out[t.index].DurationMS = float64(time.Since(t.start)) / float64(time.Millisecond)
		delete(pending, id)
	}
	for _, t := range pending {
		out[t.index].DurationMS = float64(time.Since(t.start)) / float64(time.Millisecond)
		out[t.index].Error = "STUN response timeout"
		if parent.Err() != nil {
			out[t.index].Error = parent.Err().Error()
		}
	}
}

func parseResponse(p []byte, id [12]byte) (netip.AddrPort, error) {
	fail := func(s string) (netip.AddrPort, error) { return netip.AddrPort{}, fmt.Errorf("STUN: %s", s) }
	if len(p) < 20 || binary.BigEndian.Uint32(p[4:8]) != cookie || len(p) != 20+int(binary.BigEndian.Uint16(p[2:4])) || len(p)%4 != 0 {
		return fail("invalid message header or length")
	}
	for i := range id {
		if p[8+i] != id[i] {
			return fail("transaction mismatch")
		}
	}
	typ := binary.BigEndian.Uint16(p[:2])
	if typ != 0x0101 && typ != 0x0111 {
		return fail("not a Binding response")
	}
	var mapped, xor netip.AddrPort
	errorCode := "server returned an error"
	for pos := 20; pos < len(p); {
		if pos+4 > len(p) {
			return fail("truncated attribute")
		}
		kind := binary.BigEndian.Uint16(p[pos:])
		size := int(binary.BigEndian.Uint16(p[pos+2:]))
		end := pos + 4 + size
		if end > len(p) {
			return fail("truncated attribute value")
		}
		v := p[pos+4 : end]
		switch kind {
		case 0x0001, 0x0020:
			if len(v) < 4 || v[0] != 0 {
				return fail("invalid mapped address")
			}
			length := 4
			if v[1] == 2 {
				length = 16
			} else if v[1] != 1 {
				return fail("unknown address family")
			}
			if len(v) != 4+length {
				return fail("invalid mapped address length")
			}
			port := binary.BigEndian.Uint16(v[2:])
			b := append([]byte(nil), v[4:]...)
			if kind == 0x0020 {
				port ^= uint16(cookie >> 16)
				mask := p[4:20]
				for j := range b {
					b[j] ^= mask[j]
				}
			}
			ip, ok := netip.AddrFromSlice(b)
			if !ok || port == 0 {
				return fail("invalid mapped endpoint")
			}
			a := netip.AddrPortFrom(ip.Unmap(), port)
			if kind == 0x0020 {
				xor = a
			} else {
				mapped = a
			}
		case 0x0009:
			if len(v) < 4 {
				return fail("invalid error code")
			}
			errorCode = fmt.Sprintf("server error %d: %s", int(v[2]&7)*100+int(v[3]), string(v[4:]))
		case 0x8028:
			if size != 4 || end != len(p) || binary.BigEndian.Uint32(v) != (crc32.ChecksumIEEE(p[:pos])^0x5354554e) {
				return fail("invalid fingerprint")
			}
		case 0x8022, 0x8023: // SOFTWARE and ALTERNATE-SERVER are informational; redirects are not followed.
		default:
			if kind < 0x8000 {
				return fail(fmt.Sprintf("unsupported required attribute 0x%04x", kind))
			}
		}
		pos = (end + 3) &^ 3
		if pos > len(p) {
			return fail("invalid attribute padding")
		}
	}
	if typ == 0x0111 {
		return fail(errorCode)
	}
	if xor.IsValid() {
		return xor, nil
	}
	if mapped.IsValid() {
		return mapped, nil
	}
	return fail("missing mapped address")
}
