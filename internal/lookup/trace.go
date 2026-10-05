package lookup

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type traceBuffer struct {
	buffer    bytes.Buffer
	truncated bool
}

func (b *traceBuffer) Len() int       { return b.buffer.Len() }
func (b *traceBuffer) String() string { return b.buffer.String() }

func (b *traceBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := (64 << 10) - b.Len()
	if len(p) > remaining {
		b.truncated = true
		p = p[:remaining]
	}
	_, _ = b.buffer.Write(p)
	return n, nil
}

type TraceResult struct {
	Engine    string            `json:"engine"`
	Output    string            `json:"output"`
	Truncated bool              `json:"truncated,omitempty"`
	Networks  map[string]ASN    `json:"networks,omitempty"`
	Errors    map[string]string `json:"errors,omitempty"`
	Note      string            `json:"note,omitempty"`
}

func (s *Service) Trace(ctx context.Context, ip netip.Addr, probes int, withASN bool) (any, error) {
	if probes < 1 || probes > 10 {
		return nil, fmt.Errorf("probes must be between 1 and 10")
	}
	name := "traceroute"
	args := []string{"-n", "-m", "30", "-q", strconv.Itoa(probes), "-w", "1"}
	if ip.Is6() {
		if runtime.GOOS == "darwin" {
			name = "traceroute6"
		} else {
			args = append(args, "-6")
		}
	}
	path, err := exec.LookPath(name)
	note := ""
	if err != nil {
		name = "tracepath"
		path, err = exec.LookPath(name)
		args = []string{"-n", "-m", "30"}
		if ip.Is6() {
			args = append(args, "-6")
		}
		note = "tracepath controls its own probe count; --probes does not apply"
	}
	if err != nil {
		return nil, fmt.Errorf("install traceroute or tracepath to use trace")
	}
	args = append(args, ip.String())
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.WaitDelay = time.Second
	var b traceBuffer
	cmd.Stdout = &b
	cmd.Stderr = &b
	err = cmd.Run()
	r := TraceResult{Engine: name, Output: strings.TrimSpace(b.String()), Truncated: b.truncated, Note: note}
	if err != nil {
		if ctx.Err() != nil {
			return r, ctx.Err()
		}
		return r, fmt.Errorf("%s: %w", name, err)
	}
	if withASN {
		r.Networks = map[string]ASN{}
		r.Errors = map[string]string{}
		addresses := map[netip.Addr]bool{}
		for _, field := range strings.Fields(r.Output) {
			if a, e := netip.ParseAddr(strings.Trim(field, "()")); e == nil && Classify(a) == "Public" {
				addresses[a] = true
			}
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		semaphore := make(chan struct{}, 8)
		for a := range addresses {
			wg.Add(1)
			go func(a netip.Addr) {
				defer wg.Done()
				select {
				case semaphore <- struct{}{}:
				case <-ctx.Done():
					mu.Lock()
					r.Errors[a.String()] = ctx.Err().Error()
					mu.Unlock()
					return
				}
				defer func() { <-semaphore }()
				asn, e := s.DNS.ASN(ctx, a)
				var nameErr error
				if e == nil {
					var data any
					data, nameErr = s.DNS.ASNName(ctx, asn.Number)
					if nameErr == nil {
						asn.Name = data.(map[string]string)["name"]
					}
				}
				mu.Lock()
				defer mu.Unlock()
				if e != nil {
					r.Errors[a.String()] = e.Error()
				} else {
					r.Networks[a.String()] = asn
					if nameErr != nil {
						r.Errors[a.String()] = "ASN name: " + nameErr.Error()
					}
				}
			}(a)
		}
		wg.Wait()
		if len(r.Errors) > 0 {
			return r, fmt.Errorf("some hop ASN lookups failed")
		}
	}
	return r, nil
}
