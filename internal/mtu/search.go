// Package mtu measures usable packet sizes without treating silence as size evidence.
package mtu

import (
	"context"
	"fmt"
	"time"
)

type Options struct {
	Min, Max, Attempts int
	ProbeTimeout       time.Duration
}

func (o Options) Validate(ipv6 bool) error {
	minimum := 68
	if ipv6 {
		minimum = 1280
	}
	if o.Min < minimum || o.Max < o.Min || o.Max > 65535 {
		return fmt.Errorf("packet sizes must satisfy %d <= min <= max <= 65535 (including IP headers)", minimum)
	}
	if o.Attempts < 1 || o.Attempts > 3 || o.ProbeTimeout <= 0 || o.ProbeTimeout > time.Minute {
		return fmt.Errorf("attempts must be 1–3 and probe timeout greater than zero and at most 1m")
	}
	return nil
}

type Probe struct {
	Size        int     `json:"size"`
	Status      string  `json:"status"`
	RTTMS       float64 `json:"rtt_ms,omitempty"`
	ReportedMTU int     `json:"reported_mtu,omitempty"`
	Source      string  `json:"source,omitempty"`
	Error       string  `json:"error,omitempty"`
}

type Prober interface {
	Probe(context.Context, int) (Probe, error)
}

type Report struct {
	Address          string  `json:"address"`
	IPVersion        int     `json:"ip_version"`
	Conclusion       string  `json:"conclusion"`
	LargestConfirmed *int    `json:"largest_confirmed"`
	UpperBound       *int    `json:"upper_bound"`
	SmallestRejected *int    `json:"smallest_rejected"`
	PathMTU          *int    `json:"path_mtu"`
	RequestedMax     int     `json:"requested_max"`
	Probes           []Probe `json:"probes"`
	Note             string  `json:"note"`
}

// Search performs adaptive probes sequentially. Only a matching too-big response
// or local EMSGSIZE can lower the upper bound; a timed-out probe cannot.
func Search(ctx context.Context, p Prober, address string, ipv6 bool, o Options) (Report, error) {
	r := Report{Address: address, IPVersion: 4, Conclusion: "inconclusive", RequestedMax: o.Max, Probes: []Probe{}, Note: "Sizes include IP and ICMP headers; this measures ICMP reachability on the current path."}
	if ipv6 {
		r.IPVersion = 6
	}
	if err := o.Validate(ipv6); err != nil {
		return r, err
	}
	measure := func(size int) (Probe, error) {
		var v Probe
		for range o.Attempts {
			if err := ctx.Err(); err != nil {
				return v, err
			}
			probeCtx, cancel := context.WithTimeout(ctx, o.ProbeTimeout)
			var err error
			v, err = p.Probe(probeCtx, size)
			cancel()
			v.Size = size
			if err != nil {
				v.Status, v.Error = "error", err.Error()
			}
			r.Probes = append(r.Probes, v)
			if err != nil {
				return v, err
			}
			if v.Status != "timeout" {
				return v, nil
			}
		}
		return v, fmt.Errorf("no reply at %d bytes after %d attempt(s); filtering or loss may be responsible, MTU is inconclusive", size, o.Attempts)
	}
	baseline, err := measure(o.Min)
	if err != nil {
		return r, err
	}
	if baseline.Status == "too_big" {
		r.SmallestRejected = ptr(o.Min)
		r.UpperBound = ptr(o.Min - 1)
		if baseline.ReportedMTU > 0 && baseline.ReportedMTU < *r.UpperBound {
			r.UpperBound = ptr(baseline.ReportedMTU)
		}
		r.Conclusion = "below_minimum"
		return r, fmt.Errorf("minimum probe of %d bytes was rejected; use a smaller --min where supported", o.Min)
	}
	if baseline.Status != "reply" {
		return r, fmt.Errorf("unexpected probe status %q", baseline.Status)
	}
	lower, upper := o.Min, o.Max
	r.LargestConfirmed = ptr(lower)
	if lower == upper {
		r.Conclusion = "at_least"
		return r, nil
	}
	size := upper
	for lower < upper {
		v, err := measure(size)
		if err != nil {
			return r, err
		}
		switch v.Status {
		case "reply":
			lower = size
			r.LargestConfirmed = ptr(lower)
		case "too_big":
			if r.SmallestRejected == nil || size < *r.SmallestRejected {
				r.SmallestRejected = ptr(size)
			}
			upper = size - 1
			if v.ReportedMTU > 0 && v.ReportedMTU < upper {
				upper = v.ReportedMTU
			}
			r.UpperBound = ptr(upper)
			if upper < lower {
				r.Conclusion = "inconsistent"
				return r, fmt.Errorf("size evidence contradicts a previously confirmed probe; the path may have changed")
			}
		default:
			return r, fmt.Errorf("unexpected probe status %q", v.Status)
		}
		size = lower + (upper-lower+1)/2
	}
	if r.UpperBound != nil {
		r.Conclusion, r.PathMTU = "exact", ptr(lower)
	} else {
		r.Conclusion = "at_least"
	}
	return r, nil
}

func ptr(n int) *int { return &n }
