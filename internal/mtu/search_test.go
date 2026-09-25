package mtu

import (
	"context"
	"errors"
	"testing"
	"time"
)

type probeFunc func(context.Context, int) (Probe, error)

func (f probeFunc) Probe(ctx context.Context, size int) (Probe, error) { return f(ctx, size) }

func options() Options { return Options{Min: 576, Max: 1500, Attempts: 2, ProbeTimeout: time.Second} }

func TestSearchExactWithAndWithoutRouterHint(t *testing.T) {
	for _, hint := range []int{0, 1400} {
		p := probeFunc(func(_ context.Context, size int) (Probe, error) {
			if size <= 1400 {
				return Probe{Status: "reply"}, nil
			}
			return Probe{Status: "too_big", ReportedMTU: hint}, nil
		})
		r, err := Search(context.Background(), p, "192.0.2.1", false, options())
		if err != nil || r.Conclusion != "exact" || r.PathMTU == nil || *r.PathMTU != 1400 || *r.LargestConfirmed != 1400 || *r.UpperBound != 1400 || len(r.Probes) > 12 {
			t.Fatal(r, err)
		}
	}
}

func TestSearchCeilingIsLowerBound(t *testing.T) {
	p := probeFunc(func(context.Context, int) (Probe, error) { return Probe{Status: "reply"}, nil })
	r, err := Search(context.Background(), p, "::1", true, Options{1280, 9000, 1, time.Second})
	if err != nil || r.Conclusion != "at_least" || *r.LargestConfirmed != 9000 || r.PathMTU != nil || r.UpperBound != nil || len(r.Probes) != 2 {
		t.Fatal(r, err)
	}
}

func TestSearchTimeoutNeverLowersUpperBound(t *testing.T) {
	for _, baselineTimeout := range []bool{false, true} {
		p := probeFunc(func(_ context.Context, size int) (Probe, error) {
			if size == 576 && !baselineTimeout {
				return Probe{Status: "reply"}, nil
			}
			return Probe{Status: "timeout"}, nil
		})
		r, err := Search(context.Background(), p, "192.0.2.1", false, options())
		if err == nil || r.Conclusion != "inconclusive" || r.UpperBound != nil || r.PathMTU != nil || r.SmallestRejected != nil {
			t.Fatal(r, err)
		}
		if !baselineTimeout && (r.LargestConfirmed == nil || *r.LargestConfirmed != 576 || len(r.Probes) != 3) {
			t.Fatal(r)
		}
	}
}

func TestSearchContradictionBaselineAndCancellation(t *testing.T) {
	r, err := Search(context.Background(), probeFunc(func(_ context.Context, size int) (Probe, error) {
		if size == 576 {
			return Probe{Status: "reply"}, nil
		}
		return Probe{Status: "too_big", ReportedMTU: 500}, nil
	}), "192.0.2.1", false, options())
	if err == nil || r.Conclusion != "inconsistent" || r.PathMTU != nil {
		t.Fatal(r, err)
	}
	r, err = Search(context.Background(), probeFunc(func(context.Context, int) (Probe, error) { return Probe{Status: "too_big"}, nil }), "192.0.2.1", false, options())
	if err == nil || r.Conclusion != "below_minimum" || r.LargestConfirmed != nil {
		t.Fatal(r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err = Search(ctx, probeFunc(func(context.Context, int) (Probe, error) { t.Fatal("probe after cancellation"); return Probe{}, nil }), "192.0.2.1", false, options())
	if !errors.Is(err, context.Canceled) || len(r.Probes) != 0 {
		t.Fatal(r, err)
	}
}

func TestOptionsValidate(t *testing.T) {
	for _, o := range []Options{{67, 1500, 1, time.Second}, {576, 575, 1, time.Second}, {576, 65536, 1, time.Second}, {576, 1500, 4, time.Second}, {576, 1500, 1, 0}} {
		if err := o.Validate(false); err == nil {
			t.Fatal(o)
		}
	}
	if err := options().Validate(true); err == nil {
		t.Fatal("IPv6 minimum")
	}
}
