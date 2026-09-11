package lookup

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCalculate(t *testing.T) {
	for _, tt := range []struct{ cidr, network, first, last, count, usable, broadcast string }{
		{"10.0.0.99/24", "10.0.0.0", "10.0.0.1", "10.0.0.254", "256", "254", "10.0.0.255"},
		{"0.0.0.0/0", "0.0.0.0", "0.0.0.1", "255.255.255.254", "4294967296", "4294967294", "255.255.255.255"},
		{"192.0.2.10/31", "192.0.2.10", "192.0.2.10", "192.0.2.11", "2", "2", "192.0.2.11"},
		{"192.0.2.1/32", "192.0.2.1", "192.0.2.1", "192.0.2.1", "1", "1", "192.0.2.1"},
		{"::/0", "::", "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "340282366920938463463374607431768211456", "340282366920938463463374607431768211455", ""},
		{"2001:db8::/64", "2001:db8::", "2001:db8::1", "2001:db8::ffff:ffff:ffff:ffff", "18446744073709551616", "18446744073709551615", ""},
		{"2001:db8::/127", "2001:db8::", "2001:db8::", "2001:db8::1", "2", "2", ""},
		{"::1/128", "::1", "::1", "::1", "1", "1", ""},
	} {
		t.Run(tt.cidr, func(t *testing.T) {
			r, err := Calculate(tt.cidr)
			if err != nil {
				t.Fatal(err)
			}
			if r.Network != tt.network || r.FirstHost != tt.first || r.LastHost != tt.last || r.Addresses != tt.count || r.Usable != tt.usable || r.Broadcast != tt.broadcast {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

func TestTargetNormalization(t *testing.T) {
	for input, want := range map[string]string{" https://Example.COM:443/path ": "example.com", "example.com:443": "example.com", "[2001:db8::1]:80": "2001:db8::1", "[::1]": "::1", "::ffff:192.0.2.1": "192.0.2.1", "10.0.0.7/24": "10.0.0.0/24", "BÜCHER.de": "xn--bcher-kva.de", "localhost": "localhost", "fe80::1%eth0": "fe80::1%eth0"} {
		t.Run(input, func(t *testing.T) {
			r, err := ParseTarget(input)
			if err != nil || r.Name != want {
				t.Fatalf("got %+v, %v; want %s", r, err, want)
			}
		})
	}
	for _, input := range []string{"", "999.1.2.3", "10.1/33", "--help", "bad..name", "a\x1bb.com", "[::1]junk", strings.Repeat("a", 64) + ".org"} {
		if _, err := ParseTarget(input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}

func TestClassification(t *testing.T) {
	for input, want := range map[string]string{"8.8.8.8": "Public", "192.0.0.9": "Public", "192.0.0.10": "Public", "192.0.0.8": "IETF protocol assignments", "255.255.255.255": "Limited broadcast", "::ffff:10.1.1.1": "Private", "100.64.1.1": "Shared address (CGNAT)", "203.0.113.5": "Documentation", "3fff::1": "Documentation", "fe80::1%eth0": "Link-local", "2606:4700:4700::1111": "Public"} {
		if got := Classify(netip.MustParseAddr(input)); got != want {
			t.Errorf("%s: got %s, want %s", input, got, want)
		}
	}
}

func TestRunnerDependenciesAndOverlap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	rpkiStarted := make(chan struct{})
	tasks := []Task{
		{Key: "slow", Run: func(ctx context.Context, _ map[string]Section) (any, error) {
			close(slowStarted)
			select {
			case <-releaseSlow:
				return "slow", nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}},
		{Key: "asn", Run: func(ctx context.Context, _ map[string]Section) (any, error) {
			select {
			case <-slowStarted:
				return 123, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}},
		{Key: "rpki", Depends: []string{"asn"}, Run: func(_ context.Context, d map[string]Section) (any, error) {
			if d["asn"].Data != 123 {
				t.Error("dependency data missing")
			}
			close(rpkiStarted)
			return "valid", nil
		}},
	}
	ch, err := Run(ctx, tasks)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-rpkiStarted:
	case <-ctx.Done():
		t.Fatal("RPKI blocked behind unrelated slow provider")
	}
	close(releaseSlow)
	r := NewReport("info", "test", tasks)
	for s := range ch {
		r.Apply(s)
	}
	for _, s := range r.Sections {
		if s.Status != "ok" {
			t.Fatalf("%+v", s)
		}
	}
}

func TestRunnerPartialFailureAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	tasks := []Task{{Key: "bad", Run: func(context.Context, map[string]Section) (any, error) {
		return map[string]int{"partial": 1}, errors.New("failure")
	}}, {Key: "child", Depends: []string{"bad"}, Run: func(context.Context, map[string]Section) (any, error) {
		t.Error("failed dependency ran")
		return nil, nil
	}}, {Key: "cancel", Run: func(ctx context.Context, _ map[string]Section) (any, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}}
	ch, err := Run(ctx, tasks)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	cancel()
	for s := range ch {
		if s.Key == "cancel" && s.Status != "error" {
			t.Errorf("%+v", s)
		}
	}
	noop := func(context.Context, map[string]Section) (any, error) { return nil, nil }
	for _, bad := range [][]Task{{{Key: "x", Depends: []string{"missing"}, Run: noop}}, {{Key: "x", Depends: []string{"x"}, Run: noop}}, {{Key: "x", Run: noop}, {Key: "x", Run: noop}}} {
		if _, err := Run(context.Background(), bad); err == nil {
			t.Error("accepted invalid graph")
		}
	}
}

func TestInfoDependencies(t *testing.T) {
	s := NewService()
	target, _ := ParseTarget("mail.example.com")
	tasks, err := s.Tasks("info", target, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		if task.Key == "dns" && len(task.Depends) != 0 {
			t.Error("forward DNS must not depend on IP resolution")
		}
		if task.Key == "rpki" && (len(task.Depends) != 1 || task.Depends[0] != "asn") {
			t.Error("RPKI must depend only on ASN")
		}
	}
}
