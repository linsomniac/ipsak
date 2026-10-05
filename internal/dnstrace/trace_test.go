package dnstrace

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func rr(s string) dns.RR {
	r, e := dns.NewRR(s)
	if e != nil {
		panic(e)
	}
	return r
}
func opts() Options {
	return Options{Roots: []string{"192.0.2.1:53"}, Type: dns.TypeA, MaxHops: 8, QueryTimeout: time.Second}
}
func TestDelegationBailiwickAndAuthoritativeAnswer(t *testing.T) {
	var queried []string
	x := Resolver{Exchange: func(ctx context.Context, q *dns.Msg, server string) (*dns.Msg, error) {
		if q.RecursionDesired {
			t.Error("recursive query")
		}
		queried = append(queried, server)
		m := new(dns.Msg)
		m.SetReply(q)
		if server == "192.0.2.1:53" {
			m.Ns = []dns.RR{rr("example. 60 IN NS ns.example."), rr("example. 60 IN NS outside.test.")}
			m.Extra = []dns.RR{rr("ns.example. 60 IN A 192.0.2.2"), rr("outside.test. 60 IN A 192.0.2.99")}
		} else {
			m.Authoritative = true
			m.Answer = []dns.RR{rr("www.example. 60 IN A 192.0.2.5"), rr("www.example. 60 CH A 192.0.2.6")}
		}
		return m, nil
	}, ResolveNS: func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("fixture fallback unavailable")
	}}
	r, err := x.Trace(context.Background(), "www.example", opts())
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "answer" || len(r.Hops) != 2 || len(r.Answers) != 1 || len(r.Hops[0].Fallback) != 1 || strings.Contains(strings.Join(queried, ","), "192.0.2.99") {
		t.Fatalf("%+v queries=%v", r, queried)
	}
}
func TestStructuralRejectionAndNegativeResults(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("www.example.", dns.TypeA)
	for _, kind := range []string{"wrong-question", "upward", "bad-owner", "nonauth", "nxdomain-no-soa"} {
		m := new(dns.Msg)
		m.SetReply(q)
		switch kind {
		case "wrong-question":
			m.Question[0].Name = "other.example."
		case "upward":
			m.Ns = []dns.RR{rr(". 60 IN NS a.root.")}
		case "bad-owner":
			m.Ns = []dns.RR{rr("evil.test. 60 IN NS ns.evil.test.")}
		case "nonauth":
			m.Answer = []dns.RR{rr("www.example. 60 IN A 192.0.2.1")}
		case "nxdomain-no-soa":
			m.Authoritative = true
			m.Rcode = dns.RcodeNameError
		}
		if _, _, _, e := classify(m, "www.example.", "example.", dns.TypeA); e == nil {
			t.Errorf("accepted %s", kind)
		}
	}
	for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeNameError} {
		m := new(dns.Msg)
		m.SetReply(q)
		m.Authoritative = true
		m.Rcode = rcode
		m.Ns = []dns.RR{rr("example. 60 IN SOA ns.example. hostmaster.example. 1 2 3 4 5")}
		status, _, _, err := classify(m, "www.example.", "example.", dns.TypeA)
		if err != nil || status != "nodata" && status != "nxdomain" {
			t.Fatalf("%s %v", status, err)
		}
	}
}
func TestCNAMECycleAndPartialFailure(t *testing.T) {
	x := Resolver{Exchange: func(ctx context.Context, q *dns.Msg, s string) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetReply(q)
		m.Authoritative = true
		dest := "other.example."
		if q.Question[0].Name == dest {
			dest = "www.example."
		}
		m.Answer = []dns.RR{rr(q.Question[0].Name + " 60 IN CNAME " + dest)}
		return m, nil
	}}
	r, err := x.Trace(context.Background(), "www.example", opts())
	if err == nil || len(r.Hops) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestAliasExtractionRejectsOtherClass(t *testing.T) {
	var names []string
	x := Resolver{Exchange: func(ctx context.Context, q *dns.Msg, s string) (*dns.Msg, error) {
		names = append(names, q.Question[0].Name)
		m := new(dns.Msg)
		m.SetReply(q)
		m.Authoritative = true
		if q.Question[0].Name == "www.example." {
			m.Answer = []dns.RR{rr("www.example. 60 CH CNAME wrong.example."), rr("www.example. 60 IN CNAME right.example.")}
		} else {
			m.Answer = []dns.RR{rr("right.example. 60 IN A 192.0.2.3")}
		}
		return m, nil
	}}
	r, e := x.Trace(context.Background(), "www.example", opts())
	if e != nil || len(names) != 2 || names[1] != "right.example." || r.Status != "answer" {
		t.Fatalf("%v %+v %v", names, r, e)
	}
}
func TestParallelRaceAndNativeCancellation(t *testing.T) {
	s, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	entered := make(chan struct{})
	go func() { b := make([]byte, 2048); s.ReadFrom(b); close(entered) }()
	o := opts()
	o.Roots = []string{s.LocalAddr().String()}
	o.QueryTimeout = 10 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := (Resolver{}).Trace(ctx, "example.test", o); done <- e }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("native DNS cancellation stalled")
	}
	o = opts()
	o.Roots = append(o.Roots, "192.0.2.2:53")
	all := make(chan struct{}, 2)
	release := make(chan struct{})
	x := Resolver{Exchange: func(ctx context.Context, q *dns.Msg, s string) (*dns.Msg, error) {
		all <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if s == "192.0.2.2:53" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		m := new(dns.Msg)
		m.SetReply(q)
		m.Authoritative = true
		m.Answer = []dns.RR{rr("example.test. 1 IN A 192.0.2.3")}
		return m, nil
	}}
	go func() { <-all; <-all; close(release) }()
	r, e := x.Trace(context.Background(), "example.test", o)
	if e != nil || r.Status != "answer" || len(r.Hops[0].Observations) != 2 {
		t.Fatalf("%+v %v", r, e)
	}
}
