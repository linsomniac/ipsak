package watch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func options() Options {
	return Options{Count: 1, Interval: 100 * time.Millisecond, Timeout: time.Second, Concurrency: 4}
}

func TestBoundedWorkersAndHistory(t *testing.T) {
	targets := make([]Target, 128)
	for i := range targets {
		targets[i] = Target{Name: fmt.Sprintf("service-%d", i)}
	}
	o := options()
	o.Count = 2
	var active, peak, calls atomic.Int32
	check := func(context.Context, Target) Check {
		a := active.Add(1)
		for {
			p := peak.Load()
			if p >= a || peak.CompareAndSwap(p, a) {
				break
			}
		}
		defer active.Add(-1)
		n := calls.Add(1)
		time.Sleep(time.Millisecond)
		if n <= 128 {
			return Check{Err: errors.New("down")}
		}
		return Check{}
	}
	r, e := Run(context.Background(), targets, o, check, nil)
	if e == nil || peak.Load() > 4 || peak.Load() < 2 || r.EventsDropped != 128 || len(r.Events) != 128 {
		t.Fatalf("peak=%d drops=%d retained=%d err=%v", peak.Load(), r.EventsDropped, len(r.Events), e)
	}
	for _, s := range r.Targets {
		if s.Outages != 1 || s.Failures != 1 || s.Successes != 1 {
			t.Fatal(s)
		}
	}
}
func TestDNSMatchingAnswers(t *testing.T) {
	c, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ready := make(chan struct{})
	s := &dns.Server{PacketConn: c, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		rr := func(s string) dns.RR {
			v, e := dns.NewRR(s)
			if e != nil {
				panic(e)
			}
			return v
		}
		switch q.Question[0].Name {
		case "good.test.":
			m.Answer = []dns.RR{rr("good.test. 60 IN A 192.0.2.1")}
		case "alias.test.":
			m.Answer = []dns.RR{rr("alias.test. 60 IN CNAME good.test."), rr("good.test. 60 IN A 192.0.2.1")}
		case "wrong.test.":
			m.Answer = []dns.RR{rr("unrelated.test. 60 IN A 192.0.2.1")}
		case "nxdomain.test.":
			m.Rcode = dns.RcodeNameError
		}
		w.WriteMsg(m)
	})}
	go s.ActivateAndServe()
	<-ready
	defer s.Shutdown()
	check, cleanup, _ := NewChecker(c.LocalAddr().String())
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for name, wantErr := range map[string]bool{"good.test": false, "alias.test": false, "wrong.test": true, "empty.test": true, "nxdomain.test": true} {
		target, _ := Parse("dns://" + name)
		if r := check(ctx, target); (r.Err != nil) != wantErr {
			t.Fatalf("%s: %+v", name, r)
		}
	}
}
func TestTargetsAndBounds(t *testing.T) {
	for _, s := range []string{"https://example.com/a", "tcp://[::1]:443", "dns://example.com?type=AAAA", "dns://_sip._tcp.example?type=SRV", "dns://.?type=NS", "icmp://[::1]"} {
		if _, e := Parse(s); e != nil {
			t.Errorf("%s: %v", s, e)
		}
	}
	for _, s := range []string{"example.com", "tcp://host", "ftp://host", "dns://x?bad=1", "icmp://224.0.0.1", "https://user:secret@host/", "dns://x?type=AXFR"} {
		if _, e := Parse(s); e == nil {
			t.Errorf("accepted %s", s)
		}
	}
	o := options()
	o.Concurrency = 100
	if o.Validate([]Target{{Name: "x"}}) == nil {
		t.Fatal("unbounded concurrency")
	}
}
func TestParallelChecksSnapshotsAndFailures(t *testing.T) {
	targets := []Target{{Name: "one"}, {Name: "two"}, {Name: "three"}, {Name: "four"}}
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	var active, peak atomic.Int32
	check := func(ctx context.Context, target Target) Check {
		n := active.Add(1)
		for {
			p := peak.Load()
			if p >= n || peak.CompareAndSwap(p, n) {
				break
			}
		}
		defer active.Add(-1)
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return Check{Err: ctx.Err()}
		}
		if target.Name == "two" {
			return Check{Err: errors.New("refused")}
		}
		return Check{Detail: "ready"}
	}
	go func() {
		for range targets {
			<-entered
		}
		close(release)
	}()
	var snapshots []Result
	r, err := Run(context.Background(), targets, options(), check, func(r Result) { snapshots = append(snapshots, r) })
	if err == nil || peak.Load() != 4 || r.Targets[1].Failures != 1 || r.Targets[0].Successes != 1 {
		t.Fatalf("r=%+v err=%v peak=%d", r, err, peak.Load())
	}
	if snapshots[0].Targets[0].Checks != 0 || len(snapshots[0].Events) != 0 {
		t.Fatal("snapshot mutated")
	}
}
func TestRecoveryReadinessAndPending(t *testing.T) {
	o := options()
	o.Count = 3
	o.Until = "all-up"
	calls := 0
	r, err := Run(context.Background(), []Target{{Name: "one"}}, o, func(context.Context, Target) Check {
		calls++
		if calls == 1 {
			return Check{Err: errors.New("starting")}
		}
		return Check{}
	}, nil)
	if err != nil || !r.ConditionMet || r.Rounds != 2 || len(r.Events) != 2 || r.Events[1].Kind != "recovered" {
		t.Fatalf("%+v %v", r, err)
	}
	o.Until = ""
	o.Count = 0
	o.Duration = 30 * time.Millisecond
	r, err = Run(context.Background(), []Target{{Name: "one"}}, o, func(ctx context.Context, _ Target) Check { <-ctx.Done(); return Check{Err: ctx.Err()} }, nil)
	if err == nil || r.Targets[0].Pending != 1 || r.Targets[0].Failures != 0 || r.Targets[0].Checks != 0 {
		t.Fatalf("pending %+v %v", r, err)
	}
}
func TestFailureConcurrentWithCancellationSurvives(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err := Run(ctx, []Target{{Name: "one"}}, options(), func(context.Context, Target) Check { cancel(); return Check{Err: errors.New("HTTP 503")} }, nil)
	if !errors.Is(err, context.Canceled) || r.Targets[0].Failures != 1 || r.Targets[0].Pending != 0 {
		t.Fatalf("%+v %v", r, err)
	}
}
func TestNativeHTTPAndTCP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "http://127.0.0.1:1")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(503)
	}))
	defer server.Close()
	check, closeIdle, err := NewChecker("")
	if err != nil {
		t.Fatal(err)
	}
	defer closeIdle()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for path, wantErr := range map[string]bool{"/redirect": false, "/fail": true} {
		target, e := Parse(server.URL + path)
		if e != nil {
			t.Fatal(e)
		}
		if got := check(ctx, target); (got.Err != nil) != wantErr {
			t.Fatalf("%s %+v", path, got)
		}
	}
	target, _ := Parse("tcp://" + strings.TrimPrefix(server.URL, "http://"))
	if c := check(ctx, target); c.Err != nil {
		t.Fatal(c.Err)
	}
}
func TestNativeDNSCancellation(t *testing.T) {
	s, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	check, cleanup, _ := NewChecker(s.LocalAddr().String())
	defer cleanup()
	target, _ := Parse("dns://example.test")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered := make(chan struct{})
	go func() { buf := make([]byte, 2048); s.ReadFrom(buf); close(entered) }()
	done := make(chan Check, 1)
	go func() { done <- check(ctx, target) }()
	<-entered
	start := time.Now()
	cancel()
	select {
	case c := <-done:
		if !errors.Is(c.Err, context.Canceled) {
			t.Fatal(c.Err)
		}
		if time.Since(start) > time.Second {
			t.Fatal("slow cancel")
		}
	case <-time.After(time.Second):
		t.Fatal("DNS cancellation did not close socket")
	}
}
