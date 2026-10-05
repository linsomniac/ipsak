package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

func TestSessionCoalescedFinalJSONAndOutput(t *testing.T) {
	var out bytes.Buffer
	cmd := &cobra.Command{Use: "fixture"}
	cmd.SetContext(context.Background())
	cmd.SetOut(&out)
	cmd.SetIn(strings.NewReader(""))
	err := runSession(cmd, config{json: true}, "target", "Live", func(ctx context.Context, emit func(any)) (any, error) {
		for i := range 10000 {
			emit(map[string]int{"value": i})
		}
		return map[string]int{"value": 10000}, errors.New("partial fixture")
	})
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 1 {
		t.Fatal(err)
	}
	var r lookup.Report
	d := json.NewDecoder(&out)
	if err = d.Decode(&r); err != nil {
		t.Fatal(err)
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		t.Fatal("more than one JSON report")
	}
	if r.Sections[0].Data.(map[string]any)["value"] != float64(10000) {
		t.Fatal("final snapshot lost")
	}
	cmd.SetOut(reportFailWriter{})
	err = runSession(cmd, config{json: true}, "", "", func(context.Context, func(any)) (any, error) { return "done", nil })
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}
func TestSessionHelpValidationAndPrecancel(t *testing.T) {
	for _, name := range []string{"watch", "bandwidth", "pathwatch", "dnstrace"} {
		out, stderr, code := invoke(name, "--help")
		if code != 0 || stderr != "" || out == "" {
			t.Fatal(name, out, stderr, code)
		}
	}
	for _, args := range [][]string{{"watch", "bad"}, {"watch", "tcp://localhost:80", "--concurrency", "0"}, {"watch", "http://localhost", "--until", "maybe"}, {"bandwidth"}, {"bandwidth", "--listen", "9000", "--duration", "1s"}, {"pathwatch", "127.0.0.1", "--max-hops", "-1"}, {"pathwatch", "127.0.0.1", "-4", "-6"}, {"dnstrace", "example.com", "--type", "AXFR"}} {
		out, _, code := invoke(append(args, "--json")...)
		if code != 2 || out != "" {
			t.Fatal(args, code, out)
		}
	}
	for _, args := range [][]string{{"watch", "http://127.0.0.1"}, {"bandwidth", "--listen", "0"}, {"pathwatch", "127.0.0.1"}, {"dnstrace", "example.com"}} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var out, stderr bytes.Buffer
		code := Execute(ctx, append(args, "--json"), strings.NewReader(""), &out, &stderr, "test")
		if code != 130 || !json.Valid(out.Bytes()) {
			t.Fatal(args, code, out.String(), stderr.String())
		}
	}
}
func TestWatchFiniteJSONAndFailure(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fail" {
			w.WriteHeader(503)
		}
	}))
	defer s.Close()
	for _, bad := range []bool{false, true} {
		url := s.URL
		if bad {
			url += "/fail"
		}
		out, stderr, code := invoke("watch", url, "tcp://"+strings.TrimPrefix(s.URL, "http://"), "--count", "1", "--json")
		want := 0
		if bad {
			want = 1
		}
		if code != want {
			t.Fatal(code, out, stderr)
		}
		r := probeJSON(t, out, "watch")
		if len(r.Sections) != 1 {
			t.Fatal(out)
		}
	}
}
func TestDNSTraceNativeCLI(t *testing.T) {
	c, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ready := make(chan struct{})
	s := &dns.Server{PacketConn: c, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		m.Authoritative = true
		hdr := dns.RR_Header{Name: q.Question[0].Name, Rrtype: q.Question[0].Qtype, Class: dns.ClassINET, Ttl: 42}
		switch q.Question[0].Qtype {
		case dns.TypeNS:
			m.Answer = []dns.RR{&dns.NS{Hdr: hdr, Ns: "ns.example.test."}}
		case dns.TypeSRV:
			m.Answer = []dns.RR{&dns.SRV{Hdr: hdr, Port: 5060, Target: "sip.example.test."}}
		default:
			m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.ParseIP("192.0.2.42")}}
		}
		w.WriteMsg(m)
	})}
	go s.ActivateAndServe()
	<-ready
	defer s.Shutdown()
	out, stderr, code := invoke("dnstrace", "example.test", "--root", c.LocalAddr().String(), "--json")
	if code != 0 || !strings.Contains(out, "192.0.2.42") {
		t.Fatal(code, out, stderr)
	}
	probeJSON(t, out, "dnstrace")
	for _, args := range [][]string{{".", "--type", "NS"}, {"_sip._tcp.example.test", "--type", "SRV"}} {
		out, stderr, code = invoke(append([]string{"dnstrace", "--root", c.LocalAddr().String(), "--json"}, args...)...)
		if code != 0 {
			t.Fatal(code, out, stderr)
		}
		probeJSON(t, out, "dnstrace")
	}
}
func TestBandwidthNativePairedCLI(t *testing.T) {
	var serverOut bytes.Buffer
	ready := newReadyWriter()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan int, 1)
	go func() {
		done <- Execute(ctx, []string{"bandwidth", "--listen", "0", "--json"}, strings.NewReader(""), &serverOut, ready, "test")
	}()
	var address string
	select {
	case address = <-ready.address:
	case <-ctx.Done():
		t.Fatal("listener not ready")
	}
	out, stderr, code := invoke("bandwidth", "--connect", address, "--duration", "30ms", "--json")
	if code != 0 {
		t.Fatal(code, out, stderr)
	}
	if serverCode := <-done; serverCode != 0 {
		t.Fatal(serverCode, serverOut.String())
	}
	a := probeJSON(t, out, "bandwidth")
	b := probeJSON(t, serverOut.String(), "bandwidth")
	ap := a.Sections[0].Data.(map[string]any)["phases"].([]any)
	bp := b.Sections[0].Data.(map[string]any)["phases"].([]any)
	if len(ap) != 2 || len(bp) != 2 {
		t.Fatal("missing phases")
	}
	for i := range ap {
		if ap[i].(map[string]any)["bytes"] != bp[i].(map[string]any)["bytes"] {
			t.Fatal("peer counts disagree")
		}
	}
}
