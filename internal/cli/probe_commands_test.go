package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/miekg/dns"
)

func probeJSON(t *testing.T, out string, command string) lookup.Report {
	t.Helper()
	var report lookup.Report
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err, out)
	}
	if report.SchemaVersion != 1 || report.Command != command || len(report.Sections) == 0 || strings.Contains(out, "\x1b") {
		t.Fatal(report, out)
	}
	for _, section := range report.Sections {
		if section.Status == "pending" {
			t.Fatal("pending section", section)
		}
	}
	return report
}

func TestProbeCommandValidationAndHelp(t *testing.T) {
	for _, name := range []string{"tlscert", "httpinfo", "dnscheck", "ntptime", "lookingglass"} {
		out, stderr, code := invoke(name, "--help")
		if code != 0 || out == "" || stderr != "" {
			t.Fatal(name, out, stderr, code)
		}
	}
	for _, args := range [][]string{{"tlscert", "host:0"}, {"tlscert", "example.com", "--server-name", "https://example.com"}, {"httpinfo", "ftp://example.com"}, {"httpinfo", "example.com", "--max-body", "-1"}, {"httpinfo", "example.com", "--max-redirects", "11"}, {"dnscheck", "example.com", "--resolver", "dns.example.com"}, {"dnscheck", "example.com", "--type", "AXFR"}, {"dnscheck", "", "--resolver", "127.0.0.1"}, {"ntptime", "example.com:99999"}, {"lookingglass", "example.com"}, {"lookingglass", "8.8.8.8", "--provider", "unknown"}, {"lookingglass", "8.8.8.8", "--limit", "0"}} {
		out, stderr, code := invoke(append(args, "--json")...)
		if code != 2 || out != "" || stderr == "" {
			t.Fatal(args, out, stderr, code)
		}
	}
}

func TestTLSCertCLIUntrustedRetainsJSON(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer s.Close()
	out, stderr, code := invoke("tlscert", strings.TrimPrefix(s.URL, "https://"), "--json")
	if code != 1 || stderr == "" {
		t.Fatal(out, stderr, code)
	}
	r := probeJSON(t, out, "tlscert")
	if r.Sections[0].Status != "error" || !strings.Contains(out, `"trusted": false`) || !strings.Contains(out, `"certificates": [`) {
		t.Fatal(out)
	}
}

func TestHTTPInfoCLIJSONAndTimeout(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return
		}
		w.Header().Set("X-Fixture", "ok")
		_, _ = w.Write([]byte("hello"))
	}))
	defer s.Close()
	out, stderr, code := invoke("httpinfo", s.URL, "--json")
	if code != 0 || stderr != "" {
		t.Fatal(out, stderr, code)
	}
	r := probeJSON(t, out, "httpinfo")
	if r.Sections[0].Status != "ok" {
		t.Fatal(out)
	}
	out, stderr, code = invoke("httpinfo", s.URL+"/slow", "--timeout", "20ms", "--json")
	if code != 1 || stderr == "" {
		t.Fatal(out, stderr, code)
	}
	r = probeJSON(t, out, "httpinfo")
	if r.Sections[0].Status != "error" {
		t.Fatal(out)
	}
}

func TestDNSCheckCLIJSON(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	s := &dns.Server{PacketConn: conn, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		if q.Question[0].Name == "bad.test." {
			r.Rcode = dns.RcodeServerFailure
		} else {
			r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
		}
		_ = w.WriteMsg(r)
	})}
	go func() { _ = s.ActivateAndServe() }()
	<-ready
	defer s.Shutdown()
	for _, tt := range []struct {
		name string
		code int
	}{{"example.test", 0}, {"bad.test", 1}} {
		out, stderr, code := invoke("dnscheck", tt.name, "--resolver", conn.LocalAddr().String(), "--type", "A", "--json")
		if code != tt.code {
			t.Fatal(out, stderr, code)
		}
		probeJSON(t, out, "dnscheck")
	}
}

func TestNTPTimeCLIJSON(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		for {
			buf := make([]byte, 512)
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n != 48 {
				return
			}
			p := make([]byte, 48)
			p[0] = 36
			p[1] = 2
			copy(p[24:32], buf[40:48])
			now := time.Now()
			for _, offset := range []int{32, 40} {
				binary.BigEndian.PutUint32(p[offset:], uint32(now.Unix()+2208988800))
				binary.BigEndian.PutUint32(p[offset+4:], uint32((uint64(now.Nanosecond())<<32)/1000000000))
			}
			_, _ = conn.WriteTo(p, addr)
		}
	}()
	out, stderr, code := invoke("ntptime", conn.LocalAddr().String(), "--json")
	if code != 0 || stderr != "" {
		t.Fatal(out, stderr, code)
	}
	probeJSON(t, out, "ntptime")
	if !strings.Contains(out, `"valid": true`) || !strings.Contains(out, `"clock_changed": false`) {
		t.Fatal(out)
	}
}

func TestLookingGlassCLIConcurrentPartialFailures(t *testing.T) {
	var mu sync.Mutex
	arrived := 0
	both := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fail" {
			w.WriteHeader(503)
			return
		}
		mu.Lock()
		arrived++
		if arrived == 2 {
			close(both)
		}
		mu.Unlock()
		select {
		case <-both:
		case <-r.Context().Done():
			return
		}
		if r.URL.Path == "/ripe" {
			_, _ = w.Write([]byte(`{"status":"ok","data":{"rrcs":[],"latest_time":"2026-09-24T00:00:00"}}`))
		} else {
			_, _ = w.Write([]byte(`{"prefix":"8.8.8.8","collected":null,"routes":{},"warnings":[]}`))
		}
	}))
	defer s.Close()
	out, stderr, code := invoke("lookingglass", "8.8.8.8", "--provider", "ripe="+s.URL+"/ripe,nlnog="+s.URL+"/nlnog", "--json")
	if code != 0 || stderr != "" {
		t.Fatal(out, stderr, code)
	}
	r := probeJSON(t, out, "lookingglass")
	if len(r.Sections) != 2 || r.Sections[0].Key != "lookingglass_1_ripe" || r.Sections[1].Key != "lookingglass_2_nlnog" {
		t.Fatal(r)
	}
	for _, providers := range []string{"ripe=" + s.URL + "/ripe,nlnog=" + s.URL + "/fail", "ripe=" + s.URL + "/fail,nlnog=" + s.URL + "/fail"} {
		out, stderr, code = invoke("lookingglass", "8.8.8.8", "--provider", providers, "--json")
		if code != 1 || stderr == "" {
			t.Fatal(out, stderr, code)
		}
		r = probeJSON(t, out, "lookingglass")
		if r.Sections[1].Status != "error" {
			t.Fatal(r)
		}
	}
}

func TestProbeCanceledJSON(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, args := range [][]string{{"tlscert", "example.invalid"}, {"httpinfo", "https://example.invalid"}, {"dnscheck", "example.invalid", "--resolver", "127.0.0.1:1"}, {"ntptime"}, {"lookingglass", "8.8.8.8"}} {
		var out, stderr bytes.Buffer
		code := Execute(ctx, append(args, "--json"), strings.NewReader(""), &out, &stderr, "test")
		if code != 130 {
			t.Fatal(args, code, out.String(), stderr.String())
		}
		r := probeJSON(t, out.String(), args[0])
		for _, s := range r.Sections {
			if s.Status != "error" {
				t.Fatal(s)
			}
		}
	}
}

func TestProbeIPv6HostPort(t *testing.T) {
	root := New("test")
	cmd, _, err := root.Find([]string{"ntptime"})
	if err != nil || cmd == nil {
		t.Fatal(err)
	}
	_, stderr, code := invoke("ntptime", net.JoinHostPort("::1", strconv.Itoa(65536)))
	if code != 2 || stderr == "" {
		t.Fatal(stderr, code)
	}
}
