package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestEndpointValidation(t *testing.T) {
	for _, raw := range []string{"https://example.org", "example.org:0", "example.org:65536", "user@host", "host/path", "host:abc", "127.0.0.1:", "[::1]:0", "bad host", ""} {
		if _, _, err := HostPort(raw, "443"); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"example.org", "example.org:8443", "::1", "[::1]", "[::1]:8443", "127.0.0.1:443"} {
		if _, _, err := HostPort(raw, "443"); err != nil {
			t.Errorf("%q: %v", raw, err)
		}
	}
	for _, raw := range []string{"ftp://example.org", "https://u:p@example.org", "https://example.org:", "https://example.org:65536", "https://bad host/", strings.Repeat("a", 8193)} {
		if _, err := HTTPURL(raw); err == nil {
			t.Errorf("accepted URL %q", raw)
		}
	}
}

func TestTLSVerificationRetainsInvalidCertificates(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("TLS inspection sent application data") }))
	defer s.Close()
	address := strings.TrimPrefix(s.URL, "https://")
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	r, err := TLS(testContext(t), address, "127.0.0.1", roots)
	if err != nil || !r.Trusted || len(r.Certificates) != 1 || r.Certificates[0].SHA256 == "" || r.Protocol == "" || r.RevocationChecked {
		t.Fatal(r, err)
	}
	// Certificate SANs have no interface zone even when the inspected identity
	// is scoped. Dial IPv4 loopback so this does not require IPv6 connectivity.
	r, err = TLS(testContext(t), address, "::1%fixture", roots)
	if err != nil || !r.Trusted || r.ServerName != "::1" || r.Address != address {
		t.Fatal(r, err)
	}
	for _, name := range []string{"wrong.invalid", "127.0.0.1"} {
		var trustedRoots *x509.CertPool
		if name == "wrong.invalid" {
			trustedRoots = roots
		}
		r, err = TLS(testContext(t), address, name, trustedRoots)
		if err == nil || r.Trusted || r.VerificationError == "" || len(r.Certificates) != 1 {
			t.Fatal(r, err)
		}
	}
}

func TestTLSExpiredCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "expired"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	s.StartTLS()
	defer s.Close()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	r, err := TLS(testContext(t), strings.TrimPrefix(s.URL, "https://"), "127.0.0.1", roots)
	if err == nil || r.Trusted || len(r.Certificates) != 1 || !strings.Contains(r.VerificationError, "expired") {
		t.Fatal(r, err)
	}
}

func TestTLSHandshakeCancellation(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan struct{})
	done := make(chan struct{})
	defer close(done)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		<-done
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := TLS(ctx, l.Addr().String(), "localhost", nil); result <- err }()
	<-accepted
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled TLS succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("TLS cancellation blocked")
	}
}

func TestHTTPRedirectBodyAndErrors(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Location", "/final")
			w.WriteHeader(302)
		case "/loop":
			w.Header().Set("Location", "/loop")
			w.WriteHeader(307)
		case "/credentials":
			w.Header().Set("Location", "http://user:pass@example.invalid/")
			w.WriteHeader(302)
		case "/error":
			w.WriteHeader(503)
		case "/headers":
			w.Header().Set("Huge", strings.Repeat("x", 70<<10))
		default:
			w.Header().Set("X-Test", "fixture")
			_, _ = w.Write([]byte("abcdef"))
		}
	}))
	defer s.Close()
	r, err := HTTP(testContext(t), s.URL, 5, 3)
	if err != nil || len(r.Hops) != 2 || r.Hops[1].Status != 200 || !r.Hops[1].BodyTruncated || r.Hops[1].BodyBytesRead != 4 || r.Hops[1].Headers.Get("X-Test") != "fixture" || r.Hops[1].Timing.FirstByteMS <= 0 {
		t.Fatal(r, err)
	}
	r, err = HTTP(testContext(t), s.URL+"/final", 5, 0)
	if err != nil || !r.Hops[0].BodyTruncated || r.Hops[0].BodyBytesRead != 1 {
		t.Fatal(r, err)
	}
	for _, path := range []string{"/loop", "/credentials", "/error", "/headers"} {
		r, err = HTTP(testContext(t), s.URL+path, 1, 1)
		if err == nil || len(r.Hops) == 0 {
			t.Fatal(path, r, err)
		}
	}
}

func TestHTTPCancellationPreservesHeaders(t *testing.T) {
	started := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Started", "yes")
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	}))
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan HTTPResult, 1)
	go func() {
		r, err := HTTP(ctx, s.URL, 1, 32)
		if err == nil {
			t.Error("canceled HTTP succeeded")
		}
		done <- r
	}()
	<-started
	select {
	case r := <-done:
		if len(r.Hops) != 1 || r.Hops[0].Headers.Get("X-Started") != "yes" {
			t.Fatal(r)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP cancellation blocked")
	}
}

func dnsFixture(t *testing.T, handler dns.HandlerFunc) (string, func()) {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	readyTCP, readyUDP := make(chan struct{}), make(chan struct{})
	ts := &dns.Server{Listener: tcp, Handler: handler, NotifyStartedFunc: func() { close(readyTCP) }}
	us := &dns.Server{PacketConn: udp, Handler: handler, NotifyStartedFunc: func() { close(readyUDP) }}
	go func() { _ = ts.ActivateAndServe() }()
	go func() { _ = us.ActivateAndServe() }()
	<-readyTCP
	<-readyUDP
	return tcp.Addr().String(), func() { _ = ts.Shutdown(); _ = us.Shutdown() }
}
func answerA(q *dns.Msg, ttl uint32, ip string) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.ParseIP(ip)}}
	return r
}

func TestDNSComparisonConcurrentTTLAndFailure(t *testing.T) {
	var mu sync.Mutex
	arrived := 0
	barrier := make(chan struct{})
	makeHandler := func(ttl uint32) dns.HandlerFunc {
		return func(w dns.ResponseWriter, q *dns.Msg) {
			mu.Lock()
			arrived++
			if arrived == 2 {
				close(barrier)
			}
			mu.Unlock()
			select {
			case <-barrier:
			case <-time.After(time.Second):
			}
			_ = w.WriteMsg(answerA(q, ttl, "192.0.2.1"))
		}
	}
	a, closeA := dnsFixture(t, makeHandler(10))
	defer closeA()
	b, closeB := dnsFixture(t, makeHandler(20))
	defer closeB()
	r, err := DNS(testContext(t), "example.test.", []uint16{dns.TypeA}, []string{a, b})
	if err != nil || len(r.Queries) != 2 || r.Comparisons[0].Status != "agree" || r.Queries[0].Answers[0].TTL != 10 || r.Queries[1].Answers[0].TTL != 20 {
		t.Fatal(r, err)
	}
	c, closeC := dnsFixture(t, func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetRcode(q, dns.RcodeServerFailure)
		_ = w.WriteMsg(r)
	})
	defer closeC()
	r, err = DNS(testContext(t), "example.test.", []uint16{dns.TypeA}, []string{a, c})
	if err == nil || r.Queries[0].Error != "" || r.Queries[1].RCode != "SERVFAIL" || r.Comparisons[0].SuccessfulResolvers != 1 {
		t.Fatal(r, err)
	}
}

func TestDNSNegativeAnswersFallbackAndValidation(t *testing.T) {
	a, closeA := dnsFixture(t, func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		switch q.Question[0].Name {
		case "nx.test.":
			r.Rcode = dns.RcodeNameError
		case "bad.test.":
			r.Question[0].Name = "unrelated.test."
		default:
			if w.LocalAddr().Network() == "udp" {
				r.Truncated = true
			} else {
				r = answerA(q, 60, "192.0.2.2")
			}
		}
		_ = w.WriteMsg(r)
	})
	defer closeA()
	r, err := DNS(testContext(t), "fallback.test.", []uint16{dns.TypeA}, []string{a})
	if err != nil || r.Queries[0].Transport != "tcp" || len(r.Queries[0].Answers) != 1 {
		t.Fatal(r, err)
	}
	r, err = DNS(testContext(t), "nx.test.", []uint16{dns.TypeA}, []string{a})
	if err != nil || r.Queries[0].RCode != "NXDOMAIN" {
		t.Fatal(r, err)
	}
	r, err = DNS(testContext(t), "bad.test.", []uint16{dns.TypeA}, []string{a})
	if err == nil || r.Queries[0].Error == "" {
		t.Fatal(r, err)
	}
	name, types, _, err := DNSOptions("2001:db8::1", nil, []string{a})
	if err != nil || types[0] != dns.TypePTR || !strings.HasSuffix(name, "ip6.arpa.") {
		t.Fatal(name, types, err)
	}
	for _, types := range [][]string{{"ANY"}, {"AXFR"}, {"A", "A", "A", "A", "A", "A", "A", "A", "A"}} {
		if _, _, _, err := DNSOptions("example.test", types, []string{a}); err == nil {
			t.Fatal("accepted", types)
		}
	}
}

func TestDNSCancellation(t *testing.T) {
	arrived := make(chan struct{})
	release := make(chan struct{})
	a, closeA := dnsFixture(t, func(dns.ResponseWriter, *dns.Msg) { close(arrived); <-release })
	defer closeA()
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := DNS(ctx, "example.test.", []uint16{dns.TypeA}, []string{a}); done <- err }()
	<-arrived
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("DNS cancellation blocked")
	}
	unblock()
}

func ntpPacket(t1, t2, t3 time.Time) ([]byte, []byte) {
	request := make([]byte, 48)
	request[0] = 35
	putNTP(request[40:], t1)
	p := make([]byte, 48)
	p[0] = 36
	p[1] = 2
	p[3] = byte(236)
	copy(p[24:], request[40:])
	putNTP(p[32:], t2)
	putNTP(p[40:], t3)
	return p, request
}

func TestNTPValidationArithmeticAndEra(t *testing.T) {
	t1 := time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(60 * time.Millisecond)
	t3 := t2.Add(10 * time.Millisecond)
	t4 := t1.Add(30 * time.Millisecond)
	p, req := ntpPacket(t1, t2, t3)
	r, err := parseNTP(p, req, t1, t4)
	if err != nil || !r.Valid || r.DelayMS < 19.999 || r.DelayMS > 20.001 || r.OffsetMS < 49.999 || r.OffsetMS > 50.001 || r.ServerSent.Year() != 2040 || r.ClockChanged || r.Authenticated {
		t.Fatal(r, err)
	}
	for _, tt := range []struct {
		name   string
		mutate func([]byte)
	}{{"version", func(p []byte) { p[0] = 2<<3 | 4 }}, {"mode", func(p []byte) { p[0] = 4<<3 | 3 }}, {"leap", func(p []byte) { p[0] |= 3 << 6 }}, {"stratum", func(p []byte) { p[1] = 16 }}, {"origin", func(p []byte) { p[24] ^= 1 }}, {"zero", func(p []byte) { clear(p[40:48]) }}, {"backwards", func(p []byte) { putNTP(p[40:], t1) }}, {"negative-delay", func(p []byte) { putNTP(p[40:], t2.Add(time.Second)) }}} {
		t.Run(tt.name, func(t *testing.T) {
			copyP := append([]byte{}, p...)
			tt.mutate(copyP)
			r, err := parseNTP(copyP, req, t1, t4)
			if err == nil || r.Valid {
				t.Fatal(r, err)
			}
		})
	}
	kod := append([]byte{}, p...)
	kod[1] = 0
	copy(kod[12:16], "RATE")
	r, err = parseNTP(kod, req, t1, t4)
	if err == nil || r.KissCode != "RATE" || r.Valid {
		t.Fatal(r, err)
	}
	for _, year := range []int{1960, 2035, 2036, 2040, 2100} {
		near := time.Date(year, 1, 1, 0, 0, 0, 123000000, time.UTC)
		b := make([]byte, 8)
		putNTP(b, near)
		got := readNTP(b, near)
		if delta := got.Sub(near); delta < -time.Nanosecond || delta > time.Nanosecond {
			t.Fatal(year, got, near)
		}
	}
}

func TestNTPUDPAndCancellation(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, 512)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if n != 48 || buf[0] != 35 {
			t.Errorf("bad request %d %d", n, buf[0])
			return
		}
		now := time.Now()
		p, _ := ntpPacket(now, now, now)
		copy(p[24:32], buf[40:48])
		binary.BigEndian.PutUint32(p[8:12], 655)
		_, _ = conn.WriteTo(p, addr)
	}()
	r, err := NTP(testContext(t), conn.LocalAddr().String())
	if err != nil || !r.Valid || r.RemoteAddress == "" || r.RootDispersionMS <= 0 {
		t.Fatal(r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := NTP(ctx, conn.LocalAddr().String()); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("NTP cancellation blocked")
	}
}

const ripeFixture = `{"status":"ok","data":{"query_time":"2026-09-24T01:00:00","latest_time":"2026-09-24T00:59:00","rrcs":[{"rrc":"RRC01","location":"London","peers":[{"peer":"192.0.2.2","prefix":"8.8.8.0/24","as_path":"64501 15169","origin":"IGP","next_hop":"192.0.2.2"},{"peer":"192.0.2.1","prefix":"8.8.8.0/24","as_path":"64500 15169"}]}]}}`
const nlnogFixture = `{"prefix":"8.8.8.8","collected":null,"routes":{"8.8.8.0/24":[{"peer":"peer-a","aspath":[["64500","Fixture"],["15169","Google"]],"origin":"IGP","exit_nexthop":"192.0.2.1","last_update_at":"2026-09-23 12:00:00 UTC"}]},"warnings":[]}`

func TestLookingGlassAdaptersBoundsAndValidation(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ripe":
			if r.URL.Query().Get("resource") != "8.8.8.8" {
				t.Error(r.URL)
			}
			_, _ = w.Write([]byte(ripeFixture))
		case "/nlnog":
			if r.URL.Query().Get("q") != "8.8.8.8" {
				t.Error(r.URL)
			}
			_, _ = w.Write([]byte(nlnogFixture))
		case "/oversize":
			_, _ = w.Write([]byte(strings.Repeat("x", (2<<20)+1)))
		case "/error":
			w.WriteHeader(429)
		default:
			_, _ = w.Write([]byte(`{"status":"ok","data":{}}`))
		}
	}))
	defer s.Close()
	resource, providers, err := LookingGlassOptions("8.8.8.8", []string{"ripe=" + s.URL + "/ripe", "nlnog=" + s.URL + "/nlnog"}, 1, "rrc01")
	if err != nil {
		t.Fatal(err)
	}
	r, err := LookingGlass(testContext(t), resource, providers[0], 1, "rrc01")
	if err != nil || !r.Truncated || r.TotalRoutes != 2 || r.Routes[0].Peer != "192.0.2.1" || r.Routes[0].Collector != "rrc01" {
		t.Fatal(r, err)
	}
	r, err = LookingGlass(testContext(t), resource, providers[1], 1, "")
	if err != nil || r.TotalRoutes != 1 || len(r.Routes[0].ASPath) != 2 || len(r.Warnings) == 0 {
		t.Fatal(r, err)
	}
	for _, path := range []string{"/bad", "/oversize", "/error"} {
		r, err = LookingGlass(testContext(t), resource, Provider{Kind: "ripe", URL: s.URL + path}, 1, "")
		if err == nil {
			t.Fatal(path, r)
		}
	}
	out := LookingGlassResult{Resource: "1.1.1.1"}
	if err = decodeRIPE([]byte(ripeFixture), &out, ""); err == nil {
		t.Fatal("unrelated route accepted")
	}
	for _, raw := range []string{"https://example.com", "not-an-ip", "2001:db8::1%eth0"} {
		if _, _, err = LookingGlassOptions(raw, []string{"ripe"}, 1, ""); err == nil {
			t.Fatal(raw)
		}
	}
	if _, _, err = LookingGlassOptions("8.8.8.8", []string{"ripe=http://example.com"}, 1, ""); err == nil {
		t.Fatal("unencrypted provider accepted")
	}
	b, err := json.Marshal(r)
	if err != nil || len(b) == 0 {
		t.Fatal(err)
	}
}

func TestLookingGlassCancellationAndEmpty(t *testing.T) {
	started := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := LookingGlass(ctx, "8.8.8.8", Provider{Kind: "ripe", URL: s.URL}, 1, ""); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled query succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("lookingglass cancellation blocked")
	}
	r := LookingGlassResult{Resource: "8.8.8.8"}
	if err := decodeRIPE([]byte(`{"status":"ok","data":{"rrcs":[]}}`), &r, ""); err != nil || len(r.Routes) != 0 {
		t.Fatal(r, err)
	}
}
