package lookup

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}
func fixtureService(body string) *Service {
	s := NewService()
	s.RDAPURL = "https://rdap.example/ip/"
	s.HTTP = &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) { return response(200, body), nil })}
	return s
}

func TestHTTPProviderValidation(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	for _, body := range []string{`{}`, `{"success":false,"message":"rate limited"}`, `{"success":true}`, `{"success":true,"ip":"8.8.8.8","latitude":91,"longitude":0}`, `{"success":true,"ip":"1.1.1.1","latitude":0,"longitude":0}`} {
		if _, err := fixtureService(body).Geo(context.Background(), ip); err == nil {
			t.Errorf("accepted bad geo %s", body)
		}
	}
	if _, err := fixtureService(`{"success":true,"ip":"8.8.8.8","latitude":0,"longitude":0}`).Geo(context.Background(), ip); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{}`, `{"startAddress":"1.1.1.1","endAddress":"::ffff"}`, `{"startAddress":"9.0.0.0","endAddress":"9.0.0.255"}`, `{"startAddress":"8.8.8.255","endAddress":"8.8.8.0"}`} {
		if _, err := fixtureService(body).Whois(context.Background(), ip); err == nil {
			t.Errorf("accepted bad RDAP %s", body)
		}
	}
	for _, state := range []string{"valid", "unknown", "invalid_asn", "invalid_length", "invalid"} {
		s := fixtureService(fmt.Sprintf(`{"status":"ok","data":{"status":%q}}`, state))
		if _, err := s.RPKI(context.Background(), ASN{Number: 15169, Prefix: "8.8.8.0/24"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, body := range []string{`{}`, `{"status":"error","data":{"status":"valid"}}`, `{"status":"ok","data":{"status":"new-state"}}`} {
		if _, err := fixtureService(body).RPKI(context.Background(), ASN{}); err == nil {
			t.Errorf("accepted bad RPKI %s", body)
		}
	}
}

func TestRDAPContacts(t *testing.T) {
	data := `{"name":"GOGL","handle":"NET-8-8-8-0-1","startAddress":"8.8.8.0","endAddress":"8.8.8.255","country":"US","entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Google LLC"]]],"entities":[{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","abuse@example.org"]]]}]}],"events":[{"eventAction":"registration","eventDate":"2020-01-01"}]}`
	r, err := fixtureService(data).Whois(context.Background(), netip.MustParseAddr("8.8.8.8"))
	if err != nil {
		t.Fatal(err)
	}
	w := r.(Whois)
	if w.Organization != "Google LLC" || len(w.Abuse) != 1 || w.Abuse[0] != "abuse@example.org" || w.Created != "2020-01-01" {
		t.Fatalf("%+v", w)
	}
}

func TestHTTPBoundsStatusAndCancellation(t *testing.T) {
	for _, tt := range []struct {
		code int
		body string
	}{{429, "rate limited"}, {200, "{"}, {200, strings.Repeat("x", (2<<20)+1)}} {
		s := fixtureService("")
		s.HTTP.Transport = roundTrip(func(*http.Request) (*http.Response, error) { return response(tt.code, tt.body), nil })
		var result any
		if err := s.json(context.Background(), "https://provider.example", &result); err == nil {
			t.Error("accepted invalid response")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	s := NewService()
	s.HTTP.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	done := make(chan error, 1)
	go func() { _, err := s.get(ctx, "https://provider.example"); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("missing cancel error")
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP ignored cancellation")
	}
}

func TestPublicIPRaceCancelsLosers(t *testing.T) {
	s := NewService()
	s.PublicURLs = []string{"https://slow.example", "https://fast.example"}
	slowStarted := make(chan struct{})
	slowCanceled := make(chan struct{})
	s.HTTP.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "slow.example" {
			close(slowStarted)
			<-r.Context().Done()
			close(slowCanceled)
			return nil, r.Context().Err()
		}
		<-slowStarted
		return response(200, "8.8.8.8\n"), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := s.PublicIP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.(PublicIP).Source != "https://fast.example" {
		t.Fatal(r)
	}
	select {
	case <-slowCanceled:
	case <-ctx.Done():
		t.Fatal("losing public IP request was not canceled")
	}
}

func dnsFixture(t *testing.T, handler dns.HandlerFunc) *DNSClient {
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
	tcpServer := &dns.Server{Listener: tcp, Handler: handler, NotifyStartedFunc: func() { close(readyTCP) }}
	udpServer := &dns.Server{PacketConn: udp, Handler: handler, NotifyStartedFunc: func() { close(readyUDP) }}
	go func() { _ = tcpServer.ActivateAndServe() }()
	go func() { _ = udpServer.ActivateAndServe() }()
	<-readyTCP
	<-readyUDP
	t.Cleanup(func() { _ = udpServer.Shutdown(); _ = tcpServer.Shutdown() })
	return &DNSClient{Servers: []string{tcp.Addr().String()}}
}

func TestDNSBLStates(t *testing.T) {
	for _, tt := range []struct {
		name           string
		rcode          int
		answer, status string
	}{{"negative", dns.RcodeNameError, "", "not_listed"}, {"listed", dns.RcodeSuccess, "127.0.0.2", "listed"}, {"provider refusal", dns.RcodeSuccess, "127.255.255.254", "unavailable"}, {"server failure", dns.RcodeServerFailure, "", "unavailable"}, {"empty answer", dns.RcodeSuccess, "", "unavailable"}, {"unexpected answer", dns.RcodeSuccess, "1.2.3.4", "unavailable"}} {
		t.Run(tt.name, func(t *testing.T) {
			c := dnsFixture(t, func(w dns.ResponseWriter, q *dns.Msg) {
				r := new(dns.Msg)
				r.SetReply(q)
				r.Rcode = tt.rcode
				if tt.answer != "" {
					r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP(tt.answer)}}
				}
				_ = w.WriteMsg(r)
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			data, err := c.Reputation(ctx, netip.MustParseAddr("8.8.8.8"))
			if (err != nil) != (tt.status == "unavailable") {
				t.Fatalf("error: %v", err)
			}
			for _, list := range data.([]ListResult) {
				if list.Status != tt.status {
					t.Fatalf("%+v", list)
				}
			}
		})
	}
}

func TestDNSTCPRetryAndCancellation(t *testing.T) {
	started := make(chan struct{}, 1)
	c := dnsFixture(t, func(w dns.ResponseWriter, q *dns.Msg) {
		if q.Question[0].Name == "slow.example." {
			select {
			case started <- struct{}{}:
			default:
			}
			return
		}
		r := new(dns.Msg)
		r.SetReply(q)
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			r.Truncated = true
		} else {
			r.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"hello"}}}
		}
		_ = w.WriteMsg(r)
	})
	r, err := c.txt(context.Background(), "retry.example")
	if err != nil || len(r) != 1 || r[0] != "hello" {
		t.Fatal(r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := c.Query(ctx, "slow.example", dns.TypeA); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("%v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("DNS read did not promptly cancel")
	}
}

func TestASNRejectsMalformedNumber(t *testing.T) {
	c := dnsFixture(t, func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"123garbage | 8.8.8.0/24 | US | arin | 1992-12-01"}}}
		_ = w.WriteMsg(r)
	})
	if _, err := c.ASN(context.Background(), netip.MustParseAddr("8.8.8.8")); err == nil {
		t.Fatal("accepted malformed ASN")
	}
}

func TestRDAPBootstrapLongestMatchAndHTTPS(t *testing.T) {
	for _, tt := range []struct{ name, body, want string }{
		{"longest", `{"services":[[["8.0.0.0/8"],["https://wide.example/registry/"]],[["8.8.8.0/24"],["http://insecure.example/","https://specific.example/rdap/"]]]}`, "https://specific.example/rdap/ip/"},
		{"no matching registry", `{"services":[[["9.0.0.0/8"],["https://wrong.example/"]]]}`, ""},
		{"no secure registry", `{"services":[[["8.0.0.0/8"],["http://insecure.example/"]]]}`, ""},
		{"malformed", `{"services":[[["8.0.0.0/8"]]]}`, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := fixtureService(tt.body)
			endpoint, err := s.rdapEndpoint(context.Background(), netip.MustParseAddr("8.8.8.8"))
			if tt.want == "" {
				if err == nil {
					t.Fatal("accepted invalid registry")
				}
			} else if err != nil || endpoint != tt.want {
				t.Fatal(endpoint, err)
			}
		})
	}
}

func TestRDAPBootstrapIPv6(t *testing.T) {
	s := NewService()
	s.HTTP.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case "https://data.iana.org/rdap/ipv6.json":
			return response(200, `{"services":[[["2001:4860::/32"],["https://registry.example/"]]]}`), nil
		case "https://registry.example/ip/2001:4860::1":
			return response(200, `{"startAddress":"2001:4860::","endAddress":"2001:4860:ffff:ffff:ffff:ffff:ffff:ffff","name":"GOOGLE"}`), nil
		default:
			t.Errorf("unexpected URL %s", r.URL)
			return response(404, ""), nil
		}
	})
	if _, err := s.Whois(context.Background(), netip.MustParseAddr("2001:4860::1")); err != nil {
		t.Fatal(err)
	}
}

func TestDNSCNAMEChaseAndCycle(t *testing.T) {
	c := dnsFixture(t, func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		name := q.Question[0].Name
		if name == "target.example." {
			r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.1")}}
		} else {
			target := "target.example."
			if name == "cycle.example." {
				target = name
			}
			r.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: target}}
		}
		_ = w.WriteMsg(r)
	})
	rrs, err := c.Query(context.Background(), "alias.example", dns.TypeA)
	if err != nil || len(rrs) != 2 {
		t.Fatal(rrs, err)
	}
	if _, err := c.Query(context.Background(), "cycle.example", dns.TypeA); err == nil {
		t.Fatal("CNAME cycle accepted")
	}
}

func TestWhoisPrefersOrganisationOverMaintainers(t *testing.T) {
	// Entity order follows a RIPE network: maintainers are also registrants and
	// come after the organisation that holds the range.
	data := `{"name":"RIPE-NCC","handle":"193.0.0.0 - 193.0.7.255","startAddress":"193.0.0.0","endAddress":"193.0.7.255","country":"NL","entities":[
{"roles":["administrative"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Managing Director"],["kind",{},"text","group"]]]},
{"roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Reseaux IP Europeens Network Coordination Centre (RIPE NCC)"],["kind",{},"text","org"]]]},
{"roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RIPE-NCC-MNT"],["kind",{},"text","individual"]]]},
{"roles":["abuse"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RIPE NCC Operations"],["kind",{},"text","group"],["email",{},"text","abuse@ripe.net"]]]}]}`
	r, err := fixtureService(data).Whois(context.Background(), netip.MustParseAddr("193.0.6.139"))
	if err != nil {
		t.Fatal(err)
	}
	if w := r.(Whois); w.Organization != "Reseaux IP Europeens Network Coordination Centre (RIPE NCC)" || len(w.Abuse) != 1 || w.Abuse[0] != "abuse@ripe.net" {
		t.Fatalf("%+v", w)
	}
}

func TestWhoisListsEachAbuseAddressOnce(t *testing.T) {
	// APNIC repeats a mailbox across abuse contacts and their nested entities.
	data := `{"name":"APNIC-LABS","handle":"1.1.1.0 - 1.1.1.255","startAddress":"1.1.1.0","endAddress":"1.1.1.255","country":"AU","entities":[
{"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","IRT-APNICRANDNET-AU"],["kind",{},"text","group"],["email",{},"text","helpdesk@apnic.net"],["email",{},"text","abuse@apnic.net"]]],"entities":[
{"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Abuse desk"],["email",{},"text","helpdesk@apnic.net"]]]}]},
{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","APNIC Research and Development"],["kind",{},"text","org"]]]},
{"roles":["abuse","technical"],"vcardArray":["vcard",[["fn",{},"text","NOC"],["email",{},"text","abuse@apnic.net"],["email",{},"text","noc@apnic.net"]]]}]}`
	r, err := fixtureService(data).Whois(context.Background(), netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	// First appearance decides the order.
	if w, want := r.(Whois), []string{"helpdesk@apnic.net", "abuse@apnic.net", "noc@apnic.net"}; !slices.Equal(w.Abuse, want) || w.Organization != "APNIC Research and Development" {
		t.Fatalf("%+v", w)
	}
}
