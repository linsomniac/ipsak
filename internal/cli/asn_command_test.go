package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

type asnRoundTrip func(*http.Request) (*http.Response, error)

func (f asnRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// asnFixture is a service whose providers are local: a loopback DNS server for
// Team Cymru names, and canned HTTP bodies at the production provider URLs.
func asnFixture(t *testing.T, neighboursStatus int) *lookup.Service {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{
		"as15169.asn.cymru.com.":  "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US",
		"as3356.asn.cymru.com.":   "3356 | US | arin | 2000-03-10 | LEVEL3, US",
		"as396982.asn.cymru.com.": "396982 | US | arin | 2017-03-23 | GOOGLE-CLOUD-PLATFORM, US",
	}
	ready := make(chan struct{})
	server := &dns.Server{PacketConn: conn, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		if text, ok := names[strings.ToLower(q.Question[0].Name)]; ok {
			r.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{text}}}
		} else {
			r.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(r)
	})}
	go func() { _ = server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = server.Shutdown() })
	bodies := map[string]string{
		"https://data.iana.org/rdap/asn.json":                                  `{"services":[[["1-65535"],["https://registry.example/"]]]}`,
		"https://registry.example/autnum/15169":                                `{"handle":"AS15169","startAutnum":15169,"endAutnum":15169,"name":"GOOGLE","status":["active"],"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Google LLC"],["kind",{},"text","org"]]],"entities":[{"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Abuse"],["email",{},"text","network-abuse@google.com"]]]}]}],"events":[{"eventAction":"registration","eventDate":"2000-03-30T00:00:00-05:00"}]}`,
		"https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS15169": `{"status":"ok","data":{"resource":"15169","latest_time":"2026-10-05T00:00:00","neighbour_counts":{"left":2,"right":1,"unique":3,"uncertain":0},"neighbours":[{"asn":174,"type":"left","power":5,"v4_peers":10,"v6_peers":2},{"asn":3356,"type":"left","power":9,"v4_peers":20,"v6_peers":4},{"asn":396982,"type":"right","power":418,"v4_peers":1298085,"v6_peers":127932}]}}`,
		"https://stat.ripe.net/data/routing-status/data.json?resource=AS15169": `{"status":"ok","data":{"first_seen":{"prefix":"64.209.204.0/24","origin":"15169","time":"2000-08-18T08:00:00"},"last_seen":{"prefix":"34.2.124.0/22","origin":"15169","time":"2026-10-05T08:00:00"},"visibility":{"v4":{"ris_peers_seeing":325,"total_ris_peers":325},"v6":{"ris_peers_seeing":315,"total_ris_peers":315}},"announced_space":{"v4":{"prefixes":1235,"ips":2615808},"v6":{"prefixes":176,"48s":721152}},"observed_neighbours":328,"resource":"15169","query_time":"2026-10-05T08:00:00"}}`,
	}
	s := lookup.NewService()
	s.DNS = &lookup.DNSClient{Servers: []string{conn.LocalAddr().String()}}
	s.HTTP = &http.Client{Transport: asnRoundTrip(func(r *http.Request) (*http.Response, error) {
		body, ok := bodies[r.URL.String()]
		code := http.StatusOK
		if !ok {
			t.Errorf("unexpected URL %s", r.URL)
			code = http.StatusNotFound
		}
		if strings.Contains(r.URL.Path, "asn-neighbours") {
			code = neighboursStatus
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	return s
}

func invokeASN(t *testing.T, newService func() *lookup.Service, c config, args ...string) (string, error) {
	t.Helper()
	c.timeout = 5 * time.Second
	root := &cobra.Command{Use: "ipsak", SilenceUsage: true, SilenceErrors: true}
	addASNCommand(root, &c, newService)
	var out bytes.Buffer
	root.SetArgs(args)
	root.SetIn(strings.NewReader(""))
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

func TestASNCommandValidationAndHelp(t *testing.T) {
	// Through the real command tree: the command is registered and takes one argument.
	out, stderr, code := invoke("asn", "--help")
	if code != 0 || out == "" || stderr != "" {
		t.Fatal(out, stderr, code)
	}
	if out, stderr, code = invoke("asn", "--json"); code != 2 || out != "" || stderr == "" {
		t.Fatal(out, stderr, code)
	}
	// Bad values must be refused before a service is built, so that no provider
	// can be contacted. The trap service has no resolver and no network.
	trap := func() *lookup.Service {
		t.Error("built a service for invalid arguments")
		return &lookup.Service{DNS: &lookup.DNSClient{}, HTTP: &http.Client{Transport: asnRoundTrip(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("no network in tests")
		})}}
	}
	for _, args := range [][]string{{"asn", "AS1", "AS2"}, {"asn", "example.com"}, {"asn", "8.8.8.8"}, {"asn", "AS0"}, {"asn", "AS15169", "--limit", "0"}, {"asn", "AS15169", "--limit", "101"}} {
		out, err := invokeASN(t, trap, config{json: true}, args...)
		// Execute maps any error that is not an ExitError to exit status 2.
		var exit *ExitError
		if err == nil || errors.As(err, &exit) || out != "" {
			t.Fatal(args, out, err)
		}
	}
}

func TestASNCommandJSON(t *testing.T) {
	s := asnFixture(t, http.StatusOK)
	out, err := invokeASN(t, func() *lookup.Service { return s }, config{json: true}, "asn", "as15169", "--limit", "1")
	if err != nil {
		t.Fatal(err, out)
	}
	r := probeJSON(t, out, "asn")
	if r.Target != "AS15169" || len(r.Sections) != 4 {
		t.Fatal(out)
	}
	for i, key := range []string{"asn", "registration", "neighbours", "routing"} {
		if r.Sections[i].Key != key || r.Sections[i].Status != "ok" {
			t.Fatalf("section %d: %+v", i, r.Sections[i])
		}
	}
	identity, registration, neighbours, routing := r.Sections[0].Data.(map[string]any), r.Sections[1].Data.(map[string]any), r.Sections[2].Data.(map[string]any), r.Sections[3].Data.(map[string]any)
	if identity["name"] != "GOOGLE - Google LLC, US" || identity["registry"] != "arin" {
		t.Fatal(identity)
	}
	if registration["organization"] != "Google LLC" || registration["range"] != "AS15169" || registration["abuse_email"].([]any)[0] != "network-abuse@google.com" {
		t.Fatal(registration)
	}
	// --limit 1 keeps the strongest neighbour in each direction, with its name.
	upstream, downstream := neighbours["upstream"].([]any), neighbours["downstream"].([]any)
	if len(upstream) != 1 || upstream[0].(map[string]any)["name"] != "LEVEL3, US" || len(downstream) != 1 || downstream[0].(map[string]any)["asn"] != float64(396982) || neighbours["truncated"] != true {
		t.Fatal(neighbours)
	}
	if routing["announced"] != true || routing["ipv4"].(map[string]any)["addresses"] != float64(2615808) {
		t.Fatal(routing)
	}
}

func TestASNCommandKeepsOtherSectionsWhenOneProviderFails(t *testing.T) {
	s := asnFixture(t, http.StatusInternalServerError)
	out, err := invokeASN(t, func() *lookup.Service { return s }, config{json: true}, "asn", "15169")
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 1 {
		t.Fatal(err, out)
	}
	r := probeJSON(t, out, "asn")
	for _, section := range r.Sections {
		want := "ok"
		if section.Key == "neighbours" {
			want = "error"
		}
		if section.Status != want || (want == "error") != (section.Data == nil) || (want == "error") != (section.Error != "") {
			t.Fatalf("%+v", section)
		}
	}
}

func TestASNCommandPlainOutput(t *testing.T) {
	s := asnFixture(t, http.StatusOK)
	out, err := invokeASN(t, func() *lookup.Service { return s }, config{plain: true}, "asn", "AS15169")
	if err != nil {
		t.Fatal(err, out)
	}
	for _, want := range []string{"ASN  ·  AS15169", "GOOGLE - Google LLC, US", "Google LLC", "LEVEL3, US", "2615808"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") || strings.Contains(out, "e+0") {
		t.Errorf("escapes or exponent notation in:\n%s", out)
	}
}
