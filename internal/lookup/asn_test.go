package lookup

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseASN(t *testing.T) {
	for raw, want := range map[string]uint32{"AS15169": 15169, "as15169": 15169, "As3333": 3333, "15169": 15169, "AS4294967295": 4294967295, "1": 1} {
		got, err := ParseASN(raw)
		if err != nil || got != want {
			t.Errorf("ParseASN(%q) = %d, %v; want %d", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "AS", "AS0", "0", "4294967296", "-1", "+1", "AS 15169", "15169 ", "1.10", "AS15169x", "ASAS1", "8.8.8.8", "example.com"} {
		if got, err := ParseASN(raw); err == nil {
			t.Errorf("ParseASN(%q) accepted as %d", raw, got)
		}
	}
}

// cymruFixture answers TXT queries from records (keyed by lower-case FQDN) and
// NXDOMAIN otherwise. The returned function lists every queried name, sorted.
func cymruFixture(t *testing.T, records map[string]string) (*DNSClient, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	c := dnsFixture(t, func(w dns.ResponseWriter, q *dns.Msg) {
		name := strings.ToLower(q.Question[0].Name)
		mu.Lock()
		asked = append(asked, name)
		mu.Unlock()
		r := new(dns.Msg)
		r.SetReply(q)
		if text, ok := records[name]; ok {
			r.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{text}}}
		} else {
			r.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(r)
	})
	return c, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := append([]string(nil), asked...)
		sort.Strings(out)
		return out
	}
}

func TestASNInfoParsesTeamCymruRecord(t *testing.T) {
	c, _ := cymruFixture(t, map[string]string{
		"as15169.asn.cymru.com.": "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US",
		"as3333.asn.cymru.com.":  "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US",
		"as64496.asn.cymru.com.": "64496 | ZZ",
		"as64497.asn.cymru.com.": "64497 |  |  |  | RESERVED",
	})
	ctx := context.Background()
	got, err := c.ASNInfo(ctx, 15169)
	want := ASNInfo{Number: 15169, Name: "GOOGLE - Google LLC, US", Country: "US", Registry: "arin", Allocated: "2000-03-30"}
	if err != nil || got != want {
		t.Fatalf("got %+v, %v; want %+v", got, err, want)
	}
	if got, err = c.ASNInfo(ctx, 64497); err != nil || got != (ASNInfo{Number: 64497, Name: "RESERVED"}) {
		t.Fatalf("blank fields: %+v, %v", got, err)
	}
	for _, number := range []uint32{3333, 64496} {
		if got, err := c.ASNInfo(ctx, number); err == nil {
			t.Errorf("AS%d: accepted mismatched or malformed record as %+v", number, got)
		}
	}
	// A missing record must say which AS it was, since neighbours share the lookup.
	if _, err := c.ASNInfo(ctx, 64512); err == nil || !strings.Contains(err.Error(), "AS64512") {
		t.Errorf("missing record: %v", err)
	}
}

func TestASNNameKeepsItsShapeAndErrors(t *testing.T) {
	c, _ := cymruFixture(t, map[string]string{"as15169.asn.cymru.com.": "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"})
	data, err := c.ASNName(context.Background(), 15169)
	if err != nil || data.(map[string]string)["name"] != "GOOGLE - Google LLC, US" {
		t.Fatal(data, err)
	}
	if _, err := c.ASNName(context.Background(), 64512); !errors.Is(err, ErrNXDomain) {
		t.Fatalf("missing record: %v", err)
	}
}

// asnService serves exactly the listed URLs; any other request fails the test.
func asnService(t *testing.T, routes map[string]string) *Service {
	t.Helper()
	s := NewService()
	s.DNS = &DNSClient{} // no servers: a test that forgets a fixture cannot reach the system resolver
	s.NeighboursURL = "https://stat.example/neighbours"
	s.RoutingURL = "https://stat.example/routing"
	s.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if body, ok := routes[r.URL.String()]; ok {
			return response(200, body), nil
		}
		t.Errorf("unexpected URL %s", r.URL)
		return response(404, ""), nil
	})}
	return s
}

const asnBootstrap = `{"services":[[["1-65535"],["https://wide.example/"]],[["3000-3999","2043"],["http://insecure.example/","https://registry.example/rdap/"]]]}`

// Entity order and nesting follow a RIPE autnum response: contacts and
// maintainers surround the organisation that actually holds the number.
const ripeAutnum = `{"handle":"AS3333","startAutnum":3333,"endAutnum":3333,"name":"RIPE-NCC-AS","status":["active"],"port43":"whois.ripe.net","objectClassName":"autnum","entities":[
{"handle":"JDR-RIPE","roles":["administrative"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Managing Director"],["kind",{},"text","group"]]]},
{"handle":"ORG-RIEN1-RIPE","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Reseaux IP Europeens Network Coordination Centre (RIPE NCC)"],["kind",{},"text","org"]]]},
{"handle":"RIPE-NCC-MNT","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RIPE-NCC-MNT"],["kind",{},"text","individual"]]]},
{"handle":"OPS4-RIPE","roles":["abuse"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RIPE NCC Operations"],["kind",{},"text","group"],["email",{"type":"abuse"},"text","abuse@ripe.net"]]],"entities":[
{"handle":"XX1-RIPE","roles":["technical"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","A Person"],["kind",{},"text","individual"],["email",{},"text","person@ripe.net"]]]}]}],
"events":[{"eventAction":"registration","eventDate":"2002-08-13T12:58:13Z"},{"eventAction":"last changed","eventDate":"2026-03-19T09:33:32Z"}]}`

func TestASNRegistrationFollowsBootstrapToRegistry(t *testing.T) {
	s := asnService(t, map[string]string{
		"https://data.iana.org/rdap/asn.json":       asnBootstrap,
		"https://registry.example/rdap/autnum/3333": ripeAutnum,
	})
	got, err := s.ASNRegistration(context.Background(), 3333)
	want := ASNRegistration{Handle: "AS3333", Name: "RIPE-NCC-AS", Range: "AS3333", Status: []string{"active"}, Organization: "Reseaux IP Europeens Network Coordination Centre (RIPE NCC)", Abuse: []string{"abuse@ripe.net"}, Created: "2002-08-13T12:58:13Z", Updated: "2026-03-19T09:33:32Z"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v, %v\nwant %+v", got, err, want)
	}
}

func TestASNRegistrationBlocksAndContacts(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		want       ASNRegistration
	}{
		{"reserved block with nested repeated abuse contact", `{"handle":"AS64512","startAutnum":3000,"endAutnum":3999,"name":"IANA-RSVD2","status":["reserved"],"country":"AU","entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Internet Assigned Numbers Authority"],["kind",{},"text","org"]]],"entities":[{"roles":["abuse","technical"],"vcardArray":["vcard",[["fn",{},"text","ICANN"],["email",{},"text","abuse@iana.org"]]]},{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","abuse@iana.org"],["email",{},"text","second@iana.org"]]]}]}]}`,
			ASNRegistration{Handle: "AS64512", Name: "IANA-RSVD2", Range: "AS3000 – AS3999", Country: "AU", Status: []string{"reserved"}, Organization: "Internet Assigned Numbers Authority", Abuse: []string{"abuse@iana.org", "second@iana.org"}}},
		{"first registrant when none is an organisation", `{"handle":"AS3333","startAutnum":3333,"endAutnum":3333,"entities":[{"roles":["technical"],"vcardArray":["vcard",[["fn",{},"text","NOC"]]]},{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Holder"]]]},{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","HOLDER-MNT"],["kind",{},"text","individual"]]]}]}`,
			ASNRegistration{Handle: "AS3333", Range: "AS3333", Organization: "Holder"}},
		{"first non-abuse contact when there is no registrant", `{"handle":"AS3333","startAutnum":3333,"endAutnum":3333,"entities":[{"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Abuse desk"]]]},{"roles":["technical"],"vcardArray":["vcard",[["fn",{},"text","NOC"]]]}]}`,
			ASNRegistration{Handle: "AS3333", Range: "AS3333", Organization: "NOC"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := asnService(t, map[string]string{"https://data.iana.org/rdap/asn.json": asnBootstrap, "https://registry.example/rdap/autnum/3333": tt.body})
			got, err := s.ASNRegistration(context.Background(), 3333)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got  %+v, %v\nwant %+v", got, err, tt.want)
			}
		})
	}
}

func TestASNRegistrationRejectsUnrelatedRange(t *testing.T) {
	for _, body := range []string{`{}`, `{"handle":"AS3333","startAutnum":3333}`, `{"handle":"AS1","startAutnum":1,"endAutnum":2}`, `{"handle":"AS3333","startAutnum":4000,"endAutnum":3000}`, `{"handle":"AS3333","startAutnum":3334,"endAutnum":3999}`} {
		s := asnService(t, map[string]string{"https://data.iana.org/rdap/asn.json": asnBootstrap, "https://registry.example/rdap/autnum/3333": body})
		if got, err := s.ASNRegistration(context.Background(), 3333); err == nil {
			t.Errorf("accepted %s as %+v", body, got)
		}
	}
}

func TestASNBootstrapNarrowestRangeAndHTTPS(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		number     uint32
		want       string
	}{
		{"narrowest range", asnBootstrap, 3333, "https://registry.example/rdap/autnum/"},
		{"single number entry", asnBootstrap, 2043, "https://registry.example/rdap/autnum/"},
		{"wide range only", asnBootstrap, 15169, "https://wide.example/autnum/"},
		{"range bounds are inclusive", asnBootstrap, 3999, "https://registry.example/rdap/autnum/"},
		{"no matching registry", asnBootstrap, 70000, ""},
		{"no secure registry", `{"services":[[["1-65535"],["http://insecure.example/"]]]}`, 3333, ""},
		{"specific range without HTTPS does not fall back", `{"services":[[["1-65535"],["https://wide.example/"]],[["3000-3999"],["http://insecure.example/"]]]}`, 3333, ""},
		{"malformed range", `{"services":[[["abc"],["https://registry.example/"]]]}`, 3333, ""},
		{"reversed range", `{"services":[[["9-1"],["https://registry.example/"]]]}`, 3333, ""},
		{"malformed service", `{"services":[[["1-65535"]]]}`, 3333, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			endpoint, err := fixtureService(tt.body).asnRDAPEndpoint(context.Background(), tt.number)
			if tt.want == "" {
				if err == nil {
					t.Fatalf("accepted invalid registry %q", endpoint)
				}
			} else if err != nil || endpoint != tt.want {
				t.Fatal(endpoint, err)
			}
		})
	}
}

// Shapes follow RIPEstat's asn-neighbours and routing-status data calls.
const neighboursBody = `{"status":"ok","status_code":200,"messages":[["info","Query time has been set to the latest available time (2026-10-05 00:00 UTC)"]],"data":{"resource":"15169","query_starttime":"2026-10-05T00:00:00","query_endtime":"2026-10-05T00:00:00","latest_time":"2026-10-05T00:00:00","earliest_time":"2019-08-25T00:00:00","neighbour_counts":{"left":3,"right":2,"unique":6,"uncertain":1},"neighbours":[
{"asn":174,"type":"left","power":5,"v4_peers":10,"v6_peers":2},
{"asn":3356,"type":"left","power":9,"v4_peers":20,"v6_peers":4},
{"asn":1299,"type":"left","power":9,"v4_peers":30,"v6_peers":6},
{"asn":36040,"type":"right","power":2,"v4_peers":1,"v6_peers":0},
{"asn":396982,"type":"right","power":418,"v4_peers":1298085,"v6_peers":127932},
{"asn":64500,"type":"uncertain","power":700,"v4_peers":1,"v6_peers":0}]}}`

const routingBody = `{"status":"ok","status_code":200,"messages":[["info","Results exclude routes with very low visibility (less than 10 RIS full-feed peers seeing)."]],"data":{"first_seen":{"prefix":"64.209.204.0/24","origin":"15169","time":"2000-08-18T08:00:00"},"last_seen":{"prefix":"34.2.124.0/22","origin":"15169","time":"2026-10-05T08:00:00"},"visibility":{"v4":{"ris_peers_seeing":325,"total_ris_peers":325},"v6":{"ris_peers_seeing":315,"total_ris_peers":316}},"announced_space":{"v4":{"prefixes":1235,"ips":2615808},"v6":{"prefixes":176,"48s":721152}},"observed_neighbours":328,"resource":"15169","query_time":"2026-10-05T08:00:00"}}`

var neighbourNames = map[string]string{
	"as174.asn.cymru.com.":    "174 | US | arin | 1991-05-16 | COGENT-174, US",
	"as1299.asn.cymru.com.":   "1299 | SE | ripencc | 1993-09-01 | TWELVE99 Arelion, SE",
	"as3356.asn.cymru.com.":   "3356 | US | arin | 2000-03-10 | LEVEL3, US",
	"as396982.asn.cymru.com.": "396982 | US | arin | 2017-03-23 | GOOGLE-CLOUD-PLATFORM, US",
}

func TestASNNeighboursRanksTrimsAndNamesOnlyListedNeighbours(t *testing.T) {
	s := asnService(t, map[string]string{"https://stat.example/neighbours?resource=AS15169": neighboursBody})
	var asked func() []string
	s.DNS, asked = cymruFixture(t, neighbourNames)
	got, err := s.ASNNeighbours(context.Background(), 15169, 2)
	if err != nil {
		t.Fatal(err)
	}
	if want := (ASNNeighbourCounts{Total: 6, Upstream: 3, Downstream: 2, Uncertain: 1}); got.Number != 15169 || got.Counts != want || !got.Truncated || got.LatestTime != "2026-10-05T00:00:00" || got.Scope == "" {
		t.Fatalf("%+v", got)
	}
	// Power ranks first; equal power falls back to the lower AS number.
	if want := []ASNNeighbour{{1299, "TWELVE99 Arelion, SE", 9, 30, 6}, {3356, "LEVEL3, US", 9, 20, 4}}; !reflect.DeepEqual(got.Upstream, want) {
		t.Fatalf("upstream %+v", got.Upstream)
	}
	// AS36040 has no name record: it stays listed and is reported once.
	if want := []ASNNeighbour{{396982, "GOOGLE-CLOUD-PLATFORM, US", 418, 1298085, 127932}, {36040, "", 2, 1, 0}}; !reflect.DeepEqual(got.Downstream, want) {
		t.Fatalf("downstream %+v", got.Downstream)
	}
	if len(got.Warnings) != 1 {
		t.Fatalf("warnings %q", got.Warnings)
	}
	if want := []string{"as1299.asn.cymru.com.", "as3356.asn.cymru.com.", "as36040.asn.cymru.com.", "as396982.asn.cymru.com."}; !reflect.DeepEqual(asked(), want) {
		t.Fatalf("name lookups %q", asked())
	}
}

func TestASNNeighboursWithinLimitAndEmpty(t *testing.T) {
	s := asnService(t, map[string]string{"https://stat.example/neighbours?resource=AS15169": strings.Replace(neighboursBody, `{"asn":36040,"type":"right","power":2,"v4_peers":1,"v6_peers":0},`, "", 1)})
	s.DNS, _ = cymruFixture(t, neighbourNames)
	got, err := s.ASNNeighbours(context.Background(), 15169, 3)
	if err != nil || got.Truncated || len(got.Upstream) != 3 || got.Upstream[2].Number != 174 || got.Upstream[2].Name != "COGENT-174, US" || len(got.Downstream) != 1 || got.Warnings == nil || len(got.Warnings) != 0 {
		t.Fatalf("%+v, %v", got, err)
	}
	s = asnService(t, map[string]string{"https://stat.example/neighbours?resource=AS15169": `{"status":"ok","data":{"resource":"15169","neighbours":[]}}`})
	got, err = s.ASNNeighbours(context.Background(), 15169, 10)
	// Empty lists must encode as JSON arrays, so they are never nil.
	if err != nil || got.Counts != (ASNNeighbourCounts{}) || got.Upstream == nil || got.Downstream == nil || len(got.Upstream)+len(got.Downstream) != 0 || got.Truncated {
		t.Fatalf("%+v, %v", got, err)
	}
}

func TestASNNeighboursSaysWhenTheDeadlineCutNameLookupsShort(t *testing.T) {
	s := asnService(t, map[string]string{"https://stat.example/neighbours?resource=AS15169": neighboursBody})
	// A resolver that never answers keeps every name lookup waiting for the deadline.
	s.DNS = dnsFixture(t, func(dns.ResponseWriter, *dns.Msg) {})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	got, err := s.ASNNeighbours(ctx, 15169, 2)
	if err != nil || time.Since(start) > 2*time.Second {
		t.Fatalf("%v after %s", err, time.Since(start))
	}
	// RIPEstat's answer is kept; only the names are missing, and the warning
	// must blame the deadline rather than Team Cymru.
	if len(got.Upstream) != 2 || got.Upstream[0].Number != 1299 || got.Upstream[0].Name != "" || len(got.Downstream) != 2 {
		t.Fatalf("%+v", got)
	}
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], context.DeadlineExceeded.Error()) {
		t.Fatalf("warnings %q", got.Warnings)
	}
}

// lateDeadline is a context whose deadline has passed but which has not yet
// noticed: the window in which a DNS socket, which reads the deadline
// directly, can time out before the context reports DeadlineExceeded.
type lateDeadline struct {
	context.Context
	deadline time.Time
	done     chan struct{}
	expired  atomic.Bool
}

func (c *lateDeadline) Deadline() (time.Time, bool) { return c.deadline, true }
func (c *lateDeadline) Done() <-chan struct{}       { return c.done }
func (c *lateDeadline) Err() error {
	if c.expired.Load() {
		return context.DeadlineExceeded
	}
	return nil
}

func TestASNNeighboursBlamesTheDeadlineBeforeTheContextNotices(t *testing.T) {
	s := asnService(t, map[string]string{"https://stat.example/neighbours?resource=AS15169": neighboursBody})
	s.DNS = dnsFixture(t, func(dns.ResponseWriter, *dns.Msg) {})
	ctx := &lateDeadline{Context: context.Background(), deadline: time.Now().Add(-time.Millisecond), done: make(chan struct{})}
	// The lookups time out at once; the context notices well afterwards.
	time.AfterFunc(50*time.Millisecond, func() { ctx.expired.Store(true); close(ctx.done) })
	got, err := s.ASNNeighbours(ctx, 15169, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], context.DeadlineExceeded.Error()) {
		t.Fatalf("warnings %q", got.Warnings)
	}
}

func TestASNNeighboursRejectsBadProviderDataAndLimits(t *testing.T) {
	for _, body := range []string{
		`{"status":"error","data":{"resource":"15169","neighbours":[]}}`,
		`{"status":"ok","data":{"resource":"3333","neighbours":[]}}`,
		`{"status":"ok","data":{"neighbours":[]}}`,
		`{"status":"ok","data":{"resource":"15169","neighbours":[{"asn":174,"type":"sideways","power":1,"v4_peers":1,"v6_peers":0}]}}`,
		`{"status":"ok","data":{"resource":"15169","neighbours":[{"asn":0,"type":"left","power":1,"v4_peers":1,"v6_peers":0}]}}`,
		`{"status":"ok","data":{"resource":"15169","neighbours":[{"asn":174,"type":"left","power":-1,"v4_peers":1,"v6_peers":0}]}}`,
	} {
		s := asnService(t, map[string]string{"https://stat.example/neighbours?resource=AS15169": body})
		s.DNS, _ = cymruFixture(t, neighbourNames)
		if got, err := s.ASNNeighbours(context.Background(), 15169, 10); err == nil {
			t.Errorf("accepted %s as %+v", body, got)
		}
	}
	for _, limit := range []int{-1, 0, 101} {
		s := asnService(t, map[string]string{"https://stat.example/neighbours?resource=AS15169": neighboursBody})
		s.DNS, _ = cymruFixture(t, neighbourNames)
		if _, err := s.ASNNeighbours(context.Background(), 15169, limit); err == nil {
			t.Errorf("accepted limit %d", limit)
		}
	}
}

func TestASNRouting(t *testing.T) {
	s := asnService(t, map[string]string{"https://stat.example/routing?resource=AS15169": routingBody})
	got, err := s.ASNRouting(context.Background(), 15169)
	want := ASNRouting{Number: 15169, Announced: true,
		FirstSeen: &ASNSighting{Prefix: "64.209.204.0/24", Time: "2000-08-18T08:00:00"}, LastSeen: &ASNSighting{Prefix: "34.2.124.0/22", Time: "2026-10-05T08:00:00"},
		IPv4: ASNRoutingV4{PeersSeeing: 325, TotalPeers: 325, Prefixes: 1235, Addresses: 2615808}, IPv6: ASNRoutingV6{PeersSeeing: 315, TotalPeers: 316, Prefixes: 176, Slash48s: 721152},
		ObservedNeighbours: 328, QueryTime: "2026-10-05T08:00:00", Scope: got.Scope}
	if err != nil || got.Scope == "" || !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v, %v\nwant %+v", got, err, want)
	}
}

func TestASNRoutingWithoutCurrentAnnouncements(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		seenBefore bool
	}{
		{"withdrawn", `{"status":"ok","data":{"first_seen":{"prefix":"181.192.66.0/24","origin":"15169","time":"2020-02-26T00:00:00"},"last_seen":{"prefix":"181.192.66.0/24","origin":"15169","time":"2020-02-27T00:00:00"},"visibility":{"v4":{"ris_peers_seeing":0,"total_ris_peers":325},"v6":{"ris_peers_seeing":0,"total_ris_peers":315}},"announced_space":{"v4":{"prefixes":0,"ips":0},"v6":{"prefixes":0,"48s":0}},"observed_neighbours":0,"resource":"15169","query_time":"2026-10-05T08:00:00"}}`, true},
		{"never seen", `{"status":"ok","data":{"first_seen":{},"last_seen":{},"visibility":{"v4":{"ris_peers_seeing":0,"total_ris_peers":325},"v6":{"ris_peers_seeing":0,"total_ris_peers":315}},"announced_space":{"v4":{"prefixes":0,"ips":0},"v6":{"prefixes":0,"48s":0}},"observed_neighbours":0,"resource":"15169","query_time":"2026-10-05T08:00:00"}}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := asnService(t, map[string]string{"https://stat.example/routing?resource=AS15169": tt.body}).ASNRouting(context.Background(), 15169)
			if err != nil || got.Announced || (got.FirstSeen != nil) != tt.seenBefore || (got.LastSeen != nil) != tt.seenBefore || got.IPv4.TotalPeers != 325 {
				t.Fatalf("%+v, %v", got, err)
			}
			if tt.seenBefore && got.LastSeen.Time != "2020-02-27T00:00:00" {
				t.Fatalf("%+v", got.LastSeen)
			}
		})
	}
}

func TestASNRoutingRejectsBadProviderData(t *testing.T) {
	for _, body := range []string{`{}`, `{"status":"error","data":{"resource":"15169"}}`, `{"status":"ok","data":{"resource":"3333"}}`, `{"status":"ok","data":{}}`} {
		if got, err := asnService(t, map[string]string{"https://stat.example/routing?resource=AS15169": body}).ASNRouting(context.Background(), 15169); err == nil {
			t.Errorf("accepted %s as %+v", body, got)
		}
	}
}

func TestASNCompactLines(t *testing.T) {
	neighbours := ASNNeighbours{Number: 15169, Counts: ASNNeighbourCounts{Total: 6, Upstream: 3, Downstream: 1, Uncertain: 2},
		Upstream:   []ASNNeighbour{{1299, "TWELVE99 Arelion, SE", 9, 30, 6}, {3356, "", 9, 20, 4}},
		Downstream: []ASNNeighbour{{396982, "GOOGLE-CLOUD-PLATFORM, US", 418, 1298085, 127932}},
		Truncated:  true, Warnings: []string{"a warning"}, Scope: "neighbour scope"}
	if got, want := neighbours.CompactLines(), []string{
		"6 neighbours",
		"3 upstream · 1 downstream · 2 uncertain",
		"Upstream · top 2 of 3 by power",
		"  AS1299 · power 9 · TWELVE99 Arelion, SE",
		"  AS3356 · power 9",
		"Downstream · 1",
		"  AS396982 · power 418 · GOOGLE-CLOUD-PLATFORM, US",
		"a warning",
		"Path positions, not business relationships",
	}; !reflect.DeepEqual(got, want) {
		t.Errorf("neighbours:\n%s", strings.Join(got, "\n"))
	}
	if got, want := (ASNNeighbours{Upstream: []ASNNeighbour{}, Downstream: []ASNNeighbour{}, Scope: "neighbour scope"}).CompactLines(), []string{
		"0 neighbours", "0 upstream · 0 downstream · 0 uncertain", "Upstream · none", "Downstream · none", "Path positions, not business relationships",
	}; !reflect.DeepEqual(got, want) {
		t.Errorf("no neighbours:\n%s", strings.Join(got, "\n"))
	}
	routing := ASNRouting{Number: 15169, Announced: true,
		FirstSeen: &ASNSighting{Prefix: "64.209.204.0/24", Time: "2000-08-18T08:00:00"}, LastSeen: &ASNSighting{Prefix: "34.2.124.0/22", Time: "2026-10-05T08:00:00"},
		IPv4: ASNRoutingV4{PeersSeeing: 325, TotalPeers: 325, Prefixes: 1235, Addresses: 2615808}, IPv6: ASNRoutingV6{PeersSeeing: 315, TotalPeers: 316, Prefixes: 176, Slash48s: 721152},
		ObservedNeighbours: 328, Scope: "routing scope"}
	if got, want := routing.CompactLines(), []string{
		"Announced",
		"First seen 2000-08-18T08:00:00",
		"Last seen 2026-10-05T08:00:00",
		"IPv4 · 325 of 325 RIS peers",
		"  1235 prefixes · 2615808 addresses",
		"IPv6 · 315 of 316 RIS peers",
		"  176 prefixes · 721152 /48s",
		"328 observed neighbours",
		"As seen by RIPE RIS route collectors",
	}; !reflect.DeepEqual(got, want) {
		t.Errorf("routing:\n%s", strings.Join(got, "\n"))
	}
	// The interactive view lays sections out in columns about 47 cells wide and
	// hard-wraps anything longer, so fixed text must stay within that.
	for _, line := range append(neighbours.CompactLines()[:3], routing.CompactLines()...) {
		if len([]rune(line)) > 47 {
			t.Errorf("%d cells: %q", len([]rune(line)), line)
		}
	}
	if got := (ASNRouting{Scope: "routing scope"}).CompactLines(); got[0] != "Not announced" || strings.Contains(strings.Join(got, "\n"), "seen 2") {
		t.Errorf("unannounced:\n%s", strings.Join(got, "\n"))
	}
}
