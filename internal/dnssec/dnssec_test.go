package dnssec

import (
	"context"
	"crypto"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type signedFixture struct {
	records                   map[string][]dns.RR
	denial                    []dns.RR
	root, child               *dns.DNSKEY
	rootPrivate, childPrivate crypto.Signer
	ad, truncate              bool
	started                   chan struct{}
}

func questionKey(name string, typ uint16) string { return fmt.Sprintf("%s/%d", name, typ) }
func newKey(t *testing.T, name string) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 60}, Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	p, err := k.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	return k, p.(crypto.Signer)
}
func signed(t *testing.T, k *dns.DNSKEY, private crypto.Signer, rrs ...dns.RR) []dns.RR {
	t.Helper()
	s := &dns.RRSIG{Hdr: dns.RR_Header{Ttl: 60}, Algorithm: k.Algorithm, KeyTag: k.KeyTag(), SignerName: k.Hdr.Name, Inception: uint32(time.Now().Add(-time.Hour).Unix()), Expiration: uint32(time.Now().Add(time.Hour).Unix())}
	if err := s.Sign(private, rrs); err != nil {
		t.Fatal(err)
	}
	return append(rrs, s)
}
func newFixture(t *testing.T) *signedFixture {
	t.Helper()
	f := &signedFixture{records: map[string][]dns.RR{}}
	f.root, f.rootPrivate = newKey(t, ".")
	f.child, f.childPrivate = newKey(t, "test.")
	f.records[questionKey(".", dns.TypeDNSKEY)] = signed(t, f.root, f.rootPrivate, f.root)
	f.records[questionKey("test.", dns.TypeDNSKEY)] = signed(t, f.child, f.childPrivate, f.child)
	f.records[questionKey("test.", dns.TypeDS)] = signed(t, f.root, f.rootPrivate, f.child.ToDS(dns.SHA256))
	a := &dns.A{Hdr: dns.RR_Header{Name: "www.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}
	f.records[questionKey("www.test.", dns.TypeA)] = signed(t, f.child, f.childPrivate, a)
	return f
}
func serveFixture(t *testing.T, f *signedFixture) string {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		if f.started != nil {
			f.started <- struct{}{}
			return
		}
		m := new(dns.Msg)
		m.SetReply(q)
		m.AuthenticatedData = f.ad
		if !q.CheckingDisabled || q.IsEdns0() == nil || !q.IsEdns0().Do() {
			m.Rcode = dns.RcodeRefused
		} else {
			question := q.Question[0]
			if f.truncate && w.LocalAddr().Network() == "udp" {
				m.Truncated = true
			} else {
				m.Answer = f.records[questionKey(question.Name, question.Qtype)]
				if question.Name == "test." && question.Qtype == dns.TypeDS && len(m.Answer) == 0 {
					m.Ns = f.denial
				}
			}
		}
		_ = w.WriteMsg(m)
	})
	for _, s := range []*dns.Server{{Listener: tcp, Handler: h}, {PacketConn: udp, Handler: h}} {
		ready := make(chan struct{})
		s.NotifyStartedFunc = func() { close(ready) }
		go func() { _ = s.ActivateAndServe() }()
		<-ready
		t.Cleanup(func() { _ = s.Shutdown() })
	}
	return tcp.Addr().String()
}

func TestValidationStatesAndUntrustedResolverAssertions(t *testing.T) {
	cases := []struct {
		name, state string
		change      func(*signedFixture)
	}{
		{"secure", "secure", func(f *signedFixture) {}},
		{"tcp_fallback", "secure", func(f *signedFixture) { f.truncate = true }},
		{"tampered_answer", "bogus", func(f *signedFixture) {
			f.records[questionKey("www.test.", dns.TypeA)][0].(*dns.A).A = net.ParseIP("192.0.2.99")
		}},
		{"expired", "bogus", func(f *signedFixture) {
			f.records[questionKey("www.test.", dns.TypeA)][1].(*dns.RRSIG).Expiration = uint32(time.Now().Add(-time.Hour).Unix())
		}},
		{"ds_mismatch", "bogus", func(f *signedFixture) {
			ds := f.child.ToDS(dns.SHA256)
			ds.Digest = strings.Repeat("0", 64)
			f.records[questionKey("test.", dns.TypeDS)] = signed(t, f.root, f.rootPrivate, ds)
		}},
		{"unsupported_ds", "inconclusive", func(f *signedFixture) {
			ds := f.child.ToDS(dns.SHA256)
			ds.Algorithm = 253
			f.records[questionKey("test.", dns.TypeDS)] = signed(t, f.root, f.rootPrivate, ds)
		}},
		{"unsupported_signature", "inconclusive", func(f *signedFixture) { f.records[questionKey("www.test.", dns.TypeA)][1].(*dns.RRSIG).Algorithm = 253 }},
		{"ad_only_unsigned", "inconclusive", func(f *signedFixture) {
			f.ad = true
			f.records[questionKey("www.test.", dns.TypeA)] = f.records[questionKey("www.test.", dns.TypeA)][:1]
		}},
		{"wildcard", "inconclusive", func(f *signedFixture) { f.records[questionKey("www.test.", dns.TypeA)][1].(*dns.RRSIG).Labels = 1 }},
		{"wrong_signer", "inconclusive", func(f *signedFixture) {
			f.records[questionKey("www.test.", dns.TypeA)][1].(*dns.RRSIG).SignerName = "unrelated."
		}},
		{"wrong_class", "inconclusive", func(f *signedFixture) {
			f.records[questionKey("www.test.", dns.TypeA)][0].Header().Class = dns.ClassCHAOS
		}},
		{"incomplete_rrset", "bogus", func(f *signedFixture) {
			a := f.records[questionKey("www.test.", dns.TypeA)][0]
			b := dns.Copy(a).(*dns.A)
			b.A = net.ParseIP("192.0.2.2")
			set := signed(t, f.child, f.childPrivate, a, b)
			f.records[questionKey("www.test.", dns.TypeA)] = []dns.RR{a, set[2]}
		}},
		{"bad_key_protocol", "bogus", func(f *signedFixture) { f.child.Protocol = 2 }},
		{"missing_zone_flag", "bogus", func(f *signedFixture) { f.child.Flags = 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.change(f)
			r, err := validate(context.Background(), "www.test.", dns.TypeA, serveFixture(t, f), []*dns.DS{f.root.ToDS(dns.SHA256)})
			if r.State != tc.state || (err == nil) != (tc.state == "secure") {
				t.Fatalf("state=%s err=%v report=%+v", r.State, err, r)
			}
			if tc.state == "secure" && len(r.Chain) != 2 {
				t.Fatal(r)
			}
		})
	}
}

func TestNSECUnsignedDelegationRequiresAuthenticatedExactProof(t *testing.T) {
	for _, mode := range []string{"valid", "forged", "has_ds", "has_soa", "no_ns", "wrong_owner", "self_signed"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			delete(f.records, questionKey("test.", dns.TypeDS))
			n := &dns.NSEC{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 60}, NextDomain: "zzz.", TypeBitMap: []uint16{dns.TypeNS, dns.TypeNSEC, dns.TypeRRSIG}}
			switch mode {
			case "has_ds":
				n.TypeBitMap = append(n.TypeBitMap, dns.TypeDS)
			case "has_soa":
				n.TypeBitMap = append(n.TypeBitMap, dns.TypeSOA)
			case "no_ns":
				n.TypeBitMap = []uint16{dns.TypeNSEC, dns.TypeRRSIG}
			case "wrong_owner":
				n.Hdr.Name = "other."
			}
			sort.Slice(n.TypeBitMap, func(i, j int) bool { return n.TypeBitMap[i] < n.TypeBitMap[j] })
			f.denial = signed(t, f.root, f.rootPrivate, n)
			if mode == "forged" {
				f.denial[1].(*dns.RRSIG).Signature = "AAAA"
			}
			if mode == "self_signed" {
				f.denial = signed(t, f.child, f.childPrivate, n)
			}
			r, err := validate(context.Background(), "www.test.", dns.TypeA, serveFixture(t, f), []*dns.DS{f.root.ToDS(dns.SHA256)})
			if mode == "valid" {
				if err != nil || r.State != "insecure" {
					t.Fatal(r, err)
				}
			} else if err == nil || r.State == "insecure" || r.State == "secure" {
				t.Fatal(r, err)
			}
		})
	}
}

func TestCanceledAndNegativeAreInconclusive(t *testing.T) {
	f := newFixture(t)
	address := serveFixture(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	r, err := validate(ctx, "www.test.", dns.TypeA, address, []*dns.DS{f.root.ToDS(dns.SHA256)})
	if err == nil || r.State != "inconclusive" || time.Since(start) > time.Second {
		t.Fatal(r, err)
	}
	r, err = validate(context.Background(), "missing.test.", dns.TypeA, address, []*dns.DS{f.root.ToDS(dns.SHA256)})
	if err == nil || r.State != "inconclusive" {
		t.Fatal(r, err)
	}
}

func TestDNSSECCancelsInFlightDNSRead(t *testing.T) {
	f := newFixture(t)
	f.started = make(chan struct{}, 1)
	address := serveFixture(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := validate(ctx, "www.test.", dns.TypeA, address, []*dns.DS{f.root.ToDS(dns.SHA256)})
		done <- err
	}()
	select {
	case <-f.started:
	case <-time.After(time.Second):
		t.Fatal("DNS request did not arrive")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("DNSSEC read did not cancel")
	}
}

func TestSecureOutputExcludesUnrelatedResolverRecords(t *testing.T) {
	f := newFixture(t)
	a := &dns.A{Hdr: dns.RR_Header{Name: "unrelated.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.99")}
	wrongType := &dns.TXT{Hdr: dns.RR_Header{Name: "www.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"untrusted extra data"}}
	wrongClass := dns.Copy(a).(*dns.A)
	wrongClass.Hdr.Name = "www.test."
	wrongClass.Hdr.Class = dns.ClassCHAOS
	f.records[questionKey("www.test.", dns.TypeA)] = append(f.records[questionKey("www.test.", dns.TypeA)], a, wrongType, wrongClass)
	r, err := validate(context.Background(), "www.test.", dns.TypeA, serveFixture(t, f), []*dns.DS{f.root.ToDS(dns.SHA256)})
	if err != nil || r.State != "secure" || len(r.Answers) != 2 {
		t.Fatal(r, err)
	}
	for _, answer := range r.Answers {
		if strings.Contains(answer, "unrelated") || strings.Contains(answer, "untrusted") || strings.Contains(answer, "192.0.2.99") {
			t.Fatal("unvalidated record escaped into secure output", r)
		}
	}
}
