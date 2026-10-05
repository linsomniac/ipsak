// Package dnssec validates a deliberately narrow set of DNSSEC answers locally.
// Resolver AD bits are observations only and never establish trust.
package dnssec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Step struct {
	Zone   string `json:"zone"`
	Detail string `json:"detail"`
}
type Result struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Resolver   string   `json:"resolver"`
	State      string   `json:"state"`
	Reason     string   `json:"reason"`
	ResolverAD bool     `json:"resolver_ad"`
	Answers    []string `json:"answers"`
	Chain      []Step   `json:"chain"`
	Note       string   `json:"note"`
}

func (r Result) CompactLines() []string {
	lines := []string{fmt.Sprintf("%s %s · %s", r.Name, r.Type, r.State)}
	if r.Reason != "" {
		lines = append(lines, r.Reason)
	}
	lines = append(lines, fmt.Sprintf("Resolver %s · AD %t (not trusted)", r.Resolver, r.ResolverAD))
	for _, step := range r.Chain {
		lines = append(lines, step.Zone+" · "+step.Detail)
	}
	for _, answer := range r.Answers {
		rr, err := dns.NewRR(answer)
		if signature, ok := rr.(*dns.RRSIG); err == nil && ok {
			lines = append(lines, fmt.Sprintf("RRSIG %s · signer %s · algorithm %d · key %d · valid %s–%s", dns.TypeToString[signature.TypeCovered], signature.SignerName, signature.Algorithm, signature.KeyTag, dns.TimeToString(signature.Inception), dns.TimeToString(signature.Expiration)))
		} else {
			lines = append(lines, answer)
		}
	}
	if r.Note != "" {
		lines = append(lines, r.Note)
	}
	return lines
}

// IANA root-anchors.xml, retrieved over authenticated HTTPS on 2026-09-26.
// These are the unexpired KSK-2017 and KSK-2024 SHA256 anchors. Updates require
// a reviewed release; this diagnostic does not implement RFC 5011 management.
func rootAnchors() []*dns.DS {
	return []*dns.DS{
		{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET}, KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"},
		{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET}, KeyTag: 38696, Algorithm: 8, DigestType: 2, Digest: "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"},
	}
}

type stateError struct{ state, reason string }

func (e *stateError) Error() string    { return e.reason }
func issue(state, reason string) error { return &stateError{state, reason} }
func supported(alg uint8) bool {
	switch alg {
	case dns.RSASHA256, dns.RSASHA512, dns.ECDSAP256SHA256, dns.ECDSAP384SHA384, dns.ED25519:
		return true
	}
	return false
}
func keyUsable(k *dns.DNSKEY) bool {
	return k.Hdr.Class == dns.ClassINET && k.Protocol == 3 && k.Flags&dns.ZONE != 0 && k.Flags&dns.REVOKE == 0 && supported(k.Algorithm)
}
func same(a, b string) bool { return strings.EqualFold(a, b) }
func ancestor(parent, child string) bool {
	return !same(parent, child) && dns.IsSubDomain(strings.ToLower(parent), strings.ToLower(child))
}

type validator struct {
	ctx      context.Context
	server   string
	anchors  []*dns.DS
	now      time.Time
	queries  int
	cache    map[string]*dns.Msg
	keyCache map[string][]*dns.DNSKEY
	active   map[string]bool
	chain    []Step
}

func Validate(ctx context.Context, name string, typ uint16, resolver string) (Result, error) {
	return validate(ctx, name, typ, resolver, rootAnchors())
}
func validate(ctx context.Context, name string, typ uint16, resolver string, anchors []*dns.DS) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	name = strings.ToLower(dns.Fqdn(name))
	r := Result{Name: name, Type: dns.TypeToString[typ], Resolver: resolver, State: "inconclusive", Answers: []string{}, Chain: []Step{}, Note: "Local cryptographic validation of exact-owner positive RRsets. General negative answers, CNAME/DNAME paths, wildcard expansion, and NSEC3 denial are inconclusive. Insecure requires an authenticated exact NSEC unsigned-delegation proof. AD is not trusted. Root anchors: IANA snapshot 2026-09-26 (20326,38696)."}
	v := &validator{ctx: ctx, server: resolver, anchors: anchors, now: time.Now(), cache: map[string]*dns.Msg{}, keyCache: map[string][]*dns.DNSKEY{}, active: map[string]bool{}}
	m, err := v.query(name, typ)
	if err == nil {
		r.ResolverAD = m.AuthenticatedData
		set, sigs := rrset(m.Answer, name, typ)
		// A secure verdict concerns this exact RRset only. Never present
		// unrelated resolver-supplied records alongside that verdict.
		for _, rr := range set {
			r.Answers = append(r.Answers, rr.String())
		}
		for _, sig := range sigs {
			r.Answers = append(r.Answers, sig.String())
		}
		if m.Rcode != dns.RcodeSuccess || len(set) == 0 {
			err = issue("inconclusive", "negative or missing answer requires unsupported denial validation")
		} else {
			for _, rr := range m.Answer {
				if rr.Header().Rrtype == dns.TypeCNAME || rr.Header().Rrtype == dns.TypeDNAME {
					err = issue("inconclusive", "CNAME/DNAME paths are not supported")
					break
				}
			}
			if err == nil {
				err = v.authenticate(set, sigs, "", 0)
			}
		}
	}
	r.Chain = v.chain
	if err != nil {
		var se *stateError
		if errors.As(err, &se) {
			r.State = se.state
			r.Reason = se.reason
		} else {
			r.Reason = err.Error()
		}
		if r.State == "insecure" {
			return r, nil
		}
		return r, err
	}
	r.State = "secure"
	r.Reason = "RRset signatures and DNSKEY/DS chain verified against an IANA root trust anchor"
	return r, nil
}

func (v *validator) query(name string, typ uint16) (*dns.Msg, error) {
	key := fmt.Sprintf("%s/%d", strings.ToLower(name), typ)
	if m := v.cache[key]; m != nil {
		return m, nil
	}
	v.queries++
	if v.queries > 32 {
		return nil, issue("inconclusive", "validation query limit reached")
	}
	ctx, cancel := context.WithTimeout(v.ctx, 2*time.Second)
	defer cancel()
	q := new(dns.Msg)
	q.SetQuestion(name, typ)
	q.CheckingDisabled = true
	q.SetEdns0(1232, true)
	for _, network := range []string{"udp", "tcp"} {
		c := &dns.Client{Net: network, Timeout: 2 * time.Second}
		conn, err := c.DialContext(ctx, v.server)
		if err != nil {
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		m, _, err := c.ExchangeWithConnContext(ctx, q, conn)
		stop()
		_ = conn.Close()
		if err != nil {
			return nil, err
		}
		if !m.Response || m.Opcode != dns.OpcodeQuery || len(m.Question) != 1 || !same(m.Question[0].Name, name) || m.Question[0].Qtype != typ || m.Question[0].Qclass != dns.ClassINET {
			return nil, issue("inconclusive", "invalid DNS response")
		}
		if m.Truncated && network == "udp" {
			continue
		}
		if m.Truncated || len(m.Answer)+len(m.Ns) > 512 {
			return nil, issue("inconclusive", "DNS response exceeds validation bounds")
		}
		if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
			return nil, issue("inconclusive", "DNS "+dns.RcodeToString[m.Rcode])
		}
		v.cache[key] = m
		return m, nil
	}
	return nil, issue("inconclusive", "truncated DNS response")
}

func rrset(records []dns.RR, name string, typ uint16) (set []dns.RR, sigs []*dns.RRSIG) {
	for _, rr := range records {
		h := rr.Header()
		if !same(h.Name, name) || h.Class != dns.ClassINET {
			continue
		}
		if h.Rrtype == typ {
			set = append(set, rr)
		}
		if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == typ {
			sigs = append(sigs, s)
		}
	}
	return
}

// verify checks all signatures against the complete exact-owner RRset. A valid
// supported signature is sufficient during normal key/algorithm rollovers.
func (v *validator) verify(set []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY, zone string) error {
	if len(set) == 0 {
		return issue("inconclusive", "missing RRset")
	}
	attempted := false
	wildcard := false
	for _, s := range sigs {
		if !same(s.SignerName, zone) || !supported(s.Algorithm) {
			continue
		}
		if int(s.Labels) != dns.CountLabel(set[0].Header().Name) {
			wildcard = true
			continue
		}
		if !dns.IsSubDomain(strings.ToLower(zone), strings.ToLower(set[0].Header().Name)) {
			continue
		}
		for _, k := range keys {
			if !keyUsable(k) || !same(k.Hdr.Name, zone) || s.KeyTag != k.KeyTag() || s.Algorithm != k.Algorithm {
				continue
			}
			attempted = true
			if !s.ValidityPeriod(v.now) {
				continue
			}
			if s.Verify(k, set) == nil {
				return nil
			}
		}
	}
	if wildcard {
		return issue("inconclusive", "wildcard or invalid label count requires unsupported denial validation")
	}
	if attempted {
		return issue("bogus", "supported DNSSEC signatures failed verification or validity dates")
	}
	return issue("inconclusive", "no supported signature and matching authenticated key")
}

func (v *validator) authenticate(set []dns.RR, sigs []*dns.RRSIG, parentOf string, depth int) error {
	var best error = issue("inconclusive", "unsigned RRset or unsupported signatures")
	for _, s := range sigs {
		zone := strings.ToLower(s.SignerName)
		if !supported(s.Algorithm) || !dns.IsSubDomain(zone, strings.ToLower(set[0].Header().Name)) {
			continue
		}
		if parentOf != "" && !ancestor(zone, parentOf) {
			continue
		}
		keys, err := v.keys(zone, depth+1)
		if err == nil {
			err = v.verify(set, sigs, keys, zone)
		}
		if err == nil {
			return nil
		}
		var se *stateError
		if errors.As(err, &se) && se.state == "insecure" {
			return err
		}
		if errors.As(err, &se) && se.state == "bogus" {
			best = err
		} else if e, ok := best.(*stateError); ok && e.state != "bogus" {
			best = err
		}
	}
	return best
}

func (v *validator) keys(zone string, depth int) ([]*dns.DNSKEY, error) {
	if keys := v.keyCache[zone]; keys != nil {
		return keys, nil
	}
	if depth > 16 || v.active[zone] {
		return nil, issue("inconclusive", "delegation depth or cycle limit")
	}
	v.active[zone] = true
	defer delete(v.active, zone)
	m, err := v.query(zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	set, sigs := rrset(m.Answer, zone, dns.TypeDNSKEY)
	var anchors []*dns.DS
	if zone == "." {
		anchors = v.anchors
	} else {
		dsmsg, e := v.query(zone, dns.TypeDS)
		if e != nil {
			return nil, e
		}
		dsset, dssigs := rrset(dsmsg.Answer, zone, dns.TypeDS)
		if len(dsset) == 0 {
			return nil, v.unsignedDelegation(dsmsg, zone, depth)
		}
		if e = v.authenticate(dsset, dssigs, zone, depth); e != nil {
			return nil, e
		}
		for _, rr := range dsset {
			anchors = append(anchors, rr.(*dns.DS))
		}
	}
	if len(set) == 0 {
		return nil, issue("inconclusive", "DNSKEY RRset missing")
	}
	keys := []*dns.DNSKEY{}
	matched := []*dns.DNSKEY{}
	usableDS := false
	for _, rr := range set {
		k := rr.(*dns.DNSKEY)
		if !keyUsable(k) {
			continue
		}
		keys = append(keys, k)
		for _, ds := range anchors {
			if !supported(ds.Algorithm) || (ds.DigestType != dns.SHA256 && ds.DigestType != dns.SHA384) {
				continue
			}
			usableDS = true
			if k.Algorithm != ds.Algorithm || k.KeyTag() != ds.KeyTag {
				continue
			}
			derived := k.ToDS(ds.DigestType)
			if derived != nil && same(derived.Digest, ds.Digest) {
				matched = append(matched, k)
			}
		}
	}
	// Unsupported keys must not turn an otherwise unsupported delegation bogus.
	if !usableDS {
		for _, ds := range anchors {
			if supported(ds.Algorithm) && (ds.DigestType == dns.SHA256 || ds.DigestType == dns.SHA384) {
				usableDS = true
			}
		}
	}
	if !usableDS {
		return nil, issue("inconclusive", "no supported DS digest and algorithm")
	}
	if len(matched) == 0 {
		return nil, issue("bogus", "DNSKEY does not match authenticated DS or configured root anchor")
	}
	if err = v.verify(set, sigs, matched, zone); err != nil {
		return nil, err
	}
	v.keyCache[zone] = keys
	v.chain = append(v.chain, Step{zone, "DNSKEY RRset authenticated through DS and a valid self-signature"})
	return keys, nil
}

func (v *validator) unsignedDelegation(m *dns.Msg, zone string, depth int) error {
	// Only the exact-owner NSEC proof at a delegation is implemented. NSEC3,
	// intervals, NXDOMAIN and empty nonterminals require additional proofs.
	if m.Rcode != dns.RcodeSuccess {
		return issue("inconclusive", "delegation denial proof unsupported")
	}
	records := append(append([]dns.RR{}, m.Answer...), m.Ns...)
	set, sigs := rrset(records, zone, dns.TypeNSEC)
	if len(set) != 1 {
		return issue("inconclusive", "no exact NSEC unsigned-delegation proof")
	}
	n := set[0].(*dns.NSEC)
	hasNS, hasDS, hasSOA := false, false, false
	for _, typ := range n.TypeBitMap {
		switch typ {
		case dns.TypeNS:
			hasNS = true
		case dns.TypeDS:
			hasDS = true
		case dns.TypeSOA:
			hasSOA = true
		}
	}
	if !hasNS || hasDS || hasSOA {
		return issue("inconclusive", "NSEC does not prove an unsigned delegation")
	}
	if err := v.authenticate(set, sigs, zone, depth); err != nil {
		return err
	}
	v.chain = append(v.chain, Step{zone, "Authenticated exact NSEC proves an unsigned delegation"})
	return issue("insecure", "authenticated parent NSEC proves no DS at delegation "+zone)
}
