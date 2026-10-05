package mailcheck

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func mailDNS(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	c, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ready := make(chan struct{})
	s := &dns.Server{PacketConn: c, Handler: handler, NotifyStartedFunc: func() { close(ready) }}
	go func() { _ = s.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = s.Shutdown() })
	return c.LocalAddr().String()
}
func rr(t *testing.T, s string) dns.RR {
	t.Helper()
	r, e := dns.NewRR(s)
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func TestPoliciesConcurrentAndSplitTXT(t *testing.T) {
	var mu sync.Mutex
	arrived := 0
	all := make(chan struct{})
	server := mailDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		mu.Lock()
		arrived++
		if arrived == 4 {
			close(all)
		}
		mu.Unlock()
		select {
		case <-all:
		case <-time.After(time.Second):
		}
		m := new(dns.Msg)
		m.SetReply(q)
		switch {
		case q.Question[0].Qtype == dns.TypeMX:
			m.Answer = []dns.RR{rr(t, "example.test. 60 IN MX 20 mx2.example.test."), rr(t, "example.test. 60 IN MX 10 mx1.example.test.")}
		case q.Question[0].Name == "example.test.":
			m.Answer = []dns.RR{rr(t, `example.test. 60 IN TXT "v=spf1 " "-all"`), rr(t, `example.test. 60 IN TXT "unrelated=value"`)}
		case strings.HasPrefix(q.Question[0].Name, "_dmarc."):
			m.Answer = []dns.RR{rr(t, `_dmarc.example.test. 60 IN TXT "v=DMARC1; p=reject"`)}
		default:
			m.Answer = []dns.RR{rr(t, `sel._domainkey.example.test. 60 IN TXT "v=DKIM1; p=ABC"`)}
		}
		_ = w.WriteMsg(m)
	})
	r, e := Check(context.Background(), Options{Domain: "example.test.", Resolver: server, Selector: "sel", Port: 25})
	if e != nil || len(r.Policies) != 4 || r.MX[0].Preference != 10 || r.Policies[1].Records[0] != "v=spf1 -all" {
		t.Fatal(r, e)
	}
	for _, p := range r.Policies {
		if p.Status != "present" {
			t.Fatal(p)
		}
	}
}

func TestPolicyFailureMissingOwnerAndNullMX(t *testing.T) {
	for _, mode := range []string{"missing", "nxdomain", "servfail", "unrelated", "wrongclass", "alias", "duplicate", "valid_null", "mixed_null", "nonzero_null"} {
		t.Run(mode, func(t *testing.T) {
			server := mailDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
				m := new(dns.Msg)
				m.SetReply(q)
				name := q.Question[0].Name
				switch mode {
				case "nxdomain":
					m.Rcode = dns.RcodeNameError
				case "servfail":
					m.Rcode = dns.RcodeServerFailure
				case "unrelated":
					m.Answer = []dns.RR{rr(t, "other.test. 60 IN MX 10 bad.test."), rr(t, `other.test. 60 IN TXT "v=spf1 -all"`)}
				case "wrongclass":
					m.Answer = []dns.RR{rr(t, "example.test. 60 CH MX 10 bad.test.")}
				case "alias":
					m.Answer = []dns.RR{rr(t, name+" 60 IN CNAME other.test.")}
				case "duplicate":
					if q.Question[0].Qtype == dns.TypeTXT && name == "example.test." {
						m.Answer = []dns.RR{rr(t, `example.test. 60 IN TXT "v=spf1 -all"`), rr(t, `example.test. 60 IN TXT "v=spf1 +all"`)}
					}
				case "valid_null", "mixed_null", "nonzero_null":
					if q.Question[0].Qtype == dns.TypeMX {
						pref := 0
						if mode == "nonzero_null" {
							pref = 1
						}
						m.Answer = []dns.RR{rr(t, fmt.Sprintf("example.test. 60 IN MX %d .", pref))}
						if mode == "mixed_null" {
							m.Answer = append(m.Answer, rr(t, "example.test. 60 IN MX 10 mx.example.test."))
						}
					}
				}
				_ = w.WriteMsg(m)
			})
			r, err := Check(context.Background(), Options{Domain: "example.test.", Resolver: server, SMTP: true, Port: 25})
			wantError := mode == "servfail" || mode == "alias" || mode == "duplicate" || mode == "mixed_null" || mode == "nonzero_null"
			if (err != nil) != wantError || len(r.SMTP) != 0 {
				t.Fatal(r, err)
			}
			if (mode == "unrelated" || mode == "wrongclass") && len(r.MX) != 0 {
				t.Fatal("unrelated MX accepted", r)
			}
			if mode == "nxdomain" && r.Policies[0].Status != "nxdomain" {
				t.Fatal(r)
			}
		})
	}
}

func smtpFixture(t *testing.T, config *tls.Config, mode string) (int, <-chan []string) {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = ln.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	n, _ := strconv.Atoi(port)
	commands := make(chan []string, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		seen := []string{}
		defer func() { commands <- seen }()
		if mode == "stall" {
			_, _ = io.Copy(io.Discard, c)
			return
		}
		if mode == "huge" {
			_, _ = io.WriteString(c, "220 "+strings.Repeat("x", 70000)+"\r\n")
			return
		}
		_, _ = io.WriteString(c, "220 fixture ready\r\n")
		read := bufio.NewReader(c)
		for {
			line, e := read.ReadString('\n')
			if e != nil {
				return
			}
			seen = append(seen, strings.TrimSpace(line))
			if strings.HasPrefix(line, "EHLO ") {
				if mode == "no_tls" {
					_, _ = io.WriteString(c, "250 fixture\r\n")
				} else {
					_, _ = io.WriteString(c, "250-fixture\r\n250 STARTTLS\r\n")
				}
			} else if line == "STARTTLS\r\n" {
				_, _ = io.WriteString(c, "220 ready\r\n")
				secure := tls.Server(c, config)
				if secure.Handshake() != nil {
					return
				}
				c = secure
				read = bufio.NewReader(c)
			} else {
				return
			}
		}
	}()
	return n, commands
}

func TestSMTPAndSTARTTLS(t *testing.T) {
	h := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := h.TLS.Certificates[0]
	parsed, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	h.Close()
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}}
	for _, mode := range []string{"plain", "trusted", "untrusted", "no_tls", "huge", "stall"} {
		t.Run(mode, func(t *testing.T) {
			port, commands := smtpFixture(t, serverTLS, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			var cfg *tls.Config
			if mode == "trusted" {
				cfg = &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}
			}
			r := inspectSMTPWithTLS(ctx, "127.0.0.1", port, mode != "plain", cfg)
			wantError := mode != "plain" && mode != "trusted"
			if (r.Error != "") != wantError {
				t.Fatal(r)
			}
			if mode == "trusted" && !r.TLSVerified {
				t.Fatal(r)
			}
			if mode == "untrusted" && (r.Greeting == "" || !r.STARTTLS || r.TLSVerified) {
				t.Fatal(r)
			}
			select {
			case seen := <-commands:
				for _, s := range seen {
					if s != "EHLO ipsak.invalid" && s != "STARTTLS" {
						t.Fatal("unexpected SMTP command", s)
					}
				}
				if mode == "trusted" && len(seen) != 3 {
					t.Fatal(seen)
				}
			case <-time.After(time.Second):
				t.Fatal("SMTP connection not closed")
			}
		})
	}
}

func TestMailDNSCancellationDuringRead(t *testing.T) {
	started := make(chan struct{}, 3)
	server := mailDNS(t, func(w dns.ResponseWriter, q *dns.Msg) { started <- struct{}{} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := Check(ctx, Options{Domain: "example.test.", Resolver: server, Port: 25})
		done <- err
	}()
	select {
	case <-started:
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
		t.Fatal("DNS read did not cancel")
	}
}

func TestMailDNSFallsBackToTCP(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	var udpQueries, tcpQueries atomic.Int32
	h := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		if w.LocalAddr().Network() == "udp" {
			udpQueries.Add(1)
			m.Truncated = true
		} else {
			tcpQueries.Add(1)
			m.Answer = []dns.RR{rr(t, "example.test. 60 IN MX 0 .")}
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
	m, canonical, err := query(context.Background(), tcp.Addr().String(), "example.test.", dns.TypeMX)
	if err != nil || canonical != "example.test." || len(m.Answer) != 1 || udpQueries.Load() != 1 || tcpQueries.Load() != 1 {
		t.Fatal(m, err, udpQueries.Load(), tcpQueries.Load())
	}
}

func TestDKIMAliasesAndSPFSelection(t *testing.T) {
	for _, mode := range []string{"inline", "followup", "case", "negative", "nodata", "loop", "conflict", "coexisting", "wrongclass"} {
		t.Run(mode, func(t *testing.T) {
			const original = "sel._domainkey.example.test."
			const target = "key.provider.test."
			server := mailDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
				m := new(dns.Msg)
				m.SetReply(q)
				name := q.Question[0].Name
				if name == "example.test." && q.Question[0].Qtype == dns.TypeTXT {
					for _, s := range []string{"V=SPF1 -all", "v=spf10 -all", "v=spf1;-all"} {
						m.Answer = append(m.Answer, rr(t, fmt.Sprintf("example.test. 60 IN TXT %q", s)))
					}
				} else if name == original {
					m.Answer = []dns.RR{rr(t, original+" 60 IN CNAME "+target), rr(t, `unrelated.test. 60 IN TXT "attacker record"`)}
					if mode == "case" {
						m.Answer[0].(*dns.CNAME).Target = "KEY.PROVIDER.TEST."
					}
					if mode == "inline" {
						m.Answer = append(m.Answer, rr(t, target+` 60 IN TXT "v=DKIM1; p=ABC"`))
					}
					if mode == "conflict" {
						m.Answer = append(m.Answer, rr(t, original+" 60 IN CNAME other.provider.test."))
					}
					if mode == "coexisting" {
						m.Answer = append(m.Answer, rr(t, original+` 60 IN TXT "v=DKIM1; p=INVALID"`))
					}
					if mode == "wrongclass" {
						m.Answer = append([]dns.RR{rr(t, original+" 60 CH CNAME attacker.test.")}, m.Answer...)
					}
				} else if name == target {
					switch mode {
					case "loop":
						m.Answer = []dns.RR{rr(t, target+" 60 IN CNAME SEL._domainkey.EXAMPLE.test.")}
					case "negative":
						m.Rcode = dns.RcodeNameError
					case "nodata":
					default:
						m.Answer = []dns.RR{rr(t, target+` 60 IN TXT "v=DKIM1; p=ABC"`)}
					}
				}
				_ = w.WriteMsg(m)
			})
			r, err := Check(context.Background(), Options{Domain: "example.test.", Resolver: server, Selector: "sel", Port: 25})
			bad := mode == "loop" || mode == "conflict" || mode == "coexisting"
			if (err != nil) != bad || len(r.Policies[1].Records) != 1 || r.Policies[1].Records[0] != "V=SPF1 -all" {
				t.Fatal(r, err)
			}
			p := r.Policies[3]
			if !bad && (p.QueryName != original || p.CanonicalName != target) {
				t.Fatal(p)
			}
			if mode == "negative" {
				if p.Status != "nxdomain" {
					t.Fatal(p)
				}
			} else if mode == "nodata" {
				if p.Status != "missing" {
					t.Fatal(p)
				}
			} else if !bad && (p.Status != "present" || len(p.Records) != 1 || p.Records[0] != "v=DKIM1; p=ABC") {
				t.Fatal(p)
			}
		})
	}
	if policyRecord("DMARC", "v=dmarc1; p=reject") || !policyRecord("DMARC", "v=DMARC1; p=reject") {
		t.Fatal("DMARC version case selection changed")
	}
}

func TestMailAliasLimitAndMXCanonicalOwner(t *testing.T) {
	for _, links := range []int{8, 9} {
		server := mailDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(q)
			var index int
			_, _ = fmt.Sscanf(q.Question[0].Name, "n%d.test.", &index)
			if index < links {
				m.Answer = []dns.RR{rr(t, fmt.Sprintf("n%d.test. 60 IN CNAME n%d.test.", index, index+1))}
			} else {
				m.Answer = []dns.RR{rr(t, fmt.Sprintf(`n%d.test. 60 IN TXT "v=DKIM1; p=ABC"`, index))}
			}
			_ = w.WriteMsg(m)
		})
		_, owner, err := query(context.Background(), server, "n0.test.", dns.TypeTXT)
		if links == 8 && (err != nil || owner != "n8.test.") || links == 9 && err == nil {
			t.Fatal(links, owner, err)
		}
	}
	server := mailDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		if q.Question[0].Qtype == dns.TypeMX {
			m.Answer = []dns.RR{rr(t, "example.test. 60 IN CNAME mail.test."), rr(t, "mail.test. 60 IN MX 0 ."), rr(t, "unrelated.test. 60 IN MX 5 attacker.test.")}
		}
		_ = w.WriteMsg(m)
	})
	r, err := Check(context.Background(), Options{Domain: "example.test.", Resolver: server, Port: 25, SMTP: true})
	if err != nil || len(r.MX) != 1 || r.MX[0].Host != "." || r.Policies[0].CanonicalName != "mail.test." || len(r.SMTP) != 0 {
		t.Fatal(r, err)
	}
}

func TestMailAliasTargetReadCancels(t *testing.T) {
	started := make(chan struct{}, 1)
	server := mailDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		if q.Question[0].Name == "target.test." {
			started <- struct{}{}
			return
		}
		m := new(dns.Msg)
		m.SetReply(q)
		m.Answer = []dns.RR{rr(t, "alias.test. 60 IN CNAME target.test.")}
		_ = w.WriteMsg(m)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := query(ctx, server, "alias.test.", dns.TypeTXT); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("alias target query did not arrive")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("alias target read did not cancel")
	}
}
