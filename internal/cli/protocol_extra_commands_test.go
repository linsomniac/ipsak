package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
)

func TestProtocolExtraHelpAndValidation(t *testing.T) {
	for _, name := range []string{"mailcheck", "nat", "dnssec", "sshkey"} {
		out, stderr, code := invoke(name, "--help")
		if code != 0 || out == "" || stderr != "" {
			t.Fatal(name, out, stderr, code)
		}
	}
	for _, args := range [][]string{{"mailcheck", "127.0.0.1"}, {"mailcheck", "example.test", "--selector", ".bad"}, {"mailcheck", "example.test", "--smtp-port", "0"}, {"mailcheck", "example.test", "--resolver", "resolver.test"}, {"nat", "extra"}, {"nat", "--server", "example.test:0"}, {"dnssec", "example.test", "--type", "AXFR"}, {"dnssec", "127.0.0.1"}, {"dnssec", "example.test", "--resolver", "resolver.test"}, {"sshkey", "example.test", "--fingerprint", "SHA256:bad"}, {"sshkey", "example.test:99999"}} {
		out, stderr, code := invoke(append(args, "--json")...)
		if code != 2 || out != "" || stderr == "" {
			t.Fatal(args, out, stderr, code)
		}
	}
}

func TestProtocolExtraMailDefaultAndDNSSECADNotTrustedJSON(t *testing.T) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	s := &dns.Server{PacketConn: c, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		m.AuthenticatedData = true
		if q.Question[0].Name == "bad.test." {
			m.Rcode = dns.RcodeServerFailure
		} else if q.Question[0].Name == "sel._domainkey.example.test." {
			m.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "key.provider.test."}}
		} else if q.Question[0].Name == "key.provider.test." {
			m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"v=DKIM1; p=ABC"}}}
		} else if q.Question[0].Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = s.ActivateAndServe() }()
	<-ready
	defer s.Shutdown()
	for _, tc := range []struct {
		args []string
		code int
	}{{[]string{"mailcheck", "example.test"}, 0}, {[]string{"mailcheck", "example.test", "--selector", "sel"}, 0}, {[]string{"mailcheck", "bad.test"}, 1}, {[]string{"dnssec", "example.test"}, 1}} {
		out, stderr, code := invoke(append(tc.args, "--resolver", c.LocalAddr().String(), "--json")...)
		if code != tc.code {
			t.Fatal(out, stderr, code)
		}
		probeJSON(t, out, tc.args[0])
		if len(tc.args) > 2 && tc.args[0] == "mailcheck" && !strings.Contains(out, `"canonical_name": "key.provider.test."`) {
			t.Fatal("DKIM alias provenance missing", out)
		}
		if tc.args[0] == "dnssec" && (!strings.Contains(out, `"state": "inconclusive"`) || !strings.Contains(out, `"resolver_ad": true`)) {
			t.Fatal(out)
		}
	}
}

func TestProtocolExtraNATJSON(t *testing.T) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, a, e := c.ReadFrom(buf)
			if e != nil {
				return
			}
			if n != 20 {
				continue
			}
			p := make([]byte, 32)
			copy(p, buf[:20])
			binary.BigEndian.PutUint16(p, 0x101)
			binary.BigEndian.PutUint16(p[2:], 12)
			binary.BigEndian.PutUint16(p[20:], 0x20)
			binary.BigEndian.PutUint16(p[22:], 8)
			p[25] = 1
			binary.BigEndian.PutUint16(p[26:], 40000^0x2112)
			for i, b := range []byte{203, 0, 113, 1} {
				p[28+i] = b ^ p[4+i]
			}
			_, _ = c.WriteTo(p, a)
		}
	}()
	out, stderr, code := invoke("nat", "--server", c.LocalAddr().String(), "--json")
	if code != 0 || stderr != "" {
		t.Fatal(out, stderr, code)
	}
	probeJSON(t, out, "nat")
	if !strings.Contains(out, `"mapping": "203.0.113.1:40000"`) {
		t.Fatal(out)
	}
}

func TestProtocolExtraSSHKeyJSONMismatchRetainsKey(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _, _, _ = ssh.NewServerConn(c, cfg) }()
		}
	}()
	for _, p := range []string{ssh.FingerprintSHA256(signer.PublicKey()), "SHA256:" + strings.Repeat("A", 43)} {
		out, stderr, code := invoke("sshkey", ln.Addr().String(), "--fingerprint", p, "--json")
		expected := 0
		if p != ssh.FingerprintSHA256(signer.PublicKey()) {
			expected = 1
		}
		if code != expected {
			t.Fatal(out, stderr, code)
		}
		probeJSON(t, out, "sshkey")
		if !strings.Contains(out, ssh.FingerprintSHA256(signer.PublicKey())) {
			t.Fatal(out)
		}
	}
}

func TestProtocolExtraCanceledJSON(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, args := range [][]string{{"mailcheck", "example.test", "--resolver", "127.0.0.1:1"}, {"nat", "--server", "127.0.0.1:1"}, {"dnssec", "example.test", "--resolver", "127.0.0.1:1"}, {"sshkey", "127.0.0.1:1"}} {
		var out, stderr bytes.Buffer
		code := Execute(ctx, append(args, "--json"), strings.NewReader(""), &out, &stderr, "test")
		if code != 130 {
			t.Fatal(args, out.String(), stderr.String(), code)
		}
		r := probeJSON(t, out.String(), args[0])
		if r.Sections[0].Status != "error" {
			t.Fatal(r)
		}
	}
}
