package dnswire

import (
	"context"
	"github.com/miekg/dns"
	"net"
	"testing"
	"time"
)

func TestTruncatedUDPRetriesTCP(t *testing.T) {
	tcp, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	udp, e := net.ListenPacket("udp4", tcp.Addr().String())
	if e != nil {
		tcp.Close()
		t.Fatal(e)
	}
	readyUDP, readyTCP := make(chan struct{}), make(chan struct{})
	u := &dns.Server{PacketConn: udp, NotifyStartedFunc: func() { close(readyUDP) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		m.Truncated = true
		w.WriteMsg(m)
	})}
	s := &dns.Server{Listener: tcp, NotifyStartedFunc: func() { close(readyTCP) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP("192.0.2.42")}}
		w.WriteMsg(m)
	})}
	go u.ActivateAndServe()
	go s.ActivateAndServe()
	<-readyUDP
	<-readyTCP
	defer u.Shutdown()
	defer s.Shutdown()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	r, e := Exchange(ctx, q, tcp.Addr().String())
	if e != nil || r.Truncated || len(r.Answer) != 1 {
		t.Fatalf("%v %v", r, e)
	}
}

func TestCallerDeadlineOverridesLibraryDefault(t *testing.T) {
	c, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ready := make(chan struct{})
	s := &dns.Server{PacketConn: c, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		time.Sleep(2100 * time.Millisecond)
		m := new(dns.Msg)
		m.SetReply(q)
		w.WriteMsg(m)
	})}
	go s.ActivateAndServe()
	<-ready
	defer s.Shutdown()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	q := new(dns.Msg)
	q.SetQuestion("slow.test.", dns.TypeA)
	if _, e := Exchange(ctx, q, c.LocalAddr().String()); e != nil {
		t.Fatalf("caller timeout shortened by library default: %v", e)
	}
}
