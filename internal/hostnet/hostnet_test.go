package hostnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSocketFixtures(t *testing.T) {
	fixture := `tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:(("server one",pid=42,fd=3),("server",pid=43,fd=4))
udp UNCONN 0 0 [fe80::1%eth0]:5353 [::]:*
tcp ESTAB 12 3 [::1]:443 [::1]:51000
`
	rows, err := parseSockets([]byte(fixture), "ipv6")
	if err != nil || len(rows) != 3 {
		t.Fatalf("%+v %v", rows, err)
	}
	if len(rows[0].Processes) != 2 || rows[0].Processes[0].Name != "server one" || *rows[0].Local.Port != 8080 {
		t.Fatal(rows[0])
	}
	if rows[1].Local.Address != "fe80::1%eth0" || rows[1].Remote.Port != nil || rows[1].ProcessStatus == "available" {
		t.Fatal(rows[1])
	}
	bound, err := parseSockets([]byte("udp ESTAB 0 0 192.0.2.3%eth0:68 192.0.2.1:67\n"), "ipv4")
	if err != nil || len(bound) != 1 || bound[0].Local.Address != "192.0.2.3%eth0" {
		t.Fatalf("%+v %v", bound, err)
	}
	bound, err = parseSockets([]byte("udp UNCONN 0 0 [fe80::1]%eth0:546 [::]:*\n"), "ipv6")
	if err != nil || len(bound) != 1 || bound[0].Local.Address != "fe80::1%eth0" {
		t.Fatalf("%+v %v", bound, err)
	}
	for _, endpoint := range []string{"[fe80::1]%eth0:546", "[fe80::1%eth0]:546", "fe80::1%eth0:546"} {
		e, err := parseEndpoint(endpoint)
		if err != nil || e.Address != "fe80::1%eth0" || e.Port == nil || *e.Port != 546 {
			t.Fatalf("%s => %+v %v", endpoint, e, err)
		}
	}
	partial, err := parseSockets([]byte(fixture+"bad\n"), "ipv6")
	if err == nil || len(partial) != 3 {
		t.Fatalf("partial=%v err=%v", partial, err)
	}
	for _, s := range []string{"garbage", "127.0.0.1:65536", "[::1]:bad", "bad:3", "[fe80::1%eth0]%eth1:546", "[fe80::1]bad:546", "fe80::1]:546", "[fe80::1:546"} {
		if _, err := parseEndpoint(s); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	if _, err := parseSockets([]byte(strings.Repeat("udp UNCONN 0 0 *:9 *:*\n", maxRows+1)), "ipv4"); err == nil {
		t.Fatal("missing row cap")
	}
}

func TestRouteFixtures(t *testing.T) {
	var r RouteReport
	if err := parseLinuxRoute([]byte(`[{"dst":"198.51.100.1","gateway":"192.0.2.1","dev":"eth0","prefsrc":"192.0.2.3","table":100}]`), &r); err != nil {
		t.Fatal(err)
	}
	if r.Interface != "eth0" || *r.Source != "192.0.2.3" || *r.Gateway != "192.0.2.1" || r.NextHopKind != "gateway" {
		t.Fatal(r)
	}
	r = RouteReport{}
	if err := parseLinuxRoute([]byte(`[{"type":"local","dev":"lo","prefsrc":"::1"}]`), &r); err != nil || r.NextHopKind != "local" || r.Gateway != nil {
		t.Fatalf("%+v %v", r, err)
	}
	for _, f := range []string{`[]`, `{}`, `[{}]`, `[{"dev":"eth0","gateway":"garbage"}]`, `[{"dev":"eth0","prefsrc":"garbage"}]`} {
		if err := parseLinuxRoute([]byte(f), &RouteReport{}); err == nil {
			t.Fatalf("accepted %s", f)
		}
	}
	r = RouteReport{Address: "192.0.2.19"}
	if err := parseDarwinRoute([]byte("route to: 192.0.2.19\ndestination: 192.0.2.0\nmask: 255.255.255.0\ngateway: link#4\ninterface: en0\n"), &r); err != nil || *r.MatchedPrefix != "192.0.2.0/24" || r.NextHopKind != "on-link" {
		t.Fatalf("%+v %v", r, err)
	}
	r = RouteReport{Address: "2001:db8::3"}
	if err := parseDarwinRoute([]byte("destination: default\ngateway: fe80::1%en0\ninterface: en0\n"), &r); err != nil || *r.MatchedPrefix != "::/0" || *r.Gateway != "fe80::1%en0" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, flag := range []string{"LOCAL", "REJECT", "BLACKHOLE"} {
		r = RouteReport{Address: "127.0.0.1"}
		err := parseDarwinRoute([]byte("destination: 127.0.0.1\ninterface: lo0\nflags: <UP,HOST,"+flag+">\n"), &r)
		want := map[string]string{"LOCAL": "local", "REJECT": "unreachable", "BLACKHOLE": "blackhole"}[flag]
		if r.RouteType != want || r.NextHopKind != want || r.Interface != "lo0" || (err != nil) != (flag != "LOCAL") {
			t.Fatalf("flag=%s route=%+v err=%v", flag, r, err)
		}
	}
}

func TestNeighborFixtures(t *testing.T) {
	b := []byte(`[{"dst":"192.0.2.1","dev":"eth0","lladdr":"00:11:22:33:44:55","state":["STALE"]},{"dst":"2001:db8::1","dev":"eth0","state":["INCOMPLETE"],"router":true}]`)
	r, err := parseNeighbors(b)
	if err != nil || len(r) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	if r[0].MAC == nil || r[1].MAC != nil || r[1].Family != "ipv6" || !r[1].Router || r[1].States[0] != "INCOMPLETE" {
		t.Fatal(r)
	}
	for _, f := range []string{`{}`, `[{"dst":"bad","dev":"eth0"}]`, `[{"dst":"::1"}]`, `[{"dst":"::1","dev":"lo","lladdr":"bad"}]`} {
		if _, err := parseNeighbors([]byte(f)); err == nil {
			t.Fatalf("accepted %s", f)
		}
	}
}

func TestDarwinSocketFixtures(t *testing.T) {
	fixture := "p123\x00cweb server\x00\nf7\x00tIPv6\x00PTCP\x00n[::1]:8080\x00TST=LISTEN\x00\nf8\x00tIPv4\x00PUDP\x00n*:5353\x00\np456\x00cclient\x00\nf12\x00tIPv4\x00PTCP\x00n127.0.0.1:51000->127.0.0.1:8080\x00TST=ESTABLISHED\x00\n"
	rows, err := parseLsof([]byte(fixture))
	if err != nil || len(rows) != 3 {
		t.Fatalf("%+v %v", rows, err)
	}
	if rows[0].State != "LISTEN" || rows[0].Processes[0].Name != "web server" || rows[0].ReceiveQueue != nil || rows[1].State != "UNCONN" || *rows[2].Remote.Port != 8080 {
		t.Fatal(rows)
	}
	for _, bad := range []string{"text", "p1\x00f1\x00PTCP\x00", "p1\x00f1\x00PTCP\x00PUDP\x00", "p1\x00n*:3\x00"} {
		if _, err := parseLsof([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	rows, err = parseLsof(nil)
	if err != nil || len(rows) != 0 {
		t.Fatalf("%+v %v", rows, err)
	}
}

func TestDarwinNeighborFixtures(t *testing.T) {
	arp := "? (192.0.2.1) at 0:1:2:3:4:5 on en0 ifscope [ethernet]\n? (192.0.2.2) at (incomplete) on en0 ifscope [ethernet]\n? (192.0.2.3) at 2:3:4:5:6:7 on en1 permanent [ethernet]\n"
	rows, err := parseDarwinARP([]byte(arp))
	if err != nil || len(rows) != 3 {
		t.Fatalf("%+v %v", rows, err)
	}
	if *rows[0].MAC != "00:01:02:03:04:05" || rows[1].MAC != nil || rows[1].States[0] != "INCOMPLETE" || rows[2].States[1] != "PERMANENT" {
		t.Fatal(rows)
	}
	ndp := "Neighbor Linklayer Address Netif Expire St Flgs Prbs\nfe80::1%en0 0:1:2:3:4:5 en0 23h59m59s S R\n2001:db8::2 (incomplete) en0 expired I 3\n::1 0:0:0:0:0:1 lo0 permanent R\n"
	rows, err = parseDarwinNDP([]byte(ndp))
	if err != nil || len(rows) != 3 {
		t.Fatalf("%+v %v", rows, err)
	}
	if !rows[0].Router || rows[0].States[0] != "STALE" || rows[1].States[0] != "INCOMPLETE" || rows[2].States[1] != "PERMANENT" {
		t.Fatal(rows)
	}
	if _, err := parseDarwinNDP([]byte("bad header")); err == nil {
		t.Fatal("bad header accepted")
	}
	if _, err := parseDarwinARP([]byte("? (bad) at bad on en0")); err == nil {
		t.Fatal("bad arp accepted")
	}
	for _, parse := range []func([]byte) ([]Neighbor, error){parseDarwinARP, parseDarwinNDP} {
		if rows, err := parse(nil); err != nil || len(rows) != 0 {
			t.Fatalf("%+v %v", rows, err)
		}
	}
}

func TestInterfaceSamples(t *testing.T) {
	first := InterfaceReport{Interfaces: []Interface{{Name: "eth0", Index: 1, Counters: &Counters{RXBytes: 100, TXBytes: 200}}, {Name: "gone", Index: 2, Counters: &Counters{RXBytes: 10}}}}
	second := InterfaceReport{Interfaces: []Interface{{Name: "eth0", Index: 1, Counters: &Counters{RXBytes: 500, TXBytes: 400}}}}
	r := mergeSamples(first, second, 2*time.Second)
	if len(r.Interfaces) != 2 || r.Interfaces[0].Throughput.RXBytesPerSecond != 200 || r.Interfaces[0].Throughput.TXBytesPerSecond != 100 || !strings.Contains(r.Interfaces[1].ThroughputStatus, "disappeared") {
		t.Fatal(r)
	}
	second.Interfaces[0].Counters.RXBytes = 1
	second.Interfaces[0].Throughput = nil
	r = mergeSamples(first, second, time.Second)
	if r.Interfaces[0].Throughput != nil || !strings.Contains(r.Interfaces[0].ThroughputStatus, "reset") {
		t.Fatal(r)
	}
	second.Interfaces[0].Index = 99
	r = mergeSamples(first, second, time.Second)
	if !strings.Contains(r.Interfaces[len(r.Interfaces)-1].ThroughputStatus, "identity") {
		t.Fatal(r)
	}
}
func TestCounterFixturesAndCancellation(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "statistics"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"} {
		if err := os.WriteFile(filepath.Join(dir, "statistics", name), []byte("123\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c, err := readCounters(dir)
	if err != nil || c.RXBytes != 123 || c.TXDropped != 123 {
		t.Fatalf("%+v %v", c, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "statistics", "rx_bytes"), []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCounters(dir); err == nil {
		t.Fatal("invalid counter accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Interfaces(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := SampleInterfaces(ctx, "", time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestMagicPacketAndValidation(t *testing.T) {
	p, err := MagicPacket("00:11:22:33:44:55")
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 102 || !bytes.Equal(p[:6], bytes.Repeat([]byte{255}, 6)) {
		t.Fatal(p)
	}
	for i := range 16 {
		if !bytes.Equal(p[6+i*6:12+i*6], []byte{0, 17, 34, 51, 68, 85}) {
			t.Fatal(p)
		}
	}
	for _, mac := range []string{"bad", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "00:11:22:33:44:55:66:77"} {
		if _, err := MagicPacket(mac); err == nil {
			t.Fatalf("accepted %s", mac)
		}
	}
	o := WakeOptions{MAC: "00:11:22:33:44:55", Destination: "255.255.255.255", Port: 9, Count: 1, Interval: 10 * time.Millisecond}
	if err = o.Validate(); err != nil {
		t.Fatal(err)
	}
	o.Destination = "::1"
	if err = o.Validate(); err == nil {
		t.Fatal("accepted IPv6")
	}
}

func TestWakeLoopback(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	o := WakeOptions{MAC: "00:11:22:33:44:55", Destination: "127.0.0.1", Port: conn.LocalAddr().(*net.UDPAddr).Port, Count: 3, Interval: 10 * time.Millisecond}
	r, err := Wake(ctx, o)
	if err != nil || r.Sent != 3 {
		t.Fatalf("%+v %v", r, err)
	}
	want, _ := MagicPacket(o.MAC)
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		buf := make([]byte, 2048)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil || !bytes.Equal(buf[:n], want) {
			t.Fatalf("packet %x %v", buf[:n], err)
		}
	}
	o.Count = 100
	o.Interval = time.Second
	ctx2, cancel2 := context.WithCancel(context.Background())
	done := make(chan struct{})
	var partial WakeReport
	var sendErr error
	go func() { partial, sendErr = Wake(ctx2, o); close(done) }()
	buf := make([]byte, 2048)
	if _, _, err := conn.ReadFromUDP(buf); err != nil {
		t.Fatal(err)
	}
	cancel2()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("wake did not cancel promptly")
	}
	if !errors.Is(sendErr, context.Canceled) || partial.Sent != 1 {
		t.Fatalf("%+v %v", partial, sendErr)
	}
}

func TestBoundedCommand(t *testing.T) {
	if os.Getenv("IPSAK_HOST_HELPER") == "1" {
		switch os.Args[len(os.Args)-1] {
		case "overflow":
			fmt.Print(strings.Repeat("x", maxOutput+1))
		case "wait":
			time.Sleep(10 * time.Second)
		case "empty":
			os.Exit(1)
		}
		os.Exit(0)
	}
	t.Setenv("IPSAK_HOST_HELPER", "1")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := command(ctx, os.Args[0], "-test.run=^TestBoundedCommand$", "overflow"); !errors.Is(err, errOutputLimit) {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel2()
	if _, err := command(ctx2, os.Args[0], "-test.run=^TestBoundedCommand$", "wait"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if b, err := commandOutput(ctx, true, os.Args[0], "-test.run=^TestBoundedCommand$", "empty"); err != nil || len(b) != 0 {
		t.Fatalf("%q %v", b, err)
	}
}
