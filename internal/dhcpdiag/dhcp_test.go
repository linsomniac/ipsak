package dhcpdiag

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/linsomniac/ipsak/internal/localnet"
)

var fixtureMAC = net.HardwareAddr{2, 0, 0, 0, 0, 1}

func offerPacket() []byte {
	p, _ := DiscoverPacket(123, fixtureMAC)
	p = p[:240]
	p[0] = 2
	copy(p[16:20], []byte{192, 0, 2, 10})
	p = append(p, 53, 1, 2, 54, 4, 192, 0, 2, 1, 1, 4, 255, 255, 255, 0, 3, 4, 192, 0, 2, 1, 6, 4, 192, 0, 2, 53, 51, 4, 0, 0, 14, 16, 255)
	return p
}
func TestDHCPDiscoverNeverRequestsLease(t *testing.T) {
	p, err := DiscoverPacket(123, fixtureMAC)
	if err != nil || len(p) < 300 || p[0] != 1 || p[10] != 0x80 || !bytes.Equal(p[28:34], fixtureMAC) || binary.BigEndian.Uint32(p[4:8]) != 123 {
		t.Fatal(p, err)
	}
	if !bytes.Equal(p[12:28], make([]byte, 16)) || !bytes.Equal(p[240:243], []byte{53, 1, 1}) {
		t.Fatal("not a discover-only packet")
	}
	if _, err := DiscoverPacket(1, nil); err == nil {
		t.Fatal("invalid hardware accepted")
	}
}
func TestDHCPOfferValidationAndOverload(t *testing.T) {
	p := offerPacket()
	o, err := ParseOffer(p, 123, fixtureMAC)
	if err != nil || o.Address != "192.0.2.10" || o.Server != "192.0.2.1" || len(o.DNS) != 1 || o.LeaseSeconds != 3600 || o.Evidence != "offer_only" {
		t.Fatal(o, err)
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte)
	}{{"xid", func(p []byte) { p[7] ^= 1 }}, {"chaddr", func(p []byte) { p[28] ^= 1 }}, {"op", func(p []byte) { p[0] = 1 }}, {"cookie", func(p []byte) { p[236] = 0 }}, {"type", func(p []byte) { p[242] = 5 }}, {"badlength", func(p []byte) { p[244] = 250 }}, {"address", func(p []byte) { clear(p[16:20]) }}} {
		t.Run(test.name, func(t *testing.T) {
			copy := bytes.Clone(p)
			test.mutate(copy)
			if _, err := ParseOffer(copy, 123, fixtureMAC); err == nil {
				t.Fatal("accepted invalid reply")
			}
		})
	}
	for n := 0; n < len(p); n++ {
		if _, err := ParseOffer(p[:n], 123, fixtureMAC); err == nil {
			t.Fatalf("truncation accepted at %d", n)
		}
	}
	overload := bytes.Clone(p[:240])
	copy(overload[108:236], []byte{54, 4, 192, 0, 2, 1, 255})
	overload = append(overload, 53, 1, 2, 52, 1, 1, 255)
	if _, err := ParseOffer(overload, 123, fixtureMAC); err != nil {
		t.Fatal(err)
	}
	overload[109] = 255
	if _, err := ParseOffer(overload, 123, fixtureMAC); err == nil {
		t.Fatal("malformed overloaded field accepted")
	}
}

func TestDHCPOfferSessionProvenanceAndCancellation(t *testing.T) {
	iface := net.Interface{Index: 3, Name: "fixture", HardwareAddr: fixtureMAC}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type reply struct {
		packet      []byte
		index, port int
		ip          net.IP
	}
	replies := make(chan reply, 8)
	closed := make(chan struct{})
	var once sync.Once
	writes := 0
	socket := probeIO{close: func() error { once.Do(func() { close(closed) }); return nil }, deadline: func(time.Time) error { return nil }, write: func(p []byte) error {
		writes++
		if len(p) < 243 || p[242] != 1 {
			t.Fatal("sent non-DISCOVER", p)
		}
		replies <- reply{offerPacket(), 3, 68, net.ParseIP("192.0.2.1")}
		replies <- reply{offerPacket(), 4, 67, net.ParseIP("192.0.2.1")}
		replies <- reply{offerPacket(), 3, 67, net.IPv4zero}
		bad := offerPacket()
		bad[7] ^= 1
		replies <- reply{bad, 3, 67, net.ParseIP("192.0.2.1")}
		replies <- reply{offerPacket(), 3, 67, net.ParseIP("192.0.2.1")}
		return nil
	}, read: func(p []byte) (int, int, *net.UDPAddr, error) {
		select {
		case <-closed:
			return 0, 0, nil, io.EOF
		case r := <-replies:
			return copy(p, r.packet), r.index, &net.UDPAddr{IP: r.ip, Port: r.port}, nil
		}
	}}
	r, err := collectOffers(ctx, iface, time.Second, 123, socket, ProbeResult{Offers: []Offer{}}, func(ProbeResult) { cancel() })
	if err != context.Canceled || r.Ignored != 4 || len(r.Offers) != 1 || writes != 1 || r.Sent != 1 || r.Offers[0].Interface != "fixture" {
		t.Fatal(r, err, writes)
	}
	select {
	case <-closed:
	default:
		t.Fatal("probe socket not closed")
	}
}
func TestDHCPLeaseFormatsAndScope(t *testing.T) {
	fixtures := []string{"ADDRESS=192.0.2.10\nSERVER_ADDRESS=192.0.2.1\nROUTER=192.0.2.1\nDNS=192.0.2.53 192.0.2.54\nLIFETIME=3600\n", "ip_address = 192.0.2.10\ndhcp_server_identifier = 192.0.2.1\ndomain_name_servers = 192.0.2.53 192.0.2.54\ndhcp_lease_time = 3600\n", "yiaddr = 192.0.2.10\nserver_identifier (ip): 192.0.2.1\ndomain_name_server (ip_mult): {192.0.2.53, 192.0.2.54}\nlease_time (uint32): 0xe10\n", "lease {\ninterface \"eth0\";\nfixed-address 192.0.2.10;\noption dhcp-server-identifier 192.0.2.1;\noption domain-name-servers 192.0.2.53, 192.0.2.54;\noption dhcp-lease-time 3600;\n}"}
	for _, fixture := range fixtures {
		l, err := ParseLease([]byte(fixture), "eth0", "fixture")
		if err != nil || l.Address != "192.0.2.10" || l.LeaseSeconds != 3600 || len(l.DNS) != 2 {
			t.Fatal(l, err)
		}
	}
	multiple := fixtures[3] + "\nlease {\ninterface \"eth1\";\nfixed-address 198.51.100.2;\noption dhcp-server-identifier 198.51.100.1;\n}"
	l, err := ParseLease([]byte(multiple), "eth0", "fixture")
	if err != nil || l.Address != "192.0.2.10" {
		t.Fatal(l, err)
	}
	l, err = ParseLease([]byte(multiple), "file", "fixture")
	if err != nil || l.Interface != "eth1" || l.Address != "198.51.100.2" {
		t.Fatal(l, err)
	}
	for _, bad := range []string{"", "ADDRESS=192.0.2.1", "ADDRESS=bad\nSERVER_ADDRESS=192.0.2.1", "ADDRESS=0.0.0.0\nSERVER_ADDRESS=192.0.2.1", strings.Repeat("x", (256<<10)+1)} {
		if _, err := ParseLease([]byte(bad), "file", "fixture"); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}
func TestDHCPReadOnlyAdaptersAndCancellation(t *testing.T) {
	iface := net.Interface{Index: 4, Name: "en0"}
	file := func(path, name string) (Lease, error) { return Lease{}, fmt.Errorf("missing fixture") }
	for _, goos := range []string{"linux", "darwin"} {
		calls := 0
		runner := func(ctx context.Context, name string, args ...string) (localnet.CommandResult, error) {
			calls++
			joined := strings.Join(args, " ")
			if goos == "linux" && (name != "nmcli" || !strings.Contains(joined, "DHCP4.OPTION device show en0")) {
				t.Fatal(name, args)
			}
			if goos == "darwin" && (name != "/usr/sbin/ipconfig" || joined != "getpacket en0") {
				t.Fatal(name, args)
			}
			return localnet.CommandResult{Stdout: []byte("ADDRESS=192.0.2.10\nSERVER_ADDRESS=192.0.2.1")}, nil
		}
		l, err := inspectInterface(context.Background(), iface, goos, runner, file)
		if err != nil || calls != 1 || l.Interface != "en0" {
			t.Fatal(l, err, calls)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Inspect(ctx, nil, ""); err != context.Canceled {
		t.Fatal(err)
	}
	if _, err := Probe(ctx, "fixture", 3e9, nil); err != context.Canceled {
		t.Fatal(err)
	}
}
