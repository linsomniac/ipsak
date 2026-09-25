package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/linsomniac/ipsak/internal/hostnet"
	"github.com/linsomniac/ipsak/internal/lookup"
)

func TestCompactInventoryWidthsAndEscapes(t *testing.T) {
	port := uint16(443)
	values := []any{
		hostnet.SocketReport{Count: 1, Sockets: []hostnet.Socket{{Protocol: "tcp", Family: "ipv4", State: "LISTEN", Local: hostnet.Endpoint{Address: "127.0.0.1", Port: &port}, Remote: hostnet.Endpoint{Address: "*"}, Processes: []hostnet.Process{{PID: 42, Name: "evil\x1b[2J\u202eprocess"}}}}},
		hostnet.NeighborReport{Count: 1, Neighbors: []hostnet.Neighbor{{Address: "192.0.2.1", Interface: "eth\x1b[2J\u202e0", States: []string{"STALE"}}}},
		hostnet.InterfaceReport{Interfaces: []hostnet.Interface{{Name: "eth\x1b[2J\u202e0", MTU: 1500, Up: true, CountersStatus: "unavailable", Addresses: []string{"192.0.2.2/24"}}}},
	}
	for _, value := range values {
		for _, width := range []int{32, 80} {
			out := (Theme{}).Section(lookup.Section{Title: "Inventory", Status: "ok", Data: value}, width, 0)
			if strings.ContainsAny(out, "\x1b\u202e") {
				t.Fatalf("unsafe rendering: %q", out)
			}
			for _, line := range strings.Split(out, "\n") {
				if ansi.StringWidth(line) > width {
					t.Fatalf("width %d: %q", width, line)
				}
			}
		}
	}
}

func TestCompactInventoryUnknownValuesAndFullPlain(t *testing.T) {
	r := hostnet.InterfaceReport{Interfaces: []hostnet.Interface{{Name: "eth0", MTU: 1500, CountersStatus: "unavailable on test"}}}
	s := lookup.Section{Title: "Interfaces", Status: "ok", Data: r}
	compact := (Theme{}).Section(s, 80, 0)
	if !strings.Contains(compact, "counters: unavailable") || strings.Contains(compact, "received 0") {
		t.Fatal(compact)
	}
	plain := (Theme{}).Section(s, 0, 0)
	if !strings.Contains(plain, "interfaces 1 · counters status") || strings.Contains(plain, "counters:") {
		t.Fatal("plain no longer retains field names:", plain)
	}
	s.Data = hostnet.InterfaceReport{Interfaces: []hostnet.Interface{{Name: "eth0", Counters: &hostnet.Counters{RXBytes: 2048, TXBytes: 1024}, Throughput: &hostnet.Throughput{RXBytesPerSecond: 4096, TXBytesPerSecond: 2048}}}}
	out := (Theme{}).Section(s, 80, 0)
	if !strings.Contains(out, "received 2.0 KiB · sent 1.0 KiB") || !strings.Contains(out, "rate ↓4.0 KiB/s ↑2.0 KiB/s") {
		t.Fatal(out)
	}
	neighbors, _ := diagnosticLines(hostnet.NeighborReport{Count: 1, Neighbors: []hostnet.Neighbor{{Address: "192.0.2.1"}}})
	if !strings.Contains(strings.Join(neighbors, "\n"), "MAC unavailable") {
		t.Fatal(neighbors)
	}
}
