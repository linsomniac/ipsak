package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/linsomniac/ipsak/internal/ping"
)

func TestUntrustedFieldsCannotControlTerminal(t *testing.T) {
	r := lookup.Report{Command: "info", Target: "test\x1b]52;bad\a", Sections: []lookup.Section{{Title: "DNS", Status: "error", Data: map[string]string{"txt": "hello\x1b[2J\u202e\x85"}, Error: "bad\rthing"}}}
	out := (Theme{}).Report(r, 80, 0)
	for _, bad := range []string{"\x1b", "\x07", "\r", "\u202e", "\x85"} {
		if strings.Contains(out, bad) {
			t.Fatalf("unsafe %q in %q", bad, out)
		}
	}
}

func TestLossTextAndNarrowLiveOutput(t *testing.T) {
	l := ping.Loss{First: 7, Last: 15, Count: 9, Started: time.Now()}
	if !strings.Contains(ping.LossText(l), "Lost 9 packets, ids 7–15") {
		t.Fatal(ping.LossText(l))
	}
	s := ping.Snapshot{Address: "2001:db8:abcd:1234::1234", Sent: 20, Received: 11, Lost: 9, LossPercent: 45, ActiveLoss: &l}
	for _, w := range []int{20, 40, 80, 120} {
		line := (Theme{}).PingStatus(s, w)
		if ansi.StringWidth(line) > w || strings.Contains(line, "\n") {
			t.Fatalf("width %d: %q", w, line)
		}
	}
}

func TestPlainFieldsKeepLargeCountsReadable(t *testing.T) {
	got := strings.Join(fields(map[string]any{"addresses": uint64(2615808), "asn": uint32(4200000000), "ratio": 12.5, "small": 7}, 0), "\n")
	for _, want := range []string{"addresses      2615808", "asn            4200000000", "ratio          12.5", "small          7"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestASNNeighboursRenderCompactOnlyInInteractiveColumns(t *testing.T) {
	section := lookup.Section{Title: "Neighbours · BGP", Status: "ok", Data: lookup.ASNNeighbours{
		Counts:   lookup.ASNNeighbourCounts{Total: 1, Upstream: 1},
		Upstream: []lookup.ASNNeighbour{{Number: 1299, Name: "TWELVE99 - Arelion Sweden AB, SE", Power: 354}}, Downstream: []lookup.ASNNeighbour{}}}
	// Plain output (width 0) is the detailed field list; a terminal column gets
	// the one-line-per-neighbour form, wrapped to the column.
	if plain := (Theme{}).Section(section, 0, 0); !strings.Contains(plain, "upstream 1 · asn 1299") || strings.Contains(plain, "AS1299 · power 354") {
		t.Fatalf("plain:\n%s", plain)
	}
	column := (Theme{}).Section(section, 47, 0)
	if !strings.Contains(column, "AS1299 · power 354") || strings.Contains(column, "upstream 1 · asn") {
		t.Fatalf("column:\n%s", column)
	}
	for _, line := range strings.Split(column, "\n") {
		if ansi.StringWidth(line) > 47 {
			t.Errorf("%d cells: %q", ansi.StringWidth(line), line)
		}
	}
}
