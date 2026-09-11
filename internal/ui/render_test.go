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
