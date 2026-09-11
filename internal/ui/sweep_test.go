package ui

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/linsomniac/ipsak/internal/ping"
)

func partialSweepFixture() ping.SweepSnapshot {
	rtt := &ping.RTTStats{Samples: 1, MinMS: 1.125, AvgMS: 1.125, MaxMS: 1.125}
	return ping.SweepSnapshot{
		CIDR: "192.0.2.0/29", Total: 5, Probed: 4, Completed: 3,
		Responded: 1, NoReply: 1, Errors: 1, Incomplete: 1, Unprobed: 1,
		Count: 3, Planned: 15, Attempts: 10, Sent: 6, Received: 1,
		Lost: 4, Pending: 1, SendErrors: 4, RTT: rtt,
		ElapsedSeconds: 2.4, Done: true, Partial: true, StopReason: "interrupted",
		Hosts: []ping.SweepHost{
			{Address: netip.MustParseAddr("192.0.2.1"), Status: "responded", Attempts: 3, Sent: 2, Received: 1, Lost: 1, SendErrors: 1, LossPercent: 50, RTT: rtt, Error: "temporary route failure"},
			{Address: netip.MustParseAddr("192.0.2.2"), Status: "no_reply", Attempts: 3, Sent: 3, Lost: 3, LossPercent: 100},
			{Address: netip.MustParseAddr("192.0.2.3"), Status: "error", Attempts: 3, SendErrors: 3, Error: "network unreachable"},
			{Address: netip.MustParseAddr("192.0.2.4"), Status: "incomplete", Attempts: 1, Sent: 1, Pending: 1},
			{Address: netip.MustParseAddr("192.0.2.5"), Status: "unprobed"},
		},
	}
}

func TestSweepSummaryKeepsResponderSendErrorsAndUsesSuccessfulSends(t *testing.T) {
	s := partialSweepFixture()
	out := (Theme{}).SweepSummary(s, false, 0)
	for _, want := range []string{
		"1 of 5 addresses responded", "1 no reply", "4 send failures",
		"192.0.2.1", "1/2", "50.0%", "temporary route failure",
		"192.0.2.3", "network unreachable", "3 other addresses omitted",
		"1.125/1.125/1.125/0.000 ms",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	for _, omitted := range []string{"192.0.2.2", "192.0.2.4", "192.0.2.5"} {
		if strings.Contains(out, omitted) {
			t.Fatalf("default output includes silent address %s:\n%s", omitted, out)
		}
	}
	if strings.Index(out, "192.0.2.1") > strings.Index(out, "192.0.2.3") {
		t.Fatal("address order changed")
	}
}

func TestSweepSummaryAllShowsPendingUnprobedAndUnavailableRTT(t *testing.T) {
	s := partialSweepFixture()
	s.RTT = nil
	s.Hosts = s.Hosts[1:]
	s.Total, s.Probed, s.Completed, s.Responded = 4, 3, 2, 0
	s.Planned, s.Attempts, s.Sent, s.Received, s.Lost, s.SendErrors = 12, 7, 4, 0, 3, 3
	out := (Theme{}).SweepSummary(s, true, 0)
	for _, want := range []string{
		"partial sweep", "1 pending", "1 unprobed", "3/4 addresses probed",
		"2/4 completed", "RTT unavailable", "192.0.2.2", "no reply",
		"192.0.2.4", "pending", "192.0.2.5", "unprobed",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "0.000") || strings.Contains(out, "omitted") {
		t.Fatalf("missing timing was rendered as zero, or --all omitted hosts:\n%s", out)
	}
}

func TestSweepSummaryNarrowOutputRetainsErrorsAndSanitizesValues(t *testing.T) {
	s := partialSweepFixture()
	s.CIDR += "\x1b[2J\u202e\r\n"
	s.Error = "receive\x1b]52;bad\a failure"
	s.Hosts[0].Error = "route\u202e\r\n failure"
	for _, width := range []int{1, 12, 30, 55, 80, 120} {
		out := (Theme{}).SweepSummary(s, true, width)
		for _, line := range strings.Split(out, "\n") {
			if got := ansi.StringWidth(line); got > width {
				t.Fatalf("width %d: line occupies %d columns: %q", width, got, line)
			}
		}
		for _, bad := range []string{"\x1b", "\a", "\r", "\u202e"} {
			if strings.Contains(out, bad) {
				t.Fatalf("terminal control %q survived at width %d", bad, width)
			}
		}
		// Wrapping may split words, but never discards the complete error text.
		compact := strings.Join(strings.Fields(out), "")
		if !strings.Contains(compact, "networkunreachable") || !strings.Contains(compact, "routefailure") {
			t.Fatalf("error details disappeared at width %d:\n%s", width, out)
		}
	}
}

func TestSweepStatusIncludesFailedSendsInSettledProgress(t *testing.T) {
	s := partialSweepFixture()
	out := (Theme{}).SweepStatus(s, 0)
	if !strings.Contains(out, "9/15 settled") || !strings.Contains(out, "1/5 responded") || !strings.Contains(out, "avg 1.125 ms") {
		t.Fatal(out)
	}
	if out = (Theme{}).SweepStatus(s, 80); !strings.Contains(out, "avg 1.125 ms") || ansi.StringWidth(out) > 80 {
		t.Fatal("normal terminal hid aggregate RTT", out)
	}
	s.Count, s.Planned, s.RTT = 0, 0, nil
	out = (Theme{}).SweepStatus(s, 0)
	if !strings.Contains(out, "9 settled") || !strings.Contains(out, "RTT unavailable") || strings.Contains(out, "/0") {
		t.Fatal(out)
	}
}

func TestSweepLiveViewFitsResizeAndBoundsPreview(t *testing.T) {
	s := ping.SweepSnapshot{Total: 64, Probed: 64, Responded: 40, Count: 3, Planned: 192, Attempts: 100, Sent: 100, Received: 80, Pending: 20}
	for i := range 32 {
		s.Hosts = append(s.Hosts, ping.SweepHost{
			Address: netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", i+1)),
			Status:  "responded", Sent: 3, Received: 2,
			RTT: &ping.RTTStats{Samples: 2, AvgMS: 1.25},
		})
	}
	box := &ping.SweepMailbox{}
	box.Publish(s)
	m := sweepModel{box: box, cancel: func() {}, width: 80, height: 24}
	updated, _ := m.Update(tick(time.Now()))
	m = updated.(sweepModel)
	for _, width := range []int{1, 12, 30, 55, 80, 120} {
		for _, height := range []int{1, 2, 3, 4, 8, 24, 100} {
			updated, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: height})
			view := updated.(sweepModel).View()
			lines := strings.Split(view, "\n")
			if len(lines) > max(1, height-1) {
				t.Fatalf("%dx%d produced %d rows:\n%s", width, height, len(lines), view)
			}
			for _, line := range lines {
				if ansi.StringWidth(line) > width {
					t.Fatalf("width %d: %q", width, line)
				}
			}
			if strings.Count(view, "192.0.2.") > 12 {
				t.Fatalf("unbounded host preview:\n%s", view)
			}
		}
	}
	view := m.View()
	if !strings.Contains(view, "+28 more responders") || !strings.Contains(view, "40/64 responded") || strings.Index(view, "192.0.2.2 ·") > strings.Index(view, "192.0.2.10 ·") {
		t.Fatal(view)
	}
	m.width = 30
	if view = m.View(); !strings.Contains(view, "1.25ms") {
		t.Fatalf("compact preview hid RTT:\n%s", view)
	}
}

func TestSweepStopKeysWaitForEngineCompletion(t *testing.T) {
	for _, key := range []tea.KeyMsg{
		{Type: tea.KeyRunes, Runes: []rune{'q'}},
		{Type: tea.KeyEsc},
		{Type: tea.KeyCtrlC},
	} {
		calls := 0
		box := &ping.SweepMailbox{}
		m := sweepModel{box: box, cancel: func() { calls++ }, width: 80, height: 24}
		updated, cmd := m.Update(key)
		m = updated.(sweepModel)
		if cmd != nil || !m.stopping || calls != 1 || !strings.Contains(m.View(), "Stopping") {
			t.Fatalf("key %s did not wait for cancellation: %q", key.String(), m.View())
		}
		updated, _ = m.Update(key)
		m = updated.(sweepModel)
		if calls != 1 {
			t.Fatalf("key %s cancelled repeatedly", key.String())
		}
		box.Publish(ping.SweepSnapshot{Done: true, Partial: true})
		updated, cmd = m.Update(tick(time.Now()))
		if updated.(sweepModel).View() != "" || cmd == nil {
			t.Fatal("finished engine did not clear and quit the inline view")
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Fatal("finished engine did not request terminal restoration")
		}
	}
}
