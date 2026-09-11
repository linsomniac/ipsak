package ui

import (
	"context"
	"fmt"
	"io"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/linsomniac/ipsak/internal/ping"
)

// SweepStatus describes accepted replies over the session, not current presence.
func (t Theme) SweepStatus(s ping.SweepSnapshot, width int) string {
	settled := s.Attempts - s.Pending
	progress := fmt.Sprintf("%d settled", settled)
	if s.Count > 0 {
		progress = fmt.Sprintf("%d/%d settled", settled, s.Planned)
	}
	line := fmt.Sprintf("%d/%d responded · %s · %.1fs", s.Responded, s.Total, progress, s.ElapsedSeconds)
	if width > 0 && width < 55 {
		progress = fmt.Sprintf("%d settled", settled)
		if s.Planned > 0 {
			progress = fmt.Sprintf("%.0f%%", 100*float64(settled)/float64(s.Planned))
		}
		line = fmt.Sprintf("%d responded · %s · %.1fs", s.Responded, progress, s.ElapsedSeconds)
	} else {
		var timing string
		if s.RTT == nil {
			timing = " · RTT unavailable"
		} else {
			timing = fmt.Sprintf(" · avg %.3f ms", s.RTT.AvgMS)
		}
		if width == 0 || ansi.StringWidth(line+timing) <= width {
			line += timing
		}
	}
	return sweepTruncate(t.Heading(line), width)
}

func sweepTruncate(line string, width int) string {
	if width > 0 {
		return ansi.Truncate(line, width, "…")
	}
	return line
}

func sweepHostStatus(h ping.SweepHost) string {
	status := h.Status
	switch status {
	case "no_reply":
		status = "no reply"
	case "error":
		status = "send error"
	case "incomplete":
		if h.Pending > 0 {
			status = "pending"
		}
	}
	if h.Pending > 0 && status != "pending" {
		status += fmt.Sprintf(" · %d pending", h.Pending)
	}
	return Clean(status)
}

func sweepLoss(h ping.SweepHost) string {
	if h.Sent == 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f%%", h.LossPercent)
}

func sweepRTT(r *ping.RTTStats) string {
	if r == nil {
		return "unavailable"
	}
	return fmt.Sprintf("%.3f/%.3f/%.3f", r.MinMS, r.AvgMS, r.MaxMS)
}

// SweepSummary retains all responders and send errors. Width zero preserves
// full plain output; narrow reports wrap details instead of hiding errors.
func (t Theme) SweepSummary(s ping.SweepSnapshot, all bool, width int) string {
	state := "Finished"
	if s.Partial {
		state = "Stopped · partial sweep"
	}
	if s.StopReason == "duration" {
		state = "Duration reached"
		if s.Partial {
			state += " · partial sweep"
		}
	} else if s.StopReason == "interrupted" {
		state = "Stopped"
		if s.Partial {
			state += " · partial sweep"
		}
	}
	if s.Error != "" {
		state = "Failed"
		if s.Partial {
			state += " · partial sweep"
		}
	}
	addresses := fmt.Sprintf("%d of %d addresses responded · %d no reply", s.Responded, s.Total, s.NoReply)
	for _, extra := range []struct {
		count int
		label string
	}{{s.Errors, "errors"}, {s.Incomplete, "incomplete"}, {s.Unprobed, "unprobed"}} {
		if extra.count > 0 {
			addresses += fmt.Sprintf(" · %d %s", extra.count, extra.label)
		}
	}
	packets := fmt.Sprintf("%d sent · %d received · %d lost", s.Sent, s.Received, s.Lost)
	for _, extra := range []struct {
		count uint64
		label string
	}{{s.Pending, "pending"}, {s.Late, "late"}, {s.SendErrors, "send failures"}} {
		if extra.count > 0 {
			packets += fmt.Sprintf(" · %d %s", extra.count, extra.label)
		}
	}
	lines := []string{t.Heading(fmt.Sprintf("%s · %s · %.1fs", state, Clean(s.CIDR), s.ElapsedSeconds)), addresses, packets}
	if s.RTT == nil {
		lines = append(lines, "RTT unavailable (no timely replies)")
	} else {
		lines = append(lines, fmt.Sprintf("RTT min/avg/max/stddev = %s/%.3f ms", sweepRTT(s.RTT), s.RTT.StdDevMS))
	}
	if s.Partial {
		lines = append(lines, t.Warn(fmt.Sprintf("Partial results · %d/%d addresses probed · %d/%d completed", s.Probed, s.Total, s.Completed, s.Total)))
	}
	if s.Error != "" {
		lines = append(lines, t.Warn("Error: "+Clean(s.Error)))
	}
	lines = append(lines, "")
	addressWidth, shown := len("ADDRESS"), 0
	for _, h := range s.Hosts {
		if !all && h.Received == 0 && h.SendErrors == 0 && h.Error == "" {
			continue
		}
		if n := len(h.Address.String()); n > addressWidth {
			addressWidth = n
		}
		shown++
	}
	table := width == 0 || width >= addressWidth+61
	if shown > 0 && table {
		lines = append(lines, t.Muted(fmt.Sprintf("%-*s  %12s  %7s  %25s  %s", addressWidth, "ADDRESS", "REPLIES/SENT", "LOSS", "MIN/AVG/MAX (ms)", "STATUS")))
	}
	for _, h := range s.Hosts {
		if !all && h.Received == 0 && h.SendErrors == 0 && h.Error == "" {
			continue
		}
		replies := fmt.Sprintf("%d/%d", h.Received, h.Sent)
		status := sweepHostStatus(h)
		if table {
			lines = append(lines, fmt.Sprintf("%-*s  %12s  %7s  %25s  %s", addressWidth, Clean(h.Address.String()), replies, sweepLoss(h), sweepRTT(h.RTT), status))
		} else {
			lines = append(lines, t.Heading(Clean(h.Address.String())), fmt.Sprintf("  %s replies/sent · loss %s · %s", replies, sweepLoss(h), status))
			if h.RTT == nil {
				lines = append(lines, "  RTT unavailable")
			} else {
				lines = append(lines, "  RTT min/avg/max = "+sweepRTT(h.RTT)+" ms")
			}
		}
		if h.SendErrors > 0 || h.Error != "" {
			detail := fmt.Sprintf("  %d send failures in %d attempts", h.SendErrors, h.Attempts)
			if h.Error != "" {
				detail += " · " + Clean(h.Error)
			}
			lines = append(lines, t.Warn(detail))
		}
	}
	if shown == 0 {
		lines = append(lines, t.Muted("No timely replies received."))
	} else if !all && shown < s.Total {
		lines = append(lines, t.Muted(fmt.Sprintf("%d other addresses omitted; use --all to list every address.", s.Total-shown)))
	}
	if width > 0 {
		for i := range lines {
			lines[i] = ansi.Hardwrap(ansi.Wrap(lines[i], width, ""), width, false)
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

type sweepModel struct {
	box           *ping.SweepMailbox
	cancel        context.CancelFunc
	theme         Theme
	width, height int
	s             ping.SweepSnapshot
	stopping      bool
}

func (m sweepModel) Init() tea.Cmd { return refresh() }

func (m sweepModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = max(1, msg.Width), max(1, msg.Height)
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "esc" || msg.String() == "ctrl+c" {
			if !m.stopping {
				m.stopping = true
				m.cancel()
			}
		}
	case tick:
		m.s = m.box.Snapshot()
		if m.s.Done {
			return m, tea.Quit
		}
		return m, refresh()
	}
	return m, nil
}

func (m sweepModel) View() string {
	if m.s.Done {
		return ""
	}
	width, height := max(1, m.width), max(1, m.height)
	limit := max(1, height-1)
	if m.stopping && limit < 3 {
		return sweepTruncate(m.theme.Muted("Stopping…"), width)
	}
	if m.s.Total == 0 {
		message := "Starting sweep…"
		if m.stopping {
			message = "Stopping…"
		}
		return sweepTruncate(m.theme.Muted(message), width)
	}
	lines := []string{m.theme.SweepStatus(m.s, width)}
	if limit == 1 {
		return lines[0]
	}
	footer := "q / Esc / Ctrl-C stop"
	if m.stopping {
		footer = "Stopping…"
	}
	if limit >= 3 {
		lines = append(lines, m.theme.Muted(fmt.Sprintf("%d/%d probed · %d pending · %d send failures", m.s.Probed, m.s.Total, m.s.Pending, m.s.SendErrors)))
	}
	// Reserve the footer and an overflow notice. The engine's preview is itself
	// bounded; the view displays at most twelve rows even in very tall terminals.
	available := min(12, max(0, limit-len(lines)-2))
	shown := 0
	for _, h := range m.s.Hosts {
		if shown == available {
			break
		}
		if h.Received == 0 && h.SendErrors == 0 && h.Error == "" {
			continue
		}
		rtt := "RTT unavailable"
		if h.RTT != nil {
			rtt = fmt.Sprintf("avg %.3f ms", h.RTT.AvgMS)
		}
		line := fmt.Sprintf("%s · %d/%d replies/sent · %s", Clean(h.Address.String()), h.Received, h.Sent, rtt)
		if width < 75 {
			rtt = "—"
			if h.RTT != nil {
				rtt = fmt.Sprintf("%.2fms", h.RTT.AvgMS)
			}
			line = fmt.Sprintf("%s  %d/%d  %s", Clean(h.Address.String()), h.Received, h.Sent, rtt)
		}
		if h.SendErrors > 0 || h.Error != "" {
			line = "! " + line
			line += fmt.Sprintf(" · %d send failures", h.SendErrors)
			line = m.theme.Warn(line)
		}
		lines = append(lines, line)
		shown++
	}
	if hidden := m.s.Responded - shown; hidden > 0 && len(lines) < limit-1 {
		lines = append(lines, m.theme.Muted(fmt.Sprintf("+%d more responders in final report", hidden)))
	} else if shown == 0 && len(lines) < limit-1 {
		lines = append(lines, m.theme.Muted("Waiting for replies…"))
	}
	lines = append(lines, m.theme.Muted(footer))
	for i := range lines {
		lines[i] = sweepTruncate(lines[i], width)
	}
	return strings.Join(lines, "\n")
}

// Sweep leaves the terminal in its normal inline mode. The caller cancels and
// joins the engine before printing its full final result.
func Sweep(box *ping.SweepMailbox, cancel context.CancelFunc, in io.Reader, out io.Writer, theme Theme, width int) error {
	model := sweepModel{box: box, cancel: cancel, theme: theme, width: max(1, width), height: 24}
	_, err := tea.NewProgram(model, tea.WithInput(in), tea.WithOutput(out), tea.WithoutSignalHandler()).Run()
	if err != nil {
		cancel()
	}
	return err
}
