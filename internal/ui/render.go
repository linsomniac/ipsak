// Package ui provides inline terminal dashboards and escape-free text output.
package ui

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/linsomniac/ipsak/internal/ping"
)

// Clean removes terminal controls, including ESC, C1 and bidi/format controls.
// Newlines are only introduced by the renderer, never by external field values.
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
}

type Theme struct{ Color, Verbose bool }

func (t Theme) style(text, color string, bold bool) string {
	if !t.Color {
		return text
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Bold(bold).Render(text)
}
func (t Theme) Heading(s string) string { return t.style(s, "#67E8F9", true) }
func (t Theme) Muted(s string) string   { return t.style(s, "#94A3B8", false) }
func (t Theme) Good(s string) string    { return t.style(s, "#6EE7B7", false) }
func (t Theme) Warn(s string) string    { return t.style(s, "#FBBF24", false) }

func fields(value any, width int) []string {
	now := time.Now()
	b, err := json.Marshal(value)
	if err != nil {
		return []string{Clean(fmt.Sprint(value))}
	}
	var v any
	if json.Unmarshal(b, &v) != nil {
		return nil
	}
	var lines []string
	var walk func(string, string, any)
	walk = func(key, leaf string, v any) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				label := strings.ReplaceAll(k, "_", " ")
				if key != "" {
					label = key + " · " + label
				}
				walk(label, k, x[k])
			}
		case []any:
			if len(x) == 0 {
				return
			}
			for i, e := range x {
				label := key
				if _, ok := e.(map[string]any); ok {
					label = fmt.Sprintf("%s %d", key, i+1)
				}
				walk(label, leaf, e)
			}
		case nil:
		case string:
			if x == "" {
				return
			}
			display := x
			if leaf == "not_after" || leaf == "expires" {
				display = expirationDate(x, now)
			}
			for _, line := range strings.Split(display, "\n") {
				address := addressValue(line)
				if key != "" {
					formatted := fmt.Sprintf("%-14s %s", Clean(key), Clean(line))
					if (display != x || address) && width > 0 && ansi.StringWidth(formatted) > width {
						// Keep addresses and expiry countdowns visible when their
						// field labels would otherwise push them off the screen.
						lines = append(lines, Clean(key))
						value := Clean(line)
						value = ansi.Hardwrap(value, width, true)
						lines = append(lines, strings.Split(value, "\n")...)
					} else {
						lines = append(lines, formatted)
					}
				} else {
					value := Clean(line)
					if address && width > 0 {
						value = ansi.Hardwrap(value, width, true)
					}
					lines = append(lines, strings.Split(value, "\n")...)
				}
			}
		default:
			lines = append(lines, fmt.Sprintf("%-14s %v", Clean(key), x))
		}
	}
	walk("", "", v)
	return lines
}

func addressValue(value string) bool {
	if _, err := netip.ParseAddr(value); err == nil {
		return true
	}
	if _, err := netip.ParsePrefix(value); err == nil {
		return true
	}
	if first, last, ok := strings.Cut(value, " – "); ok {
		_, firstErr := netip.ParseAddr(first)
		_, lastErr := netip.ParseAddr(last)
		return firstErr == nil && lastErr == nil
	}
	return false
}

func expirationDate(value string, now time.Time) string {
	expires, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return value
	}
	// Unix seconds avoid time.Duration's roughly 290-year range limit. Floor
	// complete 24-hour days so a just-expired certificate has a negative count.
	seconds := expires.Unix() - now.Unix()
	if expires.Nanosecond() < now.Nanosecond() {
		seconds--
	}
	const day = int64(24 * 60 * 60)
	days := seconds / day
	if seconds < 0 && seconds%day != 0 {
		days--
	}
	return fmt.Sprintf("%s (%d days)", value, days)
}

func (t Theme) Section(s lookup.Section, width int, frame int) string {
	mark := "✓"
	switch s.Status {
	case "pending":
		frames := []string{"◐", "◓", "◑", "◒"}
		mark = frames[frame%len(frames)]
	case "error":
		mark = "!"
	case "skipped":
		mark = "–"
	}
	heading := mark + " " + Clean(s.Title)
	if s.Status == "error" {
		heading = t.Warn(heading)
	} else {
		heading = t.Heading(heading)
	}
	lines := []string{heading}
	if s.Source != "" {
		lines = append(lines, t.Muted(Clean(s.Source)))
	}
	dataLines, compact := t.tlsLines(s.Data, width)
	if !compact && width > 0 {
		if summary, ok := s.Data.(interface{ CompactLines() []string }); ok {
			compact = true
			for _, line := range summary.CompactLines() {
				dataLines = append(dataLines, strings.Split(ansi.Hardwrap(Clean(line), width, true), "\n")...)
			}
		}
	}
	if !compact && width > 0 {
		dataLines, compact = diagnosticLines(s.Data)
	}
	if !compact {
		dataLines = fields(s.Data, width)
	}
	for _, line := range dataLines {
		lines = append(lines, line)
	}
	if s.Error != "" {
		lines = append(lines, t.Warn(Clean(s.Error)))
	}
	if s.Status == "pending" {
		lines = append(lines, t.Muted("Looking up…"))
	}
	if s.Status == "ok" && len(dataLines) == 0 {
		lines = append(lines, t.Muted("No records returned"))
	}
	if width > 0 {
		for i, l := range lines {
			lines[i] = ansi.Truncate(l, width, "…")
		}
	}
	return strings.Join(lines, "\n")
}

func (t Theme) Report(r lookup.Report, width, frame int) string {
	if r.Command == "myip" {
		families := 0
		for _, s := range r.Sections {
			if s.Key == "public_ipv4" || s.Key == "public_ipv6" {
				families++
			}
		}
		if families == 2 {
			// Family cards already show the discovered addresses. Keep the
			// legacy public section in JSON, and show aggregate failures here.
			sections := make([]lookup.Section, 0, len(r.Sections))
			for _, s := range r.Sections {
				if s.Key != "public" || s.Status == "error" {
					sections = append(sections, s)
				}
			}
			r.Sections = sections
		}
	}
	title := "ipsak  /  " + strings.ToUpper(r.Command)
	if r.Target != "" {
		title += "  ·  " + Clean(r.Target)
	}
	var blocks []string
	if width >= 100 && len(r.Sections) > 1 {
		w := (width - 5) / 2
		for i := 0; i < len(r.Sections); i += 2 {
			left := lipgloss.NewStyle().Width(w).Render(t.Section(r.Sections[i], w, frame))
			right := ""
			if i+1 < len(r.Sections) {
				right = t.Section(r.Sections[i+1], w, frame)
			}
			blocks = append(blocks, lipgloss.JoinHorizontal(lipgloss.Top, left, "     ", right))
		}
	} else {
		for _, s := range r.Sections {
			blocks = append(blocks, t.Section(s, width, frame))
		}
	}
	if width > 0 {
		title = ansi.Truncate(title, width, "…")
	}
	return t.Heading(title) + "\n\n" + strings.Join(blocks, "\n\n") + "\n"
}

func Sparkline(history []float64) string {
	const bars = "▁▂▃▄▅▆▇█"
	runes := []rune(bars)
	max := 1.0
	for _, v := range history {
		if v > max {
			max = v
		}
	}
	var out strings.Builder
	for _, v := range history {
		if v < 0 {
			out.WriteRune('×')
		} else {
			level := int(v / max * 7)
			if level > 7 {
				level = 7
			}
			out.WriteRune(runes[level])
		}
	}
	return out.String()
}

func (t Theme) PingStatus(s ping.Snapshot, width int) string {
	state := t.Good("●")
	if s.ActiveLoss != nil {
		state = t.Warn("●")
	}
	line := fmt.Sprintf("%s %s  ↑%d ↓%d  loss %d (%.1f%%)  RTT %.2f ms  avg %.2f ms", state, Clean(s.Address), s.Sent, s.Received, s.Lost, s.LossPercent, s.LastMS, s.AvgMS)
	if width < 80 {
		line = fmt.Sprintf("%s ↑%d ↓%d  loss %d  %.2f ms", state, s.Sent, s.Received, s.Lost, s.LastMS)
	}
	if s.Pending > 0 {
		line += fmt.Sprintf("  pending %d", s.Pending)
	}
	if width >= 110 {
		line += "  " + t.Good(Sparkline(s.History))
	}
	return ansi.Truncate(line, width, "…")
}

func (t Theme) PingSummary(s ping.Snapshot) string {
	state := "Finished"
	if s.Interrupted {
		state = "Stopped"
	}
	if s.Error != "" {
		state = "Failed"
	}
	return fmt.Sprintf("%s · %s (%s) · %.1fs\n%d sent · %d received · %d lost (%.1f%%) · %d pending · %d late\nRTT min/avg/max = %.3f/%.3f/%.3f ms · %d loss events\n", t.Heading(state), Clean(s.Target), Clean(s.Address), s.ElapsedSeconds, s.Sent, s.Received, s.Lost, s.LossPercent, s.Pending, s.Late, s.MinMS, s.AvgMS, s.MaxMS, s.LossEvents)
}
