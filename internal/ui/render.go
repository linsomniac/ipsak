// Package ui provides inline terminal dashboards and escape-free text output.
package ui

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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

type Theme struct{ Color bool }

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

func fields(value any) []string {
	b, err := json.Marshal(value)
	if err != nil {
		return []string{Clean(fmt.Sprint(value))}
	}
	var v any
	if json.Unmarshal(b, &v) != nil {
		return nil
	}
	var lines []string
	var walk func(string, any)
	walk = func(key string, v any) {
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
				walk(label, x[k])
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
				walk(label, e)
			}
		case nil:
		case string:
			if x == "" {
				return
			}
			for _, line := range strings.Split(x, "\n") {
				if key != "" {
					lines = append(lines, fmt.Sprintf("%-14s %s", Clean(key), Clean(line)))
				} else {
					lines = append(lines, Clean(line))
				}
			}
		default:
			lines = append(lines, fmt.Sprintf("%-14s %v", Clean(key), x))
		}
	}
	walk("", v)
	return lines
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
	for _, line := range fields(s.Data) {
		lines = append(lines, line)
	}
	if s.Error != "" {
		lines = append(lines, t.Warn(Clean(s.Error)))
	}
	if s.Status == "pending" {
		lines = append(lines, t.Muted("Looking up…"))
	}
	if s.Status == "ok" && len(fields(s.Data)) == 0 {
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
	title := "ipsak  /  " + strings.ToUpper(r.Command)
	if r.Target != "" {
		title += "  ·  " + Clean(r.Target)
	}
	var blocks []string
	if width >= 100 {
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
