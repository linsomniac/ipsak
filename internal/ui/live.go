package ui

import (
	"context"
	"io"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/linsomniac/ipsak/internal/lookup"
	"github.com/linsomniac/ipsak/internal/ping"
)

type tick time.Time

func refresh() tea.Cmd {
	return tea.Tick(50*time.Millisecond, func(t time.Time) tea.Msg { return tick(t) })
}

type sectionMsg struct {
	section lookup.Section
	ok      bool
}

func receive(ch <-chan lookup.Section) tea.Cmd {
	return func() tea.Msg { s, ok := <-ch; return sectionMsg{s, ok} }
}

type infoModel struct {
	report                       lookup.Report
	results                      <-chan lookup.Section
	cancel                       context.CancelFunc
	theme                        Theme
	width, height, offset, frame int
	done, stopping               bool
}

func (m infoModel) Init() tea.Cmd { return tea.Batch(receive(m.results), refresh()) }
func (m infoModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.stopping = true
			m.cancel()
		case "j", "down":
			m.offset++
		case "k", "up":
			if m.offset > 0 {
				m.offset--
			}
		case "home", "g":
			m.offset = 0
		}
	case sectionMsg:
		if !msg.ok {
			m.done = true
			return m, tea.Quit
		}
		m.report.Apply(msg.section)
		return m, receive(m.results)
	case tick:
		m.frame++
		return m, refresh()
	}
	return m, nil
}
func (m infoModel) View() string {
	if m.done {
		return ""
	}
	lines := strings.Split(strings.TrimSuffix(m.theme.Report(m.report, m.width, m.frame), "\n"), "\n")
	limit := m.height - 3
	if limit < 1 {
		limit = 1
	}
	offset := m.offset
	if offset > len(lines)-limit {
		offset = len(lines) - limit
	}
	if offset < 0 {
		offset = 0
	}
	end := offset + limit
	if end > len(lines) {
		end = len(lines)
	}
	footer := "q stop · ↑/↓ scroll"
	if m.stopping {
		footer = "Stopping lookups…"
	}
	return strings.Join(lines[offset:end], "\n") + "\n\n" + m.theme.Muted(ansi.Truncate(footer, m.width, "…"))
}

func Info(r lookup.Report, ch <-chan lookup.Section, cancel context.CancelFunc, in io.Reader, out io.Writer, theme Theme, width int) (lookup.Report, error) {
	m := infoModel{report: r, results: ch, cancel: cancel, theme: theme, width: width, height: 24}
	final, err := tea.NewProgram(m, tea.WithInput(in), tea.WithOutput(out), tea.WithoutSignalHandler()).Run()
	if err != nil {
		cancel()
		for section := range ch {
			r.Apply(section)
		}
		return r, err
	}
	return final.(infoModel).report, nil
}

type pingModel struct {
	box      *ping.Mailbox
	cancel   context.CancelFunc
	theme    Theme
	width    int
	s        ping.Snapshot
	stopping bool
}

func (m pingModel) Init() tea.Cmd { return refresh() }
func (m pingModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" || msg.String() == "esc" {
			m.stopping = true
			m.cancel()
		}
	case tick:
		var events []ping.Transition
		m.s, events = m.box.Drain()
		var lines []string
		for _, e := range events {
			if e.Kind == "end" {
				lines = append(lines, m.theme.Warn(e.Loss.Started.Local().Format("15:04:05")+"  "+ping.LossText(e.Loss)))
			}
		}
		var cmds []tea.Cmd
		if len(lines) > 0 {
			cmds = append(cmds, tea.Println(strings.Join(lines, "\n")))
		}
		if m.s.Done {
			cmds = append(cmds, tea.Quit)
		} else {
			cmds = append(cmds, refresh())
		}
		return m, tea.Sequence(cmds...)
	}
	return m, nil
}
func (m pingModel) View() string {
	if m.s.Done {
		return ""
	}
	var line string
	if m.s.ActiveLoss != nil {
		line = m.theme.Warn(ansi.Truncate(m.s.ActiveLoss.Started.Local().Format("15:04:05")+"  "+ping.LossText(*m.s.ActiveLoss), m.width, "…")) + "\n"
	}
	if m.s.Address == "" {
		return m.theme.Muted("Starting probes…")
	}
	line += m.theme.PingStatus(m.s, m.width)
	if m.stopping {
		line = m.theme.Muted("Stopping… ") + line
	}
	return line
}
func Ping(box *ping.Mailbox, cancel context.CancelFunc, in io.Reader, out io.Writer, theme Theme, width int) error {
	_, err := tea.NewProgram(pingModel{box: box, cancel: cancel, theme: theme, width: width}, tea.WithInput(in), tea.WithOutput(out), tea.WithoutSignalHandler()).Run()
	if err != nil {
		cancel()
	}
	return err
}
