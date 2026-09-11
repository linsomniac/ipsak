package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/linsomniac/ipsak/internal/ping"
)

func TestLiveLossRowUpdatesAndClearsOnRecovery(t *testing.T) {
	box := &ping.Mailbox{}
	m := pingModel{box: box, cancel: func() {}, width: 100}
	loss := ping.Loss{First: 7, Last: 7, Count: 1, Started: time.Now()}
	s := ping.Snapshot{Address: "8.8.8.8", Sent: 7, Received: 6, Lost: 1, ActiveLoss: &loss}
	_ = box.Publish(s, []ping.Transition{{Kind: "start", Loss: loss}})
	model, _ := m.Update(tick(time.Now()))
	m = model.(pingModel)
	if view := m.View(); !strings.Contains(view, "Lost 1 packets") || strings.Count(view, "\n") != 1 {
		t.Fatal(view)
	}
	loss.Last = 15
	loss.Count = 9
	s.Sent = 15
	s.Lost = 9
	_ = box.Publish(s, nil)
	model, _ = m.Update(tick(time.Now()))
	m = model.(pingModel)
	if view := m.View(); !strings.Contains(view, "Lost 9 packets, ids 7–15") || strings.Count(view, "Lost ") != 1 || strings.Count(view, "\n") != 1 {
		t.Fatal(view)
	}
	ended := time.Now()
	loss.Ended = &ended
	loss.Recovered = true
	s.ActiveLoss = nil
	s.Sent++
	s.Received++
	_ = box.Publish(s, []ping.Transition{{Kind: "end", Loss: loss}})
	model, cmd := m.Update(tick(time.Now()))
	m = model.(pingModel)
	if view := m.View(); strings.Contains(view, "Lost ") || strings.Contains(view, "\n") || cmd == nil {
		t.Fatal(view, "missing command to preserve completed loss in scrollback")
	}
}
