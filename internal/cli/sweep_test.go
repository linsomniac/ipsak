package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/linsomniac/ipsak/internal/ping"
)

type cliSweepTransport struct {
	replies chan ping.Reply
	closed  chan struct{}
	once    sync.Once
	send    func(uint64, netip.Addr) error
}

func (f *cliSweepTransport) SendTo(id uint64, ip netip.Addr) error { return f.send(id, ip) }
func (f *cliSweepTransport) Receive() (ping.Reply, error) {
	select {
	case r := <-f.replies:
		return r, nil
	case <-f.closed:
		return ping.Reply{}, net.ErrClosed
	}
}
func (f *cliSweepTransport) Close() error { f.once.Do(func() { close(f.closed) }); return nil }
func newCLISweepTransport() *cliSweepTransport {
	return &cliSweepTransport{replies: make(chan ping.Reply, 100), closed: make(chan struct{}), send: func(uint64, netip.Addr) error { return nil }}
}

func invokeSweep(t *testing.T, ctx context.Context, f *cliSweepTransport, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := newCommand("test", func(netip.Addr) (ping.SweepTransport, error) { return f, nil })
	cmd.SetArgs(args)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.ExecuteContext(ctx)
	return out.String(), err
}

func decodeSweep(t *testing.T, out string) ping.SweepSnapshot {
	t.Helper()
	var envelope struct {
		Version int                `json:"schema_version"`
		Command string             `json:"command"`
		Sweep   ping.SweepSnapshot `json:"sweep"`
		Ping    json.RawMessage    `json:"ping"`
	}
	if err := json.Unmarshal([]byte(out), &envelope); err != nil {
		t.Fatal(err, out)
	}
	if envelope.Version != 1 || envelope.Command != "ping" || envelope.Ping != nil || strings.Contains(out, "\x1b") {
		t.Fatal(out)
	}
	return envelope.Sweep
}

func TestCIDRDefaultsJSONAndExplicitCount(t *testing.T) {
	for _, tt := range []struct {
		extra   []string
		want    uint64
		partial bool
	}{{nil, 3, false}, {[]string{"-c", "1"}, 1, false}, {[]string{"-c", "0"}, 0, true}} {
		f := newCLISweepTransport()
		ctx, cancel := context.WithCancel(context.Background())
		f.send = func(id uint64, ip netip.Addr) error {
			f.replies <- ping.Reply{ID: id, Address: ip, At: time.Now()}
			if tt.partial && id == 6 {
				cancel()
			}
			return nil
		}
		args := append([]string{"ping", "192.0.2.5/31", "--json", "-i", "10ms", "--rate", "1000"}, tt.extra...)
		out, err := invokeSweep(t, ctx, f, args...)
		cancel()
		var exit *ExitError
		if !tt.partial && err != nil || tt.partial && (!errors.As(err, &exit) || exit.Code != 130) {
			t.Fatal(err, out)
		}
		s := decodeSweep(t, out)
		if s.CIDR != "192.0.2.4/31" || s.Count != tt.want || s.Total != 2 || len(s.Hosts) != 2 || s.Responded != 2 || s.Partial != tt.partial || s.Rate != 1000 || s.TimeoutMS != 1000 || s.IntervalMS != 10 {
			t.Fatalf("%+v", s)
		}
		if !tt.partial && s.Attempts != 2*tt.want {
			t.Fatal("wrong per-host count", s)
		}
		if tt.partial && (s.StopReason != "interrupted" || s.Sent != 6) {
			t.Fatal("explicit zero did not watch", s)
		}
	}
}

func TestCIDRDurationReturnsPartialJSON(t *testing.T) {
	f := newCLISweepTransport()
	out, err := invokeSweep(t, context.Background(), f, "ping", "192.0.2.0/30", "--json", "-c", "0", "--duration", "1ns")
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 1 {
		t.Fatal(err, out)
	}
	s := decodeSweep(t, out)
	if !s.Partial || s.StopReason != "duration" || s.Lost != 0 || s.Pending != s.Sent {
		t.Fatalf("%+v", s)
	}
}

func TestCIDRValidationBeforeOpening(t *testing.T) {
	for _, args := range [][]string{
		{"ping", "2001:db8::/64"}, {"ping", "192.0.2.0/24", "--max-hosts", "16"}, {"ping", "192.0.2.0/24", "--max-hosts", "65537"},
		{"ping", "192.0.2.0/24", "--rate", "0"}, {"ping", "192.0.2.0/24", "--rate", "1001"}, {"ping", "192.0.2.0/24", "-6"}, {"ping", "2001:db8::/127", "-4"},
		{"ping", "192.0.2.0/24", "-c", "18446744073709551615"}, {"ping", "224.0.0.0/24"}, {"ping", "::ffff:192.0.2.0/120"},
		{"ping", "127.0.0.1", "--rate", "100"}, {"ping", "127.0.0.1", "--all=false"}, {"ping", "127.0.0.1", "--max-hosts", "4096"},
	} {
		cmd := newCommand("test", func(netip.Addr) (ping.SweepTransport, error) { t.Fatalf("opened socket for %v", args); return nil, nil })
		cmd.SetArgs(args)
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		if err := cmd.Execute(); err == nil {
			t.Fatal("accepted invalid arguments", args)
		}
	}
}

func TestCIDRExitCodesPartialAndSilentJSON(t *testing.T) {
	for _, tt := range []struct {
		name                     string
		respond, sendError, stop bool
		want                     int
	}{
		{"sparse", true, false, false, 0}, {"silent", false, false, false, 1}, {"errors with responder", true, true, false, 0}, {"only errors", false, true, false, 2}, {"interrupted", false, false, true, 130},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newCLISweepTransport()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.send = func(id uint64, ip netip.Addr) error {
				if tt.stop {
					cancel()
				}
				if tt.respond && ip.String() == "192.0.2.0" {
					f.replies <- ping.Reply{ID: id, Address: ip, At: time.Now()}
					return nil
				}
				if tt.sendError {
					return errors.New("no route")
				}
				return nil
			}
			out, err := invokeSweep(t, ctx, f, "ping", "192.0.2.0/30", "--json", "-c", "1", "--timeout", "10ms", "--rate", "1000")
			code := 0
			var exit *ExitError
			if errors.As(err, &exit) {
				code = exit.Code
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tt.want {
				t.Fatal(code, err, out)
			}
			s := decodeSweep(t, out)
			if len(s.Hosts) != 4 {
				t.Fatal("JSON omitted silent hosts")
			}
			if !tt.respond && s.RTT != nil {
				t.Fatal("silent sweep returned latency")
			}
			if tt.stop && (!s.Partial || s.Pending != 1 || s.Unprobed != 3 || s.Lost != 0) {
				t.Fatal("lost partial work", s)
			}
		})
	}
}

func TestCIDRPlainAllAndWriterFailure(t *testing.T) {
	for _, all := range []bool{false, true} {
		f := newCLISweepTransport()
		f.send = func(id uint64, ip netip.Addr) error {
			if ip.String() == "192.0.2.0" {
				f.replies <- ping.Reply{ID: id, Address: ip, At: time.Now()}
			}
			return nil
		}
		args := []string{"ping", "192.0.2.0/30", "--plain", "-c", "1", "--timeout", "10ms", "--rate", "1000"}
		if all {
			args = append(args, "--all")
		}
		out, err := invokeSweep(t, context.Background(), f, args...)
		if err != nil || strings.Contains(out, "\x1b") || !strings.Contains(out, "192.0.2.0") || strings.Contains(out, "192.0.2.1") != all {
			t.Fatal(out, err)
		}
	}
	cmd := newCommand("test", func(netip.Addr) (ping.SweepTransport, error) {
		t.Fatal("opened socket after failed banner write")
		return nil, nil
	})
	cmd.SetArgs([]string{"ping", "192.0.2.0/30"})
	cmd.SetOut(failingSweepWriter{})
	cmd.SetIn(strings.NewReader(""))
	if err := cmd.Execute(); err == nil {
		t.Fatal("ignored failed output")
	}
}

type failingSweepWriter struct{}

func (failingSweepWriter) Write([]byte) (int, error) { return 0, errors.New("output failed") }
