package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/spf13/cobra"
	"strings"
	"testing"
	"time"

	"github.com/linsomniac/ipsak/internal/lookup"
)

func invoke(args ...string) (string, string, int) {
	var out, err bytes.Buffer
	code := Execute(context.Background(), args, strings.NewReader(""), &out, &err, "test-version")
	return out.String(), err.String(), code
}

func TestCLIJSONAndPlain(t *testing.T) {
	for _, args := range [][]string{{"calc", "10.0.0.99/24", "--json"}, {"-j", "calc", "10.0.0.99/24"}} {
		out, stderr, code := invoke(args...)
		if code != 0 {
			t.Fatal(code, stderr)
		}
		var r lookup.Report
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatal(err, out)
		}
		if r.SchemaVersion != 1 || r.Command != "calc" || len(r.Sections) != 1 || strings.Contains(out, "\x1b") {
			t.Fatal(out)
		}
	}
	out, stderr, code := invoke("calc", "::/0", "--plain")
	if code != 0 || !strings.Contains(out, "340282366920938463463374607431768211456") || strings.Contains(out, "\x1b") {
		t.Fatal(out, stderr, code)
	}
}

func TestCLIHelpAndValidation(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"-V"}, {"--version"}, {"ping", "--help"}} {
		out, stderr, code := invoke(args...)
		if code != 0 || out == "" {
			t.Fatal(args, out, stderr, code)
		}
	}
	for _, args := range [][]string{{"8.8.8.8"}, {"calc", "bad"}, {"ping"}, {"info"}, {"myip", "extra"}, {"ping", "localhost", "-4", "-6"}, {"ping", "localhost", "-i", "0.001"}, {"ping", "localhost", "--duration", "-1s"}, {"info", "localhost", "--timeout", "NaN"}, {"info", "localhost", "--timeout", "0"}, {"trace", "localhost", "-q", "11"}} {
		_, stderr, code := invoke(args...)
		if code == 0 || stderr == "" {
			t.Fatal("accepted", args)
		}
	}
}

func TestPingTimeoutDefaultAndPlacement(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want time.Duration
	}{{[]string{"ping", "localhost"}, time.Second}, {[]string{"ping", "localhost", "--timeout", ".25"}, 250 * time.Millisecond}, {[]string{"--timeout", "250ms", "ping", "localhost"}, 250 * time.Millisecond}} {
		root := New("test")
		cmd, _, err := root.Find([]string{"ping"})
		if err != nil {
			t.Fatal(err)
		}
		cmd.RunE = func(cmd *cobra.Command, _ []string) error {
			got, err := cmd.Flags().GetDuration("timeout")
			if err != nil || got != tt.want {
				t.Fatalf("%v: got %s, %v", tt.args, got, err)
			}
			return nil
		}
		root.SetArgs(tt.args)
		if err := root.Execute(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCanceledPingDoesNotStartNetworkWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, target := range []string{"example.invalid", "127.0.0.1"} {
		var out, stderr bytes.Buffer
		code := Execute(ctx, []string{"ping", target}, strings.NewReader(""), &out, &stderr, "test")
		if code != 130 || !strings.Contains(stderr.String(), "ping interrupted") || out.Len() != 0 {
			t.Fatal(code, out.String(), stderr.String())
		}
	}
}
