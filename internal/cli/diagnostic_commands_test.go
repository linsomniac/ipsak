package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/linsomniac/ipsak/internal/lookup"
)

func TestAllNewCommandsRegistered(t *testing.T) {
	for _, name := range []string{"doctor", "tlscert", "httpinfo", "dnscheck", "mtu", "sockets", "route", "interfaces", "neighbors", "connect", "listen", "send", "receive", "serve", "wake", "lookingglass", "ntptime"} {
		out, stderr, code := invoke(name, "--help")
		if code != 0 || out == "" || stderr != "" {
			t.Fatalf("%s: %d %s %s", name, code, out, stderr)
		}
	}
}

func TestDoctorCLIJSONAndValidation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	out, stderr, code := invoke("doctor", srv.URL, "--json")
	var r lookup.Report
	if code != 1 || stderr == "" || json.Unmarshal([]byte(out), &r) != nil || r.Command != "doctor" || strings.Contains(out, "\x1b") {
		t.Fatal(code, out, stderr)
	}
	foundHTTP := false
	for _, s := range r.Sections {
		if s.Key == "http" {
			foundHTTP = s.Status == "error" && strings.Contains(s.Error, "503") && s.Data != nil
		}
	}
	if !foundHTTP {
		t.Fatal(out)
	}
	for _, args := range [][]string{{"doctor", "ftp://example.com"}, {"mtu", "224.0.0.1"}, {"mtu", "0.0.0.0"}, {"mtu", "255.255.255.255"}, {"mtu", "127.0.0.1", "--min", "20"}, {"mtu", "127.0.0.1", "--max", "65536"}, {"mtu", "127.0.0.1", "--attempts", "4"}, {"mtu", "localhost", "-4", "-6"}, {"mtu", "192.0.2.0/24"}} {
		if out, _, code := invoke(args...); code != 2 || out != "" {
			t.Fatal(args, code, out)
		}
	}
}

func TestDiagnosticCancellationAndDeadlineJSON(t *testing.T) {
	for _, command := range []string{"doctor", "mtu"} {
		for _, deadline := range []bool{false, true} {
			ctx, cancel := context.WithCancel(context.Background())
			want := 130
			if deadline {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				want = 1
			} else {
				cancel()
			}
			var out, stderr bytes.Buffer
			code := Execute(ctx, []string{command, "127.0.0.1", "--json"}, strings.NewReader(""), &out, &stderr, "test")
			cancel()
			if code != want || !json.Valid(out.Bytes()) {
				t.Fatal(command, deadline, code, out.String(), stderr.String())
			}
		}
	}
}
