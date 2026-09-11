package lookup

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTraceAdapterArgumentsAndPartialTimeout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "traceroute")
	script := "#!/bin/sh\nprintf 'hop one\\n'\nprintf '%s\\n' \"$@\"\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	s := NewService()
	ip := netip.MustParseAddr("127.0.0.1")
	data, err := s.Trace(context.Background(), ip, 7, false)
	if err != nil {
		t.Fatal(err)
	}
	r := data.(TraceResult)
	if r.Engine != "traceroute" || !strings.Contains(r.Output, "-q\n7\n") || !strings.HasSuffix(r.Output, "127.0.0.1") {
		t.Fatalf("%+v", r)
	}
	script = "#!/bin/sh\nprintf 'partial hop\\n'\nexec '" + strings.ReplaceAll(sleep, "'", "'\"'\"'") + "' 30\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	data, err = s.Trace(ctx, ip, 3, false)
	if err != context.DeadlineExceeded || !strings.Contains(data.(TraceResult).Output, "partial hop") {
		t.Fatal(data, err)
	}
}

func TestTraceDependencyAndBoundedOutput(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := NewService().Trace(context.Background(), netip.MustParseAddr("127.0.0.1"), 3, false); err == nil {
		t.Fatal("missing utility not reported")
	}
	var b traceBuffer
	input := []byte(strings.Repeat("x", 100000))
	n, err := b.Write(input)
	if err != nil || n != len(input) || b.Len() != 64<<10 || !b.truncated {
		t.Fatal(n, err, b.Len(), b.truncated)
	}
}
