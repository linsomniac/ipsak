//go:build unix

package cli

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestSendCLIFIFOFileDoesNotBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := invoke("send", path, "--connect", "127.0.0.1:1")
	if code != 1 || !strings.Contains(stderr, "regular file") {
		t.Fatal(code, stderr)
	}
}
