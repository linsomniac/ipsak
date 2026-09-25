//go:build unix

package stream

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestInheritedBlockingPipeOutputCancellationRestoresFlags(t *testing.T) {
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		t.Fatal(err)
	}
	reader := os.NewFile(uintptr(fds[0]), "inherited-reader")
	defer reader.Close()
	writer := os.NewFile(uintptr(fds[1]), "inherited-stdout")
	defer writer.Close()
	if err := unix.SetNonblock(fds[1], true); err != nil {
		t.Fatal(err)
	}
	// Fill the pipe before starting the cancellable write so it must block.
	for {
		_, err := unix.Write(fds[1], make([]byte, 4096))
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.SetNonblock(fds[1], false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w, cleanup, err := prepareOutput(ctx, writer)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := w.Write([]byte("x")); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("full-pipe write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked output ignored cancellation")
	}
	cleanup()
	flags, err := unix.FcntlInt(uintptr(fds[1]), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK != 0 {
		t.Fatal("original flags not restored", flags, err)
	}
	if _, err := reader.Read(make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("still-open")); err != nil {
		t.Fatal("original output was closed", err)
	}
}

func TestNullAndFullOutputDevices(t *testing.T) {
	for _, name := range []string{os.DevNull, "/dev/full"} {
		f, err := os.OpenFile(name, os.O_WRONLY, 0)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		w, cleanup, err := prepareOutput(context.Background(), f)
		if err != nil {
			f.Close()
			t.Fatal(name, err)
		}
		_, err = w.Write([]byte("payload"))
		cleanup()
		f.Close()
		if (name == os.DevNull) != (err == nil) {
			t.Fatal(name, err)
		}
	}
}

func TestNullInputThroughInheritedName(t *testing.T) {
	alias := filepath.Join(t.TempDir(), "stdin")
	if err := os.Symlink(os.DevNull, alias); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(alias)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	input, err := prepareInput(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	defer input.cleanup()
	if n, err := input.reader.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatal(n, err)
	}
}
