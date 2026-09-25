//go:build unix

package stream

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Duplicate the descriptor, not the caller's os.File, to use Go's runtime poller
// even when an inherited stdout pipe started as a blocking descriptor. Dup shares
// status flags, so restore the original mode after all writes are joined.
func pollableOutput(original *os.File) (*os.File, func(), error) {
	raw, err := original.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	duplicate := -1
	var originalFlags int
	var syscallErr error
	err = raw.Control(func(fd uintptr) {
		originalFlags, syscallErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
		if syscallErr != nil {
			return
		}
		duplicate, syscallErr = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0)
	})
	if err != nil {
		return nil, nil, err
	}
	if syscallErr != nil {
		return nil, nil, fmt.Errorf("duplicate output: %w", syscallErr)
	}
	if err := unix.SetNonblock(duplicate, true); err != nil {
		_ = unix.Close(duplicate)
		return nil, nil, fmt.Errorf("prepare cancellable output: %w", err)
	}
	file := os.NewFile(uintptr(duplicate), original.Name())
	return file, func() {
		_ = file.Close()
		_ = raw.Control(func(fd uintptr) { _ = unix.SetNonblock(int(fd), originalFlags&unix.O_NONBLOCK != 0) })
	}, nil
}
