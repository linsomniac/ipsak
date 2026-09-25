// Package hostnet provides bounded, read-only host network inspection and
// Wake-on-LAN transmission. Missing operating-system facilities are explicit.
package hostnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const maxOutput = 4 << 20
const maxRows = 20000

var errOutputLimit = errors.New("system command output exceeded the safety limit")

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
	cancel   context.CancelFunc
}

func (b *boundedBuffer) Len() int       { return b.buffer.Len() }
func (b *boundedBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *boundedBuffer) String() string { return b.buffer.String() }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		b.overflow = true
		b.cancel()
		return 0, errOutputLimit
	}
	return b.buffer.Write(p)
}

func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	return commandOutput(ctx, false, name, args...)
}

// lsof uses status 1 for an empty selection. Only that exact condition, with
// no diagnostic output, is permitted when allowEmpty is requested.
func commandOutput(ctx context.Context, allowEmpty bool, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	c.WaitDelay = 200 * time.Millisecond
	out := &boundedBuffer{limit: maxOutput, cancel: cancel}
	stderr := &boundedBuffer{limit: 8192, cancel: cancel}
	c.Stdout, c.Stderr = out, stderr
	err := c.Run()
	if out.overflow || stderr.overflow {
		return nil, errOutputLimit
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		var status *exec.ExitError
		if allowEmpty && errors.As(err, &status) && status.ExitCode() == 1 && out.Len() == 0 && stderr.Len() == 0 {
			return []byte{}, nil
		}
		var missing *exec.Error
		if errors.As(err, &missing) && errors.Is(missing.Err, exec.ErrNotFound) {
			return nil, fmt.Errorf("%s is required for this operation; install the operating system's networking tools: %w", name, err)
		}
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return out.Bytes(), nil
}
