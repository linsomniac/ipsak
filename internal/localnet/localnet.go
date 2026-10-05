// Package localnet provides bounded adapters for local network diagnostics.
package localnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
	"unicode"
)

type CommandResult struct {
	Stdout, Stderr []byte
	Code           int
}
type Runner func(context.Context, string, ...string) (CommandResult, error)
type limitedBuffer struct {
	buffer   bytes.Buffer
	Limit    int
	Overflow bool
	Cancel   context.CancelFunc
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.Limit-b.buffer.Len() {
		b.Overflow = true
		b.Cancel()
		return 0, fmt.Errorf("command output exceeded %d bytes", b.Limit)
	}
	return b.buffer.Write(p)
}
func Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	c.WaitDelay = 200 * time.Millisecond
	out := &limitedBuffer{Limit: 256 << 10, Cancel: cancel}
	stderr := &limitedBuffer{Limit: 8192, Cancel: cancel}
	c.Stdout = out
	c.Stderr = stderr
	err := c.Run()
	result := CommandResult{Stdout: out.buffer.Bytes(), Stderr: stderr.buffer.Bytes()}
	if c.ProcessState != nil {
		result.Code = c.ProcessState.ExitCode()
	} else {
		result.Code = -1
	}
	if out.Overflow || stderr.Overflow {
		return result, fmt.Errorf("%s output exceeded safety limit", name)
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if err != nil {
		var missing *exec.Error
		if errors.As(err, &missing) {
			return result, fmt.Errorf("%s is required: %w", name, err)
		}
		return result, fmt.Errorf("%s exited %d: %s", name, result.Code, strings.TrimSpace(string(result.Stderr)))
	}
	return result, nil
}
func ValidInterfaceName(name string) error {
	if name == "" || len(name) > 64 || strings.HasPrefix(name, "-") || strings.IndexFunc(name, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		return fmt.Errorf("invalid interface name")
	}
	return nil
}
func Interfaces(names []string, multicast bool) ([]net.Interface, error) {
	if len(names) > 8 {
		return nil, fmt.Errorf("at most eight interfaces are supported")
	}
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Index < all[j].Index })
	selected := []net.Interface{}
	seen := map[string]bool{}
	for _, name := range names {
		if err := ValidInterfaceName(name); err != nil {
			return nil, err
		}
		seen[name] = false
	}
	for _, iface := range all {
		_, requested := seen[iface.Name]
		if len(names) > 0 && !requested {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			if requested {
				return nil, fmt.Errorf("interface %s is down", iface.Name)
			}
			continue
		}
		if len(names) == 0 && iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if multicast && iface.Flags&net.FlagMulticast == 0 {
			if requested {
				return nil, fmt.Errorf("interface %s does not support multicast", iface.Name)
			}
			continue
		}
		selected = append(selected, iface)
		seen[iface.Name] = true
	}
	for name, found := range seen {
		if !found {
			return nil, fmt.Errorf("interface %q is unavailable", name)
		}
	}
	if len(selected) > 8 {
		return nil, fmt.Errorf("more than eight interfaces are eligible; select --interface explicitly")
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no eligible interfaces; select --interface explicitly")
	}
	return selected, nil
}
