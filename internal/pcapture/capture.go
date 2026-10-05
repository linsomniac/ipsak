package pcapture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/linsomniac/ipsak/internal/localnet"
	"github.com/linsomniac/ipsak/internal/stream"
)

type Options struct {
	Interface, Read, Write    string
	Force                     bool
	Count, ScanLimit, Snaplen int
	Duration                  time.Duration
	Filter                    Filter
}

func (o Options) Validate() error {
	if o.Count < 1 || o.Count > 10000 {
		return fmt.Errorf("count must be 1–10000")
	}
	if o.ScanLimit < o.Count || o.ScanLimit > 1000000 {
		return fmt.Errorf("scan-limit must be at least count and at most 1000000")
	}
	if o.Snaplen < 64 || o.Snaplen > 65535 {
		return fmt.Errorf("snaplen must be 64–65535")
	}
	if o.Duration <= 0 || o.Duration > time.Minute {
		return fmt.Errorf("duration must be greater than zero and at most 1m")
	}
	if o.Read != "" && o.Interface != "" {
		return fmt.Errorf("choose --read FILE or --interface, not both")
	}
	if o.Read == "-" || o.Write == "-" {
		return fmt.Errorf("pcap input/output requires filenames; stdout is reserved for diagnostics")
	}
	if o.Force && o.Write == "" {
		return fmt.Errorf("--force requires --write")
	}
	if o.Interface != "" {
		if err := localnet.ValidInterfaceName(o.Interface); err != nil {
			return err
		}
	}
	return o.Filter.Validate()
}

type Result struct {
	Interface string   `json:"interface,omitempty"`
	Input     string   `json:"input,omitempty"`
	Output    string   `json:"output,omitempty"`
	LinkType  uint32   `json:"link_type"`
	Scanned   int      `json:"scanned"`
	Matched   int      `json:"matched"`
	Bytes     uint64   `json:"captured_bytes"`
	Packets   []Packet `json:"packets"`
	Stop      string   `json:"stop_reason"`
	Notes     []string `json:"notes"`
}

func (r Result) CompactLines() []string {
	lines := []string{fmt.Sprintf("%d packets matched · %d scanned · %d bytes", r.Matched, r.Scanned, r.Bytes)}
	start := max(0, len(r.Packets)-12)
	for _, p := range r.Packets[start:] {
		src, dst := p.Source, p.Destination
		if p.SourcePort > 0 {
			src = net.JoinHostPort(src, fmt.Sprint(p.SourcePort))
		}
		if p.DestinationPort > 0 {
			dst = net.JoinHostPort(dst, fmt.Sprint(p.DestinationPort))
		}
		detail := p.Detail
		if p.Error != "" {
			detail = p.Error
		}
		lines = append(lines, fmt.Sprintf("%s %-5s %s → %s  %d B %s", p.Time.Format("15:04:05.000"), p.Protocol, src, dst, p.Original, detail))
	}
	return lines
}

type stderrBuffer struct {
	buffer   bytes.Buffer
	overflow bool
	cancel   context.CancelFunc
}

func (b *stderrBuffer) Write(p []byte) (int, error) {
	if len(p) > 8192-b.buffer.Len() {
		b.overflow = true
		b.cancel()
		return 0, fmt.Errorf("tcpdump diagnostic output exceeded 8192 bytes")
	}
	return b.buffer.Write(p)
}

func Run(parent context.Context, o Options, emit func(Result)) (result Result, err error) {
	return run(parent, o, emit, exec.CommandContext, net.InterfaceByName)
}
func run(parent context.Context, o Options, emit func(Result), command func(context.Context, string, ...string) *exec.Cmd, lookupInterface func(string) (*net.Interface, error)) (result Result, err error) {
	result = Result{Interface: o.Interface, Input: o.Read, Packets: []Packet{}, Notes: []string{}}
	if err = o.Validate(); err != nil {
		return result, err
	}
	if err = parent.Err(); err != nil {
		return result, err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var input io.ReadCloser
	var process *exec.Cmd
	var diagnostic *stderrBuffer
	var capture *stream.Output
	var timer *time.Timer
	planned := make(chan struct{})
	if o.Read != "" {
		file, e := os.OpenFile(o.Read, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if e != nil {
			return result, e
		}
		st, e := file.Stat()
		if e != nil || !st.Mode().IsRegular() {
			file.Close()
			return result, fmt.Errorf("pcap input must be a regular file")
		}
		input = file
	} else {
		if o.Interface == "" {
			ifaces, e := localnet.Interfaces(nil, false)
			if e != nil {
				return result, e
			}
			o.Interface = ifaces[0].Name
		}
		if _, e := lookupInterface(o.Interface); e != nil {
			return result, e
		}
		result.Interface = o.Interface
		process = command(ctx, "tcpdump", "-n", "-p", "-U", "-i", o.Interface, "-s", fmt.Sprint(o.Snaplen), "-w", "-")
		process.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
		process.WaitDelay = 200 * time.Millisecond
		diagnostic = &stderrBuffer{cancel: cancel}
		process.Stderr = diagnostic
		input, err = process.StdoutPipe()
		if err != nil {
			return result, err
		}
		if err = process.Start(); err != nil {
			input.Close()
			return result, fmt.Errorf("live capture requires tcpdump and capture permissions: %w", err)
		}
		timer = time.AfterFunc(o.Duration, func() { close(planned); cancel() })
		defer timer.Stop()
	}
	defer input.Close()
	stop := context.AfterFunc(ctx, func() { _ = input.Close() })
	defer stop()
	waited := false
	finishProcess := func() error {
		if process == nil || waited {
			return nil
		}
		waited = true
		cancel()
		_ = input.Close()
		waitErr := process.Wait()
		note := strings.TrimSpace(diagnostic.buffer.String())
		if note != "" {
			result.Notes = append(result.Notes, note)
		}
		if diagnostic.overflow {
			return fmt.Errorf("tcpdump diagnostic output exceeded limit")
		}
		expected := result.Stop == "count" || result.Stop == "scan_limit" || result.Stop == "duration" || result.Stop == "interrupted"
		if waitErr != nil && !expected {
			return fmt.Errorf("tcpdump failed (capture privileges may be required): %v: %s", waitErr, note)
		}
		return nil
	}
	defer func() {
		if finishErr := finishProcess(); finishErr != nil {
			if err == nil {
				err = finishErr
			} else {
				err = fmt.Errorf("%v: %w", err, finishErr)
			}
		}
		if parent.Err() != nil {
			err = parent.Err()
		}
	}()
	pcap, e := NewReader(input)
	if e != nil {
		return result, e
	}
	result.LinkType = pcap.LinkType
	if o.Write != "" {
		capture, e = stream.NewOutput(o.Write, o.Force)
		if e != nil {
			return result, e
		}
		defer capture.Abort()
		if _, e = capture.File.Write(pcap.Header[:]); e != nil {
			return result, e
		}
	}
	last := time.Time{}
	for result.Scanned < o.ScanLimit && result.Matched < o.Count {
		if ctx.Err() != nil {
			break
		}
		record, e := pcap.Next()
		if e != nil {
			if errors.Is(e, io.EOF) {
				result.Stop = "eof"
				break
			}
			if ctx.Err() != nil {
				result.Notes = append(result.Notes, "Stopped at the last complete packet record.")
				break
			}
			return result, fmt.Errorf("pcap record %d: %w", result.Scanned+1, e)
		}
		result.Scanned++
		packet := Decode(pcap.LinkType, record)
		if !o.Filter.Match(packet) {
			continue
		}
		result.Matched++
		result.Bytes += uint64(len(record.Data))
		result.Packets = append(result.Packets, packet)
		if capture != nil {
			if _, e = capture.File.Write(record.WireHeader[:]); e != nil {
				return result, e
			}
			if _, e = capture.File.Write(record.Data); e != nil {
				return result, e
			}
		}
		if emit != nil && time.Since(last) >= 100*time.Millisecond {
			snapshot := result
			snapshot.Packets = append([]Packet(nil), result.Packets...)
			snapshot.Notes = append([]string(nil), result.Notes...)
			emit(snapshot)
			last = time.Now()
		}
	}
	if parent.Err() != nil {
		result.Stop = "interrupted"
	} else if ctx.Err() != nil {
		select {
		case <-planned:
			result.Stop = "duration"
		default:
			return result, ctx.Err()
		}
	} else if result.Matched >= o.Count {
		result.Stop = "count"
	} else if result.Scanned >= o.ScanLimit {
		result.Stop = "scan_limit"
		result.Notes = append(result.Notes, "Scan limit reached; further packets were not examined.")
	}
	if e = finishProcess(); e != nil {
		return result, e
	}
	if capture != nil {
		if e = capture.Commit(); e != nil {
			return result, e
		}
		result.Output = o.Write
	}
	return result, parent.Err()
}
