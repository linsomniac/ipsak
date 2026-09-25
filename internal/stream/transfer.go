package stream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net"
)

const magic = "IPSAK1\r\n"
const acknowledgement = "IPSAKOK1"
const maxFrame = 65536

func Send(ctx context.Context, conn net.Conn, source io.Reader, progress Progress) (stats Stats, err error) {
	in, err := prepareInput(ctx, source)
	if err != nil {
		return stats, err
	}
	defer in.cleanup()
	stop := bindContext(ctx, conn)
	defer stop()
	defer func() { err = contextError(ctx, err) }()
	if err = writeAll(conn, []byte(magic)); err != nil {
		return stats, err
	}
	hash := sha256.New()
	buf := make([]byte, maxFrame)
	var length [4]byte
	noProgress := 0
	for {
		n, readErr := in.reader.Read(buf)
		if n < 0 || n > len(buf) {
			return stats, fmt.Errorf("invalid input read count")
		}
		if n > 0 {
			noProgress = 0
			if stats.Sent > math.MaxInt64-int64(n) {
				return stats, fmt.Errorf("transfer size overflow")
			}
			binary.BigEndian.PutUint32(length[:], uint32(n))
			if err = writeAll(conn, length[:]); err != nil {
				return stats, err
			}
			if err = writeAll(conn, buf[:n]); err != nil {
				return stats, err
			}
			_, _ = hash.Write(buf[:n])
			stats.Sent += int64(n)
			if progress != nil {
				if err = progress(stats.Sent); err != nil {
					return stats, err
				}
			}
		} else if readErr == nil {
			noProgress++
			if noProgress >= 100 {
				return stats, io.ErrNoProgress
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return stats, readErr
		}
	}
	digest := hash.Sum(nil)
	stats.SHA256 = hex.EncodeToString(digest)
	trailer := make([]byte, 4+8+sha256.Size)
	binary.BigEndian.PutUint64(trailer[4:12], uint64(stats.Sent))
	copy(trailer[12:], digest)
	if err = writeAll(conn, trailer); err != nil {
		return stats, err
	}
	if err = closeWrite(conn); err != nil {
		return stats, err
	}
	ack := make([]byte, len(acknowledgement)+8+sha256.Size)
	if _, err = io.ReadFull(conn, ack); err != nil {
		return stats, fmt.Errorf("receiver did not acknowledge committed output: %w", err)
	}
	if string(ack[:8]) != acknowledgement || binary.BigEndian.Uint64(ack[8:16]) != uint64(stats.Sent) || !bytes.Equal(ack[16:], digest) {
		return stats, fmt.Errorf("invalid receiver acknowledgement")
	}
	if err = requireEOF(conn); err != nil {
		return stats, fmt.Errorf("invalid receiver acknowledgement: %w", err)
	}
	stats.Verified = true
	stats.Committed = true
	return stats, nil
}

// Receive validates the complete stream before commit, then acknowledges it.
// commit must publish/sync a named output, or be nil for a streaming destination.
func Receive(ctx context.Context, conn net.Conn, output io.Writer, maxBytes int64, commit func() error, progress Progress) (stats Stats, err error) {
	if maxBytes < 0 {
		return stats, fmt.Errorf("max bytes cannot be negative")
	}
	stop := bindContext(ctx, conn)
	defer stop()
	output, cleanup, err := prepareOutput(ctx, output)
	if err != nil {
		return stats, err
	}
	defer cleanup()
	defer func() { err = contextError(ctx, err) }()
	header := make([]byte, len(magic))
	if _, err = io.ReadFull(conn, header); err != nil {
		return stats, fmt.Errorf("transfer header: %w", err)
	}
	if string(header) != magic {
		return stats, fmt.Errorf("peer does not speak ipsak transfer protocol version 1")
	}
	hash := sha256.New()
	buf := make([]byte, maxFrame)
	var length [4]byte
	for {
		if _, err = io.ReadFull(conn, length[:]); err != nil {
			return stats, fmt.Errorf("%w: frame length: %v", errTruncated, err)
		}
		n := int64(binary.BigEndian.Uint32(length[:]))
		if n == 0 {
			break
		}
		if n > maxFrame {
			return stats, fmt.Errorf("frame exceeds %d bytes", maxFrame)
		}
		if stats.Received > math.MaxInt64-n || (maxBytes > 0 && n > maxBytes-stats.Received) {
			return stats, fmt.Errorf("transfer exceeds byte limit")
		}
		if _, err = io.ReadFull(conn, buf[:n]); err != nil {
			return stats, fmt.Errorf("%w: frame payload: %v", errTruncated, err)
		}
		written, writeErr := output.Write(buf[:n])
		if written < 0 || int64(written) > n {
			return stats, fmt.Errorf("invalid output write count")
		}
		stats.Received += int64(written)
		if writeErr != nil {
			return stats, writeErr
		}
		if int64(written) != n {
			return stats, io.ErrShortWrite
		}
		_, _ = hash.Write(buf[:n])
		if progress != nil {
			if err = progress(stats.Received); err != nil {
				return stats, err
			}
		}
	}
	trailer := make([]byte, 8+sha256.Size)
	if _, err = io.ReadFull(conn, trailer); err != nil {
		return stats, fmt.Errorf("%w: trailer: %v", errTruncated, err)
	}
	digest := hash.Sum(nil)
	stats.SHA256 = hex.EncodeToString(digest)
	if binary.BigEndian.Uint64(trailer[:8]) != uint64(stats.Received) {
		return stats, fmt.Errorf("transfer byte count mismatch")
	}
	if !bytes.Equal(trailer[8:], digest) {
		return stats, fmt.Errorf("transfer SHA-256 mismatch")
	}
	if err = requireEOF(conn); err != nil {
		return stats, err
	}
	if err = ctx.Err(); err != nil {
		return stats, err
	}
	stats.Verified = true
	if commit != nil {
		if err = commit(); err != nil {
			return stats, fmt.Errorf("commit output: %w", err)
		}
	}
	stats.Committed = true
	ack := append([]byte(acknowledgement), trailer...)
	if err = writeAll(conn, ack); err != nil {
		return stats, fmt.Errorf("output committed but acknowledgement failed: %w", err)
	}
	return stats, nil
}

func requireEOF(r io.Reader) error {
	var extra [1]byte
	n, err := r.Read(extra[:])
	if n != 0 {
		return fmt.Errorf("unexpected bytes after transfer trailer")
	}
	if err != io.EOF {
		if err == nil {
			err = io.ErrNoProgress
		}
		return fmt.Errorf("expected end of transfer: %w", err)
	}
	return nil
}
