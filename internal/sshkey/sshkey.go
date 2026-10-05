// Package sshkey observes an SSH host key without starting authentication.
package sshkey

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Result struct {
	Address     string `json:"address"`
	Remote      string `json:"remote,omitempty"`
	KeyType     string `json:"key_type,omitempty"`
	Fingerprint string `json:"fingerprint_sha256,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
	PinMatch    *bool  `json:"pin_match,omitempty"`
	Note        string `json:"note"`
}

func (r Result) CompactLines() []string {
	lines := []string{r.Address}
	if r.Remote != "" {
		lines = append(lines, "Peer "+r.Remote)
	}
	if r.KeyType != "" {
		lines = append(lines, "Host key "+r.KeyType)
	}
	if r.Fingerprint != "" {
		lines = append(lines, r.Fingerprint)
	} else {
		lines = append(lines, "No host key observed")
	}
	if r.PinMatch != nil {
		if *r.PinMatch {
			lines = append(lines, "Supplied fingerprint matches")
		} else {
			lines = append(lines, "Supplied fingerprint DOES NOT MATCH")
		}
	} else if r.Fingerprint != "" {
		lines = append(lines, "No fingerprint comparison requested")
	} else {
		lines = append(lines, "Fingerprint comparison unavailable")
	}
	if r.Note != "" {
		lines = append(lines, r.Note)
	}
	return lines
}

// ValidatePin accepts the canonical OpenSSH SHA256 fingerprint format.
func ValidatePin(pin string) error {
	if pin == "" {
		return nil
	}
	if !strings.HasPrefix(pin, "SHA256:") {
		return fmt.Errorf("fingerprint must use SHA256: followed by 43 unpadded base64 characters")
	}
	s := strings.TrimPrefix(pin, "SHA256:")
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 || base64.RawStdEncoding.EncodeToString(b) != s {
		return fmt.Errorf("invalid SHA256 fingerprint")
	}
	return nil
}

func Observe(ctx context.Context, address, pin string) (Result, error) {
	r := Result{Address: address, Note: "A reported key has a verified key-exchange signature. A matching supplied fingerprint compares identity against that pin; trust depends on how the pin was obtained. No login is attempted; only one negotiated key is observed."}
	if err := ValidatePin(pin); err != nil {
		return r, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return r, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	observed := errors.New("host key observed; stop before authentication")
	cfg := &ssh.ClientConfig{User: "ipsak", HostKeyCallback: func(_ string, remote net.Addr, key ssh.PublicKey) error {
		r.Remote, r.KeyType = remote.String(), key.Type()
		r.Fingerprint, r.PublicKey = ssh.FingerprintSHA256(key), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		return observed
	}}
	_, _, _, err = ssh.NewClientConn(conn, address, cfg)
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	if !errors.Is(err, observed) || r.Fingerprint == "" {
		return r, fmt.Errorf("SSH host key handshake: %w", err)
	}
	if pin != "" {
		match := subtle.ConstantTimeCompare([]byte(pin), []byte(r.Fingerprint)) == 1
		r.PinMatch = &match
		if !match {
			return r, fmt.Errorf("SSH host key fingerprint mismatch")
		}
	}
	return r, nil
}
