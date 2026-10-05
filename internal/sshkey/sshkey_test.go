package sshkey

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestHandshakeAndPinsWithoutAuthentication(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var auth atomic.Int32
	var wg sync.WaitGroup
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil }, AuthLogCallback: func(ssh.ConnMetadata, string, error) { auth.Add(1) }}
	cfg.AddHostKey(signer)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); defer c.Close(); _, _, _, _ = ssh.NewServerConn(c, cfg) }()
		}
	}()
	pin := ssh.FingerprintSHA256(signer.PublicKey())
	for _, p := range []string{"", pin, "SHA256:" + strings.Repeat("A", 43)} {
		r, e := Observe(context.Background(), ln.Addr().String(), p)
		if r.Fingerprint != pin || r.KeyType != ssh.KeyAlgoED25519 || r.PublicKey == "" {
			t.Fatal(r, e)
		}
		if p != "" && p != pin {
			if e == nil || r.PinMatch == nil || *r.PinMatch {
				t.Fatal(r, e)
			}
		} else if e != nil {
			t.Fatal(r, e)
		}
	}
	_ = ln.Close()
	<-done
	wg.Wait()
	if auth.Load() != 0 {
		t.Fatalf("attempted %d authentication requests", auth.Load())
	}
}

func TestPinSyntaxAndHandshakeCancellation(t *testing.T) {
	for _, p := range []string{"md5:abc", "SHA256:abc", "SHA256:" + strings.Repeat("A", 43) + "=", "SHA256:" + strings.Repeat("A", 42) + "B"} {
		if ValidatePin(p) == nil {
			t.Fatalf("accepted %q", p)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	closed := make(chan struct{})
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 1024)
		for {
			if _, e = c.Read(b); e != nil {
				close(closed)
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	r, err := Observe(ctx, ln.Addr().String(), "")
	if err == nil || r.Fingerprint != "" || time.Since(start) > time.Second {
		t.Fatal(r, err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("canceled handshake connection leaked")
	}
}
