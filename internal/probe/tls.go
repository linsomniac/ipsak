package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"time"
)

type Certificate struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	DNSNames    []string  `json:"dns_names"`
	IPAddresses []string  `json:"ip_addresses"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	SHA256      string    `json:"sha256"`
	IsCA        bool      `json:"is_ca"`
}

type TLSResult struct {
	Address           string        `json:"address"`
	ServerName        string        `json:"server_name"`
	RemoteAddress     string        `json:"remote_address,omitempty"`
	Protocol          string        `json:"protocol,omitempty"`
	Cipher            string        `json:"cipher,omitempty"`
	ALPN              string        `json:"alpn,omitempty"`
	Trusted           bool          `json:"trusted"`
	VerificationError string        `json:"verification_error,omitempty"`
	RevocationChecked bool          `json:"revocation_checked"`
	Certificates      []Certificate `json:"certificates"`
	HandshakeMS       float64       `json:"handshake_ms"`
}

// TLS captures peer certificates without sending application data, then verifies
// identity, validity and chain independently. Capture alone never implies trust.
func TLS(ctx context.Context, address, serverName string, roots *x509.CertPool) (TLSResult, error) {
	// Interface scopes select a route, not a certificate identity. Keep the
	// address untouched for dialing while checking the unscoped IP SAN.
	if ip, err := netip.ParseAddr(serverName); err == nil {
		serverName = ip.WithZone("").String()
	}
	out := TLSResult{Address: address, ServerName: serverName, Certificates: []Certificate{}}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return out, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	client := tls.Client(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, NextProtos: []string{"h2", "http/1.1"}}) // Certificate acquisition only; verification below is mandatory.
	start := time.Now()
	err = client.HandshakeContext(ctx)
	out.HandshakeMS = float64(time.Since(start)) / float64(time.Millisecond)
	if err != nil {
		return out, err
	}
	state := client.ConnectionState()
	out.RemoteAddress, out.Protocol, out.Cipher, out.ALPN = conn.RemoteAddr().String(), tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite), state.NegotiatedProtocol
	for _, c := range state.PeerCertificates {
		sum := sha256.Sum256(c.Raw)
		item := Certificate{Subject: c.Subject.String(), Issuer: c.Issuer.String(), Serial: c.SerialNumber.String(), DNSNames: append([]string{}, c.DNSNames...), IPAddresses: []string{}, NotBefore: c.NotBefore, NotAfter: c.NotAfter, SHA256: hex.EncodeToString(sum[:]), IsCA: c.IsCA}
		for _, ip := range c.IPAddresses {
			item.IPAddresses = append(item.IPAddresses, ip.String())
		}
		out.Certificates = append(out.Certificates, item)
	}
	if len(state.PeerCertificates) == 0 {
		return out, fmt.Errorf("server provided no certificate")
	}
	intermediates := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	_, err = state.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: serverName, Roots: roots, Intermediates: intermediates})
	if err != nil {
		out.VerificationError = err.Error()
		return out, fmt.Errorf("certificate verification failed: %w", err)
	}
	out.Trusted = true
	return out, ctx.Err()
}
