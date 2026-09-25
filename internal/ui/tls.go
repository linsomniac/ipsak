package ui

import (
	"time"

	"github.com/linsomniac/ipsak/internal/probe"
)

// TLS presentation keeps the leaf visible without changing the full chain in
// structured output. Verbose adds the chain after the summary and leaf details.
func (t Theme) tlsLines(value any, width int) ([]string, bool) {
	r, ok := value.(probe.TLSResult)
	if !ok {
		return nil, false
	}
	chain := r.Certificates
	r.Certificates = nil
	var expires *time.Time
	if len(chain) > 0 && !chain[0].NotAfter.IsZero() {
		date := chain[0].NotAfter.UTC()
		expires = &date
	}
	lines := fields(struct {
		probe.TLSResult
		Expires *time.Time `json:"expires,omitempty"`
	}{r, expires}, width)
	if len(chain) == 0 {
		return lines, true
	}
	leaf := chain[0]
	lines = append(lines, "", "Target certificate")
	// The leaf's expiry is already promoted to the main summary above.
	lines = append(lines, fields(map[string]any{
		"subject":      leaf.Subject,
		"issuer":       leaf.Issuer,
		"serial":       leaf.Serial,
		"dns_names":    leaf.DNSNames,
		"ip_addresses": leaf.IPAddresses,
		"not_before":   leaf.NotBefore,
		"sha256":       leaf.SHA256,
		"is_ca":        leaf.IsCA,
	}, width)...)
	if t.Verbose {
		lines = append(lines, "", "Certificate chain")
		lines = append(lines, fields(map[string]any{"certificates": chain}, width)...)
	}
	return lines, true
}
