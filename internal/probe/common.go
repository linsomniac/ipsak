// Package probe implements bounded, cancellable network protocol inspections.
package probe

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/linsomniac/ipsak/internal/lookup"
)

func HostPort(raw, defaultPort string) (host, address string, err error) {
	if raw == "" || len(raw) > 1024 || strings.ContainsAny(raw, "/?#@") || strings.IndexFunc(raw, unicode.IsSpace) >= 0 {
		return "", "", fmt.Errorf("expected a host or host:port")
	}
	port := defaultPort
	if h, p, e := net.SplitHostPort(raw); e == nil {
		host, port = h, p
	} else {
		host = raw
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
	}
	host, err = Host(host)
	if err != nil {
		return "", "", err
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("port must be 1–65535")
	}
	return host, net.JoinHostPort(host, strconv.Itoa(n)), nil
}

func Host(raw string) (string, error) {
	if strings.ContainsAny(raw, "/?#@[]") || strings.TrimSpace(raw) != raw {
		return "", fmt.Errorf("invalid host %q", raw)
	}
	if ip, err := netip.ParseAddr(raw); err == nil {
		return ip.String(), nil
	}
	if strings.Contains(raw, ":") {
		return "", fmt.Errorf("invalid host %q", raw)
	}
	t, err := lookup.ParseTarget(raw)
	if err != nil {
		return "", err
	}
	return t.Name, nil
}

func HTTPURL(raw string) (*url.URL, error) {
	if len(raw) > 8192 {
		return nil, fmt.Errorf("URL exceeds 8192 bytes")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("expected an HTTP or HTTPS URL without credentials")
	}
	host, err := Host(u.Hostname())
	if err != nil {
		return nil, err
	}
	port := u.Port()
	if port != "" {
		_, address, err := HostPort(net.JoinHostPort(host, port), "443")
		if err != nil {
			return nil, err
		}
		u.Host = address
	} else {
		if strings.HasSuffix(u.Host, ":") {
			return nil, fmt.Errorf("empty URL port")
		}
		u.Host = host
		if strings.Contains(host, ":") {
			u.Host = "[" + host + "]"
		}
	}
	u.Fragment = ""
	return u, nil
}
