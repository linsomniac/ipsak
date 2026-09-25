package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"
)

type HTTPTiming struct {
	DNSMS            float64 `json:"dns_ms"`
	ConnectMS        float64 `json:"connect_ms"`
	TLSMS            float64 `json:"tls_ms"`
	FirstByteMS      float64 `json:"first_byte_ms"`
	TotalMS          float64 `json:"total_ms"`
	ConnectionReused bool    `json:"connection_reused"`
}
type HTTPHop struct {
	URL           string      `json:"url"`
	Status        int         `json:"status"`
	Protocol      string      `json:"protocol,omitempty"`
	RemoteAddress string      `json:"remote_address,omitempty"`
	Headers       http.Header `json:"headers,omitempty"`
	BodyBytesRead int64       `json:"body_bytes_read"`
	BodyTruncated bool        `json:"body_truncated"`
	Timing        HTTPTiming  `json:"timing"`
	Error         string      `json:"error,omitempty"`
}
type HTTPResult struct {
	Hops      []HTTPHop `json:"hops"`
	FinalURL  string    `json:"final_url"`
	BodyLimit int64     `json:"body_limit"`
}

// HTTP performs independent GET requests per redirect hop. It neither retains
// cookies nor propagates credentials, and reads only limit+1 bytes of any body.
func HTTP(ctx context.Context, raw string, redirects int, limit int64) (HTTPResult, error) {
	out := HTTPResult{Hops: []HTTPHop{}, BodyLimit: limit}
	if redirects < 0 || redirects > 10 || limit < 0 || limit > 1<<20 {
		return out, fmt.Errorf("invalid HTTP limits")
	}
	u, err := HTTPURL(raw)
	if err != nil {
		return out, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxResponseHeaderBytes = 64 << 10
	transport.MaxIdleConns, transport.MaxIdleConnsPerHost, transport.MaxConnsPerHost = 2, 2, 2
	transport.DisableCompression = true
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for hop := 0; ; hop++ {
		out.FinalURL = u.String()
		r := HTTPHop{URL: u.String()}
		var mu sync.Mutex
		var timing HTTPTiming
		var remote string
		start := time.Now()
		var dnsStart, tlsStart time.Time
		connectStarts := map[string]time.Time{}
		ms := func(s time.Time) float64 {
			if s.IsZero() {
				return 0
			}
			return float64(time.Since(s)) / float64(time.Millisecond)
		}
		trace := &httptrace.ClientTrace{
			DNSStart:     func(httptrace.DNSStartInfo) { mu.Lock(); dnsStart = time.Now(); mu.Unlock() },
			DNSDone:      func(httptrace.DNSDoneInfo) { mu.Lock(); timing.DNSMS += ms(dnsStart); mu.Unlock() },
			ConnectStart: func(network, address string) { mu.Lock(); connectStarts[network+address] = time.Now(); mu.Unlock() },
			ConnectDone: func(network, address string, err error) {
				mu.Lock()
				timing.ConnectMS += ms(connectStarts[network+address])
				mu.Unlock()
			},
			TLSHandshakeStart:    func() { mu.Lock(); tlsStart = time.Now(); mu.Unlock() },
			TLSHandshakeDone:     func(tls.ConnectionState, error) { mu.Lock(); timing.TLSMS += ms(tlsStart); mu.Unlock() },
			GotFirstResponseByte: func() { mu.Lock(); timing.FirstByteMS = ms(start); mu.Unlock() },
			GotConn: func(info httptrace.GotConnInfo) {
				mu.Lock()
				timing.ConnectionReused = info.Reused
				remote = info.Conn.RemoteAddr().String()
				mu.Unlock()
			},
		}
		req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, u.String(), nil)
		if err != nil {
			return out, err
		}
		req.Header.Set("User-Agent", "ipsak/1.0")
		resp, requestErr := client.Do(req)
		if resp != nil {
			r.Status, r.Protocol, r.Headers = resp.StatusCode, resp.Proto, resp.Header.Clone()
			n, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, limit+1))
			_ = resp.Body.Close()
			r.BodyTruncated = n > limit
			r.BodyBytesRead = n
			if readErr != nil && requestErr == nil {
				requestErr = readErr
			}
		}
		mu.Lock()
		r.Timing = timing
		r.RemoteAddress = remote
		mu.Unlock()
		r.Timing.TotalMS = ms(start)
		if requestErr != nil {
			r.Error = requestErr.Error()
		}
		out.Hops = append(out.Hops, r)
		if requestErr != nil {
			return out, requestErr
		}
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		location := resp.Header.Get("Location")
		isRedirect := r.Status == 301 || r.Status == 302 || r.Status == 303 || r.Status == 307 || r.Status == 308
		if !isRedirect || location == "" {
			if r.Status >= 400 {
				return out, fmt.Errorf("HTTP status %d", r.Status)
			}
			return out, nil
		}
		if hop >= redirects {
			return out, fmt.Errorf("redirect limit %d reached", redirects)
		}
		next, err := u.Parse(location)
		if err != nil {
			return out, fmt.Errorf("invalid redirect: %w", err)
		}
		u, err = HTTPURL(next.String())
		if err != nil {
			return out, fmt.Errorf("invalid redirect: %w", err)
		}
	}
}
