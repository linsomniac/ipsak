package stream

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/netutil"
)

type ServerOptions struct {
	Address        string
	Status         int
	Body           string
	BodySet        bool
	Delay, Timeout time.Duration
	MaxBody        int64
	MaxConnections int
}

func (o ServerOptions) Validate() error {
	if _, err := ListenAddress(o.Address); err != nil {
		return err
	}
	if o.Status < 200 || o.Status > 599 {
		return fmt.Errorf("status must be between 200 and 599")
	}
	if o.BodySet && (o.Status == 204 || o.Status == 304) && o.Body != "" {
		return fmt.Errorf("status %d does not allow a response body", o.Status)
	}
	if o.Delay < 0 || o.Delay > time.Minute {
		return fmt.Errorf("delay must be between zero and 1m")
	}
	if o.Timeout <= 0 || o.Timeout > 24*time.Hour {
		return fmt.Errorf("request timeout must be greater than zero and at most 24h")
	}
	if o.Delay >= o.Timeout {
		return fmt.Errorf("delay must be shorter than request timeout")
	}
	if o.MaxBody < 0 || o.MaxBody > 16<<20 {
		return fmt.Errorf("max body must be between zero and 16777216 bytes")
	}
	if len(o.Body) > 16<<20 {
		return fmt.Errorf("response body must be at most 16777216 bytes")
	}
	if o.MaxConnections < 1 || o.MaxConnections > 1024 {
		return fmt.Errorf("max connections must be between 1 and 1024")
	}
	return nil
}

type ServerStats struct {
	Address  string `json:"address"`
	Requests uint64 `json:"requests"`
	Rejected uint64 `json:"rejected"`
	Errors   uint64 `json:"errors"`
}

type serverCounters struct {
	requests, rejected, failures atomic.Uint64
	mu                           sync.Mutex
	active                       sync.WaitGroup
	closing                      bool
}

func (c *serverCounters) enter() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing {
		return false
	}
	c.active.Add(1)
	return true
}
func (c *serverCounters) join() { c.mu.Lock(); c.closing = true; c.mu.Unlock(); c.active.Wait() }

func diagnosticHandler(o ServerOptions, counts *serverCounters) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !counts.enter() {
			return
		}
		defer counts.active.Done()
		counts.requests.Add(1)
		ctx, cancel := context.WithTimeout(r.Context(), o.Timeout)
		defer cancel()
		r.Body = http.MaxBytesReader(w, r.Body, o.MaxBody)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			counts.rejected.Add(1)
			var limit *http.MaxBytesError
			if errors.As(err, &limit) {
				http.Error(w, "request body exceeds configured limit", http.StatusRequestEntityTooLarge)
			} else {
				http.Error(w, "could not read request body", http.StatusBadRequest)
			}
			return
		}
		if o.Delay > 0 {
			timer := time.NewTimer(o.Delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				counts.failures.Add(1)
				return
			}
		}
		if ctx.Err() != nil {
			counts.failures.Add(1)
			return
		}
		if o.BodySet {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		w.Header().Set("X-Ipsak", "diagnostic")
		w.WriteHeader(o.Status)
		if o.Status == 204 || o.Status == 304 {
			return
		}
		if o.BodySet {
			_, err = io.WriteString(w, o.Body)
		} else {
			err = json.NewEncoder(w).Encode(struct {
				Method     string      `json:"method"`
				URI        string      `json:"uri"`
				Host       string      `json:"host"`
				Remote     string      `json:"remote"`
				Headers    http.Header `json:"headers"`
				BodyBase64 string      `json:"body_base64"`
				BodyBytes  int         `json:"body_bytes"`
			}{r.Method, r.URL.RequestURI(), r.Host, r.RemoteAddr, r.Header, base64.StdEncoding.EncodeToString(body), len(body)})
		}
		if err != nil {
			counts.failures.Add(1)
		}
	})
}

// Serve closes its listener and drains requests on cancellation, then forces
// remaining connections closed after three seconds. It joins the serving loop.
func Serve(ctx context.Context, o ServerOptions, ready func(string) error) (stats ServerStats, err error) {
	if err = o.Validate(); err != nil {
		return stats, err
	}
	if err = ctx.Err(); err != nil {
		return stats, err
	}
	address, _ := ListenAddress(o.Address)
	l, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		return stats, err
	}
	l = netutil.LimitListener(l, o.MaxConnections)
	defer l.Close()
	stats.Address = l.Addr().String()
	if ready != nil {
		if err = ready(stats.Address); err != nil {
			return stats, err
		}
	}
	counts := &serverCounters{}
	server := &http.Server{Handler: diagnosticHandler(o, counts), ReadHeaderTimeout: min(o.Timeout, 5*time.Second), ReadTimeout: o.Timeout, WriteTimeout: o.Timeout, IdleTimeout: o.Timeout, MaxHeaderBytes: 32768}
	done := make(chan error, 1)
	go func() { done <- server.Serve(l) }()
	select {
	case err = <-done:
		_ = server.Close()
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		shutdownErr := server.Shutdown(shutdownCtx)
		cancel()
		if shutdownErr != nil {
			_ = server.Close()
		}
		serveErr := <-done
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			err = serveErr
		} else {
			err = ctx.Err()
		}
	}
	counts.join()
	stats.Requests = counts.requests.Load()
	stats.Rejected = counts.rejected.Load()
	stats.Errors = counts.failures.Load()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return stats, err
}
