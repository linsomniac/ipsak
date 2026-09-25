package lookup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func publicFixture(t *testing.T, handler http.HandlerFunc) (*Service, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	s := NewService()
	s.HTTP = server.Client()
	s.PublicURLs = []string{server.URL}
	return s, server
}

func TestPublicIPFamiliesFreshTransportAndRedirect(t *testing.T) {
	for _, family := range []string{"tcp4", "tcp6"} {
		t.Run(family, func(t *testing.T) {
			address := "198.99.83.244"
			if family == "tcp6" {
				address = "2001:4860:4860::8888"
			}
			s, server := publicFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/redirect" {
					http.Redirect(w, r, "/address", http.StatusFound)
					return
				}
				fmt.Fprint(w, address)
			})
			transport := s.HTTP.Transport.(*http.Transport)
			networks := make(chan string, 4)
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				networks <- network
				// Record the requested family; both isolated TLS fixtures use loopback IPv4.
				return (&net.Dialer{}).DialContext(ctx, "tcp4", address)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := s.PublicIP(ctx); err != nil {
				t.Fatal(err)
			}
			if got := <-networks; got != "tcp" {
				t.Fatal("initial network:", got)
			}
			s.PublicURLs = []string{server.URL + "/redirect"}
			data, err := s.publicIPFamily(ctx, family)
			if err != nil || data.(PublicIP).IP.String() != address {
				t.Fatal(data, err)
			}
			if got := <-networks; got != family {
				t.Fatal("probe reused initial pool or did not force requested family:", got)
			}
			if s.HTTP.Transport != transport {
				t.Fatal("probe replaced the shared transport")
			}
			transport.CloseIdleConnections()
			if _, err := s.PublicIP(ctx); err != nil {
				t.Fatal(err)
			}
			if got := <-networks; got != "tcp" {
				t.Fatal("probe modified the original dialer:", got)
			}
		})
	}
}

func TestPublicIPv4RaceCancelsLosers(t *testing.T) {
	started, canceled := make(chan struct{}), make(chan struct{})
	s, server := publicFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(started)
			<-r.Context().Done()
			close(canceled)
			return
		}
		select {
		case <-started:
			fmt.Fprint(w, "198.99.83.244")
		case <-r.Context().Done():
		}
	})
	s.PublicURLs = []string{server.URL + "/slow", server.URL + "/fast"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := s.PublicIPv4(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-ctx.Done():
		t.Fatal("losing request was not canceled")
	}
}

func TestPublicIPValidatesFamilyScopeAndPublicAddress(t *testing.T) {
	for _, family := range []string{"tcp4", "tcp6"} {
		for _, body := range []string{"198.99.83.244", "::ffff:198.99.83.244", "2001:4860:4860::8888", "2001:4860:4860::8888%eth0", "::ffff:198.99.83.244%eth0", "10.0.0.1", "fe80::1", "garbage"} {
			t.Run(family+"/"+body, func(t *testing.T) {
				s := fixtureService(body)
				s.PublicURLs = []string{"https://fixture.example"}
				data, err := s.discoverPublicIP(context.Background(), family)
				valid := family == "tcp4" && (body == "198.99.83.244" || body == "::ffff:198.99.83.244") || family == "tcp6" && body == "2001:4860:4860::8888"
				if (err == nil) != valid {
					t.Fatal(data, err)
				}
				if valid && family == "tcp4" && data.(PublicIP).IP.String() != "198.99.83.244" {
					t.Fatal("address not normalized:", data)
				}
			})
		}
		s := fixtureService("198.99.83.244")
		if _, err := s.publicIPFamily(context.Background(), family); err == nil {
			t.Fatal("accepted transport without address-family control")
		}
	}
}

// Route the injected dialer to distinct local TLS providers for each family.
// Tests work on IPv4-only CI hosts while still enforcing tcp4/tcp6 selection.
func dualPublicFixture(t *testing.T, v4, v6 http.HandlerFunc) *Service {
	t.Helper()
	s, four := publicFixture(t, v4)
	_, six := publicFixture(t, v6)
	s.HTTP.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		address := four.Listener.Addr().String()
		switch network {
		case "tcp4":
		case "tcp6":
			address = six.Listener.Addr().String()
		default:
			return nil, fmt.Errorf("unexpected unforced network: %s", network)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp4", address)
	}
	return s
}

func myIPTasks(t *testing.T, s *Service) []Task {
	t.Helper()
	all, err := s.Tasks("myip", Target{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var tasks []Task
	for _, task := range all {
		switch task.Key {
		case "public", "public_ipv4", "public_ipv6", "target":
			tasks = append(tasks, task)
		}
	}
	return tasks
}

func runPublicTasks(t *testing.T, ctx context.Context, tasks []Task) map[string]Section {
	t.Helper()
	ch, err := Run(ctx, tasks)
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]Section)
	for section := range ch {
		out[section.Key] = section
	}
	return out
}

func TestMyIPBothFamiliesOverlapPrimaryEnrichment(t *testing.T) {
	for _, first := range []int{0, 1} {
		t.Run(fmt.Sprintf("IPv%d-first", first*2+4), func(t *testing.T) {
			var requests [2]atomic.Int32
			started := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
			release := make(chan struct{})
			addresses := [2]string{"198.99.83.244", "2001:4860:4860::8888"}
			handler := func(index int) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if requests[index].Add(1) != 1 {
						t.Error("redundant discovery request")
						return
					}
					close(started[index])
					wait := release
					if index == first {
						wait = started[1-index]
					}
					select {
					case <-wait:
						fmt.Fprint(w, addresses[index])
					case <-r.Context().Done():
					}
				}
			}
			s := dualPublicFixture(t, handler(0), handler(1))
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			tasks := myIPTasks(t, s)
			tasks = append(tasks, Task{Key: "enrichment", Depends: []string{"target"}, Run: func(ctx context.Context, deps map[string]Section) (any, error) {
				close(release)
				return deps["target"].Data, nil
			}})
			out := runPublicTasks(t, ctx, tasks)
			for key, section := range out {
				if section.Status != "ok" {
					t.Fatalf("%s: %+v", key, section)
				}
			}
			if out["public"].Data.(PublicIP).IP.String() != addresses[first] || out["target"].Data.(Target).IP.String() != addresses[first] {
				t.Fatal("did not enrich first successful family:", out)
			}
			for i, key := range []string{"public_ipv4", "public_ipv6"} {
				if out[key].Data.(PublicIP).IP.String() != addresses[i] || requests[i].Load() != 1 {
					t.Fatal("missing family or duplicate requests:", out)
				}
			}
			b, err := json.Marshal(out)
			if err != nil || !strings.Contains(string(b), `"ip":"198.99.83.244"`) || !strings.Contains(string(b), `"ip":"2001:4860:4860::8888"`) {
				t.Fatal(string(b), err)
			}
		})
	}
}

func TestMyIPFamilyFailureAndTotalFailure(t *testing.T) {
	for _, available := range []string{"IPv4", "IPv6", "neither"} {
		t.Run(available, func(t *testing.T) {
			handler := func(family, address string) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if family == available {
						fmt.Fprint(w, address)
					} else {
						http.Error(w, "unavailable", http.StatusServiceUnavailable)
					}
				}
			}
			s := dualPublicFixture(t, handler("IPv4", "198.99.83.244"), handler("IPv6", "2001:4860:4860::8888"))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			out := runPublicTasks(t, ctx, myIPTasks(t, s))
			if available == "neither" {
				if out["public"].Status != "error" || out["target"].Status != "skipped" {
					t.Fatal(out)
				}
			} else {
				for key, section := range out {
					want := "ok"
					if key == "public_ipv4" && available != "IPv4" || key == "public_ipv6" && available != "IPv6" {
						want = "skipped"
					}
					if section.Status != want {
						t.Fatalf("%s: %+v, want %s", key, section, want)
					}
				}
			}
		})
	}
}

func TestMyIPMissingFamilyGraceAndCancellation(t *testing.T) {
	probing, canceled := make(chan struct{}), make(chan struct{})
	s := dualPublicFixture(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-probing:
			fmt.Fprint(w, "198.99.83.244")
		case <-r.Context().Done():
		}
	}, func(_ http.ResponseWriter, r *http.Request) {
		close(probing)
		<-r.Context().Done()
		close(canceled)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out := runPublicTasks(t, ctx, myIPTasks(t, s))
	if out["public_ipv4"].Status != "ok" || out["public_ipv6"].Status != "skipped" || !strings.Contains(out["public_ipv6"].Error, "within 2s") || ctx.Err() != nil {
		t.Fatal(out, ctx.Err())
	}
	select {
	case <-canceled:
	case <-ctx.Done():
		t.Fatal("unfinished family was not canceled")
	}
}

func TestMyIPParentCancellationIsNotOptional(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(fmt.Sprint(canceled), func(t *testing.T) {
			wait := func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }
			s := dualPublicFixture(t, wait, wait)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			if canceled {
				cancel()
			}
			defer cancel()
			out := runPublicTasks(t, ctx, myIPTasks(t, s))
			for _, key := range []string{"public", "public_ipv4", "public_ipv6"} {
				if out[key].Status != "error" || !strings.Contains(out[key].Error, ctx.Err().Error()) {
					t.Fatal("parent failure was hidden:", out)
				}
			}
		})
	}
}

func TestPublicDiscoveryPrimaryUsesOverallDeadline(t *testing.T) {
	slow := func(ctx context.Context) (any, error) {
		select {
		case <-time.After(2100 * time.Millisecond):
			return "address", nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	fail := func(context.Context) (any, error) { return nil, errors.New("unavailable") }
	d := newPublicDiscovery(slow, fail)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	data, err := d.result(ctx, 0)
	if err != nil || data != "address" {
		t.Fatal("primary discovery incorrectly capped at2s:", data, err)
	}
	cancel()
	if _, err := d.result(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatal("cached result hid cancellation:", err)
	}
}
