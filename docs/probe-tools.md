# Protocol inspection tools

All five commands use the shared lookup report, concurrent task runner, inline
display, plain output, deadline, and final JSON document. Independent resolvers
and providers run concurrently; results retain argument order. Network and
verification failures retain collected data and return exit 1; invalid arguments
return exit 2; cancellation returns exit 130.

## Brainstorm

Each command was considered separately before design and implementation.

| Command | Alternatives considered | Proposed direction |
| --- | --- | --- |
| `tlscert` | Shell out to openssl; stop at verification error; capture then independently verify | Native TLS handshake captures the presented chain, then Go X.509 verification checks the requested identity and system roots. Invalid certificates remain visible with explicit trust failure. |
| `httpinfo` | HEAD only; unbounded GET; bounded GET with hop traces | Native GET, manual bounded redirects, headers and per-hop DNS/connect/TLS/first-byte timings, bounded body sampling without displaying response content. |
| `dnscheck` | Compare only OS resolution; external dig; DNS wire queries per resolver | Existing DNS dependency, explicit per-resolver response codes, sorted TTL-independent answer sets, UDP with TCP fallback and a comparison summary. |
| `ntptime` | External ntpdate; maintained daemon; one validated UDP exchange | One NTPv4 request, validate protocol fields and origin, unfold era near local time, report timestamps/delay/offset without adjusting the clock. |
| `lookingglass` | HTML scraping; provider links only; documented public JSON APIs | Query RIPE RIS and NLNOG OpenBGPD observations concurrently, normalize routes and freshness metadata, permit explicit adapter endpoint overrides and collector filtering. |

## Primary references

- TLS capture and verification: https://pkg.go.dev/crypto/tls and https://pkg.go.dev/crypto/x509
- HTTP tracing: https://pkg.go.dev/net/http/httptrace
- DNS implementation: https://pkg.go.dev/github.com/miekg/dns
- NTP wire fields and clock arithmetic: https://www.rfc-editor.org/rfc/rfc5905
- RIPEstat public API envelope: https://stat.ripe.net/docs/data-api/ripestat-data-api
- RIS looking-glass parameters and results: https://data.stat.ripe.net/docs/data-api/api-endpoints/looking-glass
- Independent NLNOG API: https://github.com/NLNOG/lg.ring.nlnog.net/blob/main/API.md
- NLNOG service scope: https://lg.ring.nlnog.net/about

Review evidence and accepted designs are recorded below as each stage completes.

## Design

- `tlscert HOST[:PORT]`: port 443 by default, optional `--server-name`.
  Human output shows connection/trust information and the target certificate by
  default, with its expiration prominently labeled `expires` in the main summary.
  Use `--verbose` (`-v`) to add all numbered certificates in the presented chain.
  JSON always includes the complete chain, regardless of verbosity.
  Acquire certificates without application data, then independently verify the
  requested hostname/IP and chain against system trust. Report certificate
  identity, validity, SHA-256 fingerprint, protocol and cipher; untrusted chains
  retain the chain and return failure. IPv6 interface scope stays in the dial
  address and is removed from the certificate identity. This does not check
  revocation. Human-readable expiry timestamps in `tlscert` and `doctor` include
  remaining whole 24-hour days, for example `2026-11-06T14:31:14Z (42 days)`.
  Counts round down: less than a day remaining is `0 days`, and expired dates
  have negative counts. JSON retains the original timestamps.
- `httpinfo URL`: HTTPS is assumed for a bare hostname. GET follows at most five
  redirects (`--max-redirects 0..10`), traces each hop, reads at most 64 KiB of
  each response (`--max-body 0..1048576`), and retains headers. Headers are capped
  at 64 KiB per hop. Body contents are discarded. No cookie jar is used.
  Sampling reads one additional byte to detect truncation, included in
  `body_bytes_read`. Timings use milliseconds; connection time sums connection
  attempts and can overlap under dual-stack dialing. Statuses 400 and above
  produce exit 1 with the response intact. Redirect-limit errors retain the last
  response. HTTP and HTTPS redirects are both allowed.
- `dnscheck NAME`: query A/AAAA by default, PTR for an address; `--type` selects
  up to eight supported types. Up to eight `--resolver IP[:PORT]` values replace
  system DNS servers. Query each resolver/type concurrently with UDP-to-TCP
  fallback. Compare sorted answer sets without TTL; negative answers remain
  distinct from transport and DNS server errors. AD is a resolver assertion,
  not local DNSSEC validation. Different answers need not indicate a fault.
- `ntptime [SERVER[:PORT]]`: one NTP exchange with `pool.ntp.org:123` by default.
  Validate response identity and synchronization fields, preserve diagnostics,
  report client/server timestamps and offset/delay. Era unfolding assumes the
  local clock is within 68 years of actual time. This is an unauthenticated
  single-sample estimate and never changes the system clock.
- `lookingglass IP|PREFIX`: query RIPE and NLNOG by default. `--provider`
  selects providers or `ripe=URL` / `nlnog=URL` compatible endpoints. Independent
  requests run concurrently and fail separately. Bound responses to 2 MiB,
  sort routes deterministically and retain at most `--limit` routes per
  provider. `--collector` filters RIPE observations. Report timestamps, warnings
  and truncation. These BGP observations describe particular collectors, and
  do not execute remote ping or traceroute or prove end-to-end reachability.

Examples:

```sh
ipsak tlscert example.com
ipsak tlscert example.com --verbose
ipsak tlscert 192.0.2.10:8443 --server-name example.com --json
ipsak httpinfo https://example.com --max-redirects 3 --max-body 1024
ipsak dnscheck example.com --resolver 1.1.1.1,8.8.8.8 --type A,AAAA
ipsak dnscheck 2001:4860:4860::8888 --resolver 1.1.1.1
ipsak ntptime pool.ntp.org --json
ipsak lookingglass 8.8.8.8 --provider ripe,nlnog --limit 20
ipsak lookingglass 8.8.8.0/24 --provider ripe --collector rrc01
```

All result sections contain typed JSON data. `tlscert` uses section `tls` with
explicit `trusted`, `verification_error`, `revocation_checked`, and presented
`certificates`. `httpinfo` uses `http`, whose `hops` preserve redirect order.
`dnscheck` uses `dnscheck`, with resolver/type `queries` and per-type
`comparisons`; `insufficient_data` means fewer than two successful resolver
responses. `ntptime` uses `ntp`, with `valid`, all four timestamps, signed
`offset_ms` (positive means the server is ahead), `delay_ms`, and root quality
fields. `lookingglass` uses `lookingglass_N_PROVIDER` in requested provider
order, with sorted `routes`, `total_routes`, `truncated`, `has_routes`, freshness
metadata, and `warnings`. Empty route responses are observations with warnings,
not claims that no route exists. Endpoint overrides require HTTPS except
numeric loopback HTTP for development fixtures.

## Stage review log

All reviews use the independent ultra-effort `/root/stream_tools` agent.

| Command | Brainstorm review | Design review | Implementation review | Test review |
| --- | --- | --- | --- | --- |
| tlscert | Approved: capture + explicit trust; no application data | Approved: context covers handshake and invalid trust fails | Approved: isolated capture, explicit X.509 verification | Approved: trust, wrong identity, expiry, cancellation |
| httpinfo | Approved: bounded GET and hop traces | Approved: credentials prohibited, zero-byte sampling defined | Approved: redirect/body/header limits and trace mutex | Approved: limits, redirects, HTTP errors, timeout, JSON |
| dnscheck | Approved: distinguish NXDOMAIN, NODATA, and errors | Approved: compare status and canonical successful answer sets | Approved after checking bounds before allocation and rejecting empty name | Approved: concurrent queries, TTL independence, negative/error separation, TCP fallback, cancellation |
| ntptime | Approved: validated sample and uncertainty | Approved: negative-delay rejection and era assumptions | Approved: origin, protocol, synchronization, KoD, signed arithmetic | Approved: malformed fields, era boundaries, arithmetic, UDP, JSON |
| lookingglass | Approved: real public APIs, collector scope | Approved: independent NLNOG adapter, freshness/empty limits | Approved after declared-prefix relationship validation | Approved: schemas, bounds, unrelated data, provider concurrency, partial failure, cancellation |

The implementation and test reviews were conducted against the actual files,
not only the design summaries. Reviewer recommendations incorporated into the
implementation include retaining invalid certificate diagnostics, exact NTP
origin validation, marking materially negative NTP delays invalid, distinguishing
DNS negative answers from operational failures, and validating NLNOG's declared
prefix even when no routes are returned.

An additional ultra-reviewed TLS refinement strips IPv6 interface scope from
the certificate identity while retaining the scoped dial address. The local
TLS trust fixture verifies the unscoped IP SAN; the focused TLS race suite
passed after this change.

Test evidence (local fixtures only, no external service dependency):

```sh
GOCACHE=/tmp/ipsak-go-build go test -buildvcs=false ./internal/probe ./internal/cli \
  -run 'Test(Endpoint|TLS|HTTP|DNS|NTP|LookingGlass|Probe)' -count=1 -timeout=60s
GOCACHE=/tmp/ipsak-go-build go test -race -buildvcs=false ./internal/probe ./internal/cli \
  -run 'Test(Endpoint|TLS|HTTP|DNS|NTP|LookingGlass|Probe)' -count=1 -timeout=60s
```

Both commands passed. Fixture listeners bind loopback TCP/UDP only. The CLI
checks validate startup exit 2, retained partial results with exit 1, cancellation
exit 130, stable provider order, and a single final JSON document without pending
sections. Two read-only sample queries to each public looking-glass service also
confirmed adapter field formats: RIPE uses uppercase collector IDs (normalized
to lowercase), and NLNOG can return a null collection timestamp (reported as
unavailable freshness). Public service availability remains outside the test
suite and has no effect on whether tests pass.
