# Monitoring, throughput, and DNS delegation

These four tools use native Go networking and the existing versioned report
envelope. `watch`, `pathwatch`, and `bandwidth` publish immutable snapshots to a
single-slot live update channel. Rendering never delays measurements. Stopping
joins the worker, keeps partial evidence, and emits one final JSON document.
Compact terminal rows wrap full addresses; plain output retains every field.

The independent `expansion_ultra_review` agent reviewed each stage at ultra
effort. All four brainstorm, design, implementation and test gates passed.

| Tool | Brainstorm/design decisions | Implementation/test review evidence |
| --- | --- | --- |
| watch | Native multi-service checks instead of shell loops; bounded parallel rounds, transition history, explicit readiness predicates. | Fixed cancellation accounting and native DNS socket cancellation; fixtures cover concurrency caps, 128 retained transitions, immutable snapshots, HTTP/TCP/DNS, recovery, pending checks and CLI JSON/exits. |
| bandwidth | Cooperating versioned TCP protocol, sequential directions, one stream; receiver-measured payload throughput and receipt. | Fixtures cover both peers/directions, count/rate agreement, malformed negotiation/frames/receipts, partial disconnect, blocked mid-phase cancellation, and real paired TCP CLI JSON. |
| pathwatch | Native ICMP TTL probes with independently identified destination probe; parallel outstanding hops instead of serialized traceroute processes. | Strict IPv4/IPv6 quote/session matching, fresh per-round socket, route growth, independent destination failures, pending probes, immutable bounded history, and privilege errors reviewed. |
| dnstrace | Native iterative DNS with parallel servers at each step; dependency phases stay sequential; missing glue uses an explicitly labeled system-resolver fallback. | Bailiwick/progress/owner/class checks, alias loops, mixed-class records, authoritative negative results, native cancellation and UDP-to-TCP fallback tested. |

## Watch

```
ipsak watch https://example.com tcp://localhost:5432
ipsak watch 'dns://example.com?type=AAAA' icmp://8.8.8.8 --count 5 --json
ipsak watch tcp://localhost:8080 --until all-up --duration 1m
```

Supported schemes: HTTP, HTTPS, TCP, DNS, and ICMP. IPv6 URL authorities use
brackets. HTTP checks connect directly, validate TLS, do not follow redirects,
and consider 200–399 healthy. They read response headers and close the body.
DNS checks require a matching answer of the requested type; in-message CNAME
chains are followed, but an unresolved alias is not counted as success. DNS
defaults to the first system resolver; `--resolver IP[:port]` overrides it.
ICMP uses the existing unprivileged-then-raw ping transport.

Defaults: one-second minimum round interval, ten-second per-check timeout,
16 concurrent checks, continuous observation. `--count` and `--duration` stop
normally; `--timeout` bounds each check. Rounds do not overlap or catch up in
bursts. At most 128 targets, 32 workers, and 128 recent outage/recovery events
are retained, with cumulative counters and dropped-event counts.

Each target distinguishes completed checks from pending checks. A duration or
interrupt does not turn unfinished probes into failed checks. A finite run exits
1 if any completed check failed or none completed. `--until all-up` exits 0 when
every target passes a round, retaining earlier failure history. `--until any-down`
stops after a failing round and exits 1. An unmet readiness condition exits 1.

## Bandwidth

```
# On the receiving machine; explicitly bind beyond loopback.
ipsak bandwidth --listen 0.0.0.0:9000
# On the connecting machine.
ipsak bandwidth --connect peer:9000 --duration 5s --json
ipsak bandwidth --connect peer:9000 --direction download --duration 10s
```

Directions are always relative to the connector. `both` uploads, then downloads;
each phase defaults to five seconds. One TCP stream measures application payload
throughput, not physical link capacity. Listener `--max-duration` caps the peer's
requested time per direction (default one minute). Accepted durations are
1ms–1m. The listener accepts one peer; a bare port binds loopback. Readiness goes
to stderr, including the actual address when listening on port zero.

The `IPSBW1` protocol negotiates direction and duration, then exchanges frames up
to 64 KiB, a terminator, and a receipt containing receiver byte count and elapsed
time. The receiver times payload reception, excluding the initial frame header;
inter-frame gaps remain included. Sender progress is provisional until a valid
receipt agrees with its count. Final rates use the same receiver measurement on
both peers. Empty phases and malformed receipts fail instead of producing NaN
or misleading success. Partial counts survive a disconnect. Receipt delivery
failure can leave a receiver with complete measurements while the sender fails.

The protocol is unencrypted and does not authenticate peers. Handshakes are
bounded to five seconds; each phase gets its requested duration plus five seconds
to finish frames and receipts. `--timeout` optionally bounds the entire session,
including accept; its default zero is unlimited. Cancel closes blocked I/O.

## Pathwatch

```
ipsak pathwatch example.com
ipsak pathwatch example.com --count 5 --max-hops 30 --json
ipsak pathwatch ::1 -6 --duration 10s
```

Each round sends one probe at TTLs 1 through `--max-hops` (default 30, maximum
64), plus a separate TTL-255 destination probe. Probes remain outstanding
concurrently; TTL changes and sends are serialized on one socket. ICMP echo,
time-exceeded, unreachable and IPv6 packet-too-big responses require matching
protocol, destination, random session ID, probe sequence, and any quoted nonce.
Echo replies additionally require the destination source and full nonce. Fresh
sockets and session identities isolate rounds. RTT is application send-to-read
timing and includes the small time spent sending the round's other probes.

Raw ICMP privileges are required: CAP_NET_RAW on Linux or elevated privileges on
macOS. `-4`/`-6` select the family; name resolution has a separate ten-second bound.
Defaults are continuous rounds, one-second interval and one-second round response
budget (`--timeout`). `--count`/`--duration` preserve a final report. Partial probes
remain pending when the session stops. Destination failures determine exit 1;
intermediate silence alone does not. No destination echo also exits 1.

The table shows the current round's reached TTL, while JSON retains all configured
hop statistics. Eight source addresses per hop and 128 recent path changes are
retained, with omission counters. Hop reply rates describe router responses and
must not be interpreted as forwarded packet loss. ECMP, ICMP filtering and rate
limiting can produce changing or silent hop responses.

## DNS trace

```
ipsak dnstrace example.com
ipsak dnstrace example.com --type AAAA --json
ipsak dnstrace private.example --root 192.0.2.53
```

Queries request no recursion and start with four IPv4/IPv6 root-hint addresses.
`--root` accepts up to eight numeric IP[:port] endpoints, useful for private roots
and fixture servers. Each delegation races up to eight servers, uses the first
structurally useful answer, closes slower queries, and retains all observations.
Truncated UDP replies retry TCP within the same deadline. Query timeout defaults
to two seconds; the normal command timeout bounds the whole trace.

Referrals must move strictly deeper toward the queried name. Additional-section
glue is accepted only for named servers inside the delegated zone. Missing or
out-of-bailiwick nameserver addresses use bounded parallel system-resolver calls,
explicitly recorded in `system_resolver_fallback`. The trace is therefore not a
fully independent recursive resolver. CNAME following restarts at the roots,
with loop detection and an eight-alias bound. Total steps default to 32, maximum
64. Retained records and nameservers are bounded.

Authoritative NXDOMAIN or NODATA with a relevant SOA is a completed diagnostic
outcome and exits 0. Lame responses, malformed responses, exhausted limits and
unavailable servers retain partial hops and exit 1. Structural checks do not
authenticate DNS: `dnssec_validated` is false; use `dnssec` for signature checks.

## References and verification

Implementation references: [DNS concepts, RFC 1034](https://www.rfc-editor.org/rfc/rfc1034),
[ICMP, RFC 792](https://www.rfc-editor.org/rfc/rfc792),
[ICMPv6, RFC 4443](https://www.rfc-editor.org/rfc/rfc4443),
and the [Go ICMP package](https://pkg.go.dev/golang.org/x/net/icmp).

Targeted race tests passed for `watch`, `dnstrace`, `dnswire`, `bandwidth`,
`pathwatch` and their CLI fixtures. The session helper additionally tests 10,000
coalesced updates with final-snapshot retention, single JSON output, output
errors, invalid arguments, and cancellation exit 130. Packet tests do not need
raw privileges; native protocol fixtures use loopback TCP/UDP only.

Integration smoke checks also passed native raw IPv4 and IPv6 pathwatch against
loopback (two rounds, three traced hops, two independent destination echoes per
family), a real-terminal watch at widths 40/80/120, and disposable rendering
checks at widths 1/20/40/80/120 for complete IPv6 addresses and JSON immutability.
