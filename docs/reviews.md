# Review and validation notes

The user requested ultra-effort subagent reviews of the work plan, design, and
implementation. Independent reviews covered the command-porting scope,
dependency graph, provider validation, ping accounting/transport, and terminal
lifecycle. Final architecture and implementation reviews approved the result with
no outstanding findings.

Findings resolved during implementation:

- DNS blocklist timeouts, empty responses, and refusal codes are distinct from
  confirmed negatives; current Spamhaus codes and IPv6 special-use exceptions
  are handled explicitly.
- DNS sockets close on cancellation, truncated responses retry over TCP, and
  CNAME chains have a depth limit and cycle detection.
- ASN parsing is strict, ASN names match their requested number, and malformed
  location coordinates or mixed-family RDAP ranges fail visibly.
- RPKI depends only on ASN discovery; domain DNS and local interface discovery
  remain useful when their independent IP resolution/discovery fails.
- Public RDAP uses IANA's authoritative bootstrap. A live test exposed a timeout
  in the initial third-party redirect approach; direct registry lookup passed.
- Ping uses receipt timestamps and drains published replies before expiration,
  commits outcomes in send order, and preserves completed loss transitions when
  status snapshots are coalesced.
- Interrupted probes remain pending. User interruption returns exit 130,
  including cancellation during hostname resolution.
- Failed output writes cancel and join the ping engine. Untrusted terminal text,
  including IPv6 zones, is sanitized.
- A full event queue during final shutdown is reported in the final snapshot,
  including the boundary where the last loss-start fits but its closing event
  does not. A finite-probe regression test covers that case.

Validation includes `go vet`, `go test -race`, a Linux build, a macOS arm64 cross
build, native IPv4/IPv6 loopback ICMP, public-address information lookup, and real
PTY tests for resize, finite completion, keyboard stop, `NO_COLOR`, cursor and
terminal restoration. A `/dev/full` smoke test verifies prompt shutdown on a
failed output stream. Provider tests use HTTP fixtures and local UDP/TCP DNS;
ping accounting and loss-row updates also have deterministic tests.

The trace adapter and JSON schema differences from Python are deliberate and
documented in README.md. No claim of native traceroute feature parity is made.

## CIDR ping extension

Ultra-effort subagents reviewed brainstorming, the concrete implementation plan,
the scheduler/transport/CLI implementation, and the terminal/JSON integration.
The [CIDR design notes](cidr-ping.md) record the fping, Nmap, and gping research
and the chosen defaults.

Review findings resolved:

- Sweep validation is independent of the single-host pending/interval limit;
  size and count overflow checks happen before socket creation or expansion.
- Local send errors consume attempts and remain visible without preventing a
  useful sweep with responders from succeeding.
- Global and per-address pacing start from write completion so a blocked write
  cannot trigger a catch-up burst. RTT retains the application send timestamp.
- The bounded live preview prioritizes responders, so early send errors cannot
  hide later responding addresses. All errors remain in the final report.
- Final text uses the terminal's latest dimensions after resizing; live timing
  also appears in ordinary 80-column terminals when it fits.
- Continuous-mode count tests stop after a known number of sends instead of
  requiring a minimum amount of work within a short wall-clock window.

Validation covers range endpoints and IPv6 limits; numeric ordering; native
ICMP session identity/source/sequence wrapping; duplicate/late/queued replies;
weighted latency and immutable snapshots; finite drain, pacing and cancellation;
failed sends/read errors; CLI defaults, exit codes, JSON and plain output;
terminal widths, height bounds, stop keys, and output failure.

Full `make check` (vet and race tests) passes with a writable Go cache and access
to the existing loopback DNS fixtures. Native smoke tests cover IPv4 `/30`
including both endpoints, IPv6 `/128`, unchanged host ping, duration expiry,
SIGINT with partial JSON, and rejection of oversized IPv6 ranges. Real PTY
checks cover finite completion, resize, q, NO_COLOR, and cursor/terminal
restoration. A `/dev/full` check confirms failed-output shutdown. Linux and
macOS arm64 builds are checked.

## Diagnostic and stream expansion (2026-09-24)

Seventeen commands were added: doctor, tlscert, httpinfo, dnscheck, mtu, sockets,
route, interfaces, neighbors, connect, listen, send, receive, serve, wake,
lookingglass, and ntptime. Every command received separate brainstorm, design,
implementation, and test verdicts from an independent ultra-effort subagent.

| Implementation group | Independent ultra reviewer | Per-command record |
| --- | --- | --- |
| Protocol clients | stream_tools | [Protocol tools](probe-tools.md) |
| Local host tools | protocol_tools | [Host tools](host-tools.md) |
| Streams and HTTP server | host_tools | [Stream tools](stream-tools.md) |
| Doctor, MTU, shared reports | host_tools | [Diagnostic tools](diagnostic-tools.md) |
| Compact inventory UI | protocol_tools | [Diagnostic tools](diagnostic-tools.md) |

All stages and the final cross-group implementation/documentation audit are
approved, with no unresolved review findings. Follow-up reviews resolved:

- Parallel provider failures preserve successful data, deterministic JSON, and
  useful nonzero exit codes. Cancellation differs from expired deadlines.
- Transfers support either connection direction, retain raw byte ordering, and
  keep payload separate from reports. Named receives verify before atomic
  publication and acknowledge only committed output. Blocking inherited pipes
  can be canceled without closing caller-owned descriptors.
- Stream sessions default to unlimited duration, with an optional overall
  deadline and a separate ten-second outgoing TCP establishment limit.
- Invalid TLS certificates remain visible without implying trust. IPv6 interface
  scopes remain in routed addresses but are removed from certificate identity.
- MTU search uses explicit size evidence; timeouts cannot invent upper bounds.
- Linux socket parsing handles both IPv4 device scopes and IPv6 scopes inside
  or outside brackets. Native checks exposed these real output variations.
- macOS route flags distinguish local routes, rejects, and blackholes. macOS
  socket/neighbor adapters have typed parsers and fixtures.
- Compact terminal inventory rows retain full plain/JSON data, sanitize generated
  fields, and avoid unnecessary JSON conversion on each live update.

Validation includes complete vet/race tests, Linux and macOS arm64 builds, local
protocol fixtures, native Linux inventory/route/socket/neighbor checks, and real
CLI binary file transfers in both connection directions. A temporary HTTP server
was queried with httpinfo and raw TCP. PTY checks verified narrow resize, normal
completion, keyboard cancellation, NO_COLOR, and terminal-state restoration.

Public smoke tests passed for tlscert, httpinfo, doctor, ntptime, and both RIPE
RIS/NLNOG looking-glass providers. DNS comparison correctly retained successful
IPv4-resolver answers while returning failure for a configured unreachable IPv6
resolver. These public checks are manual evidence, not test-suite dependencies.

Native IPv4/IPv6 MTU checks ran in a disposable user/network namespace. Ceiling
probes succeeded; a configured isolated 1400-byte loopback MTU was discovered
exactly for both families. No host privileges or interface settings were changed.
macOS runtime behavior is covered by parser fixtures and cross-compilation; no
native macOS runtime was available during this implementation.

## Public IPv4 and IPv6 discovery (2026-09-24)

The protocol_tools ultra-effort reviewer approved brainstorming, design,
implementation, and network/display verification for concurrent family discovery.
Separate connection pools enforce tcp4/tcp6 and validate the returned family.
The first success starts enrichment immediately, while a two-second grace period
bounds the remaining family probe. Parent cancellation remains an error; a missing
family is optional when its peer succeeds. Existing JSON keys remain available.

Regression fixtures cover both reply orders, concurrent starts without redundant
requests, overlap with enrichment, fresh transports and redirects, provider loser
cancellation, mapped/scoped/nonpublic address rejection, one or both families
failing, grace cancellation, and the full deadline for the first response.
The complete vet/race suite passes. The rebuilt binary discovers both public
families on the development host in roughly 70 ms; unrelated RPKI and blocklist
provider failures remain separately reported.

Human output labels each family explicitly and calls the selected primary
address “Address used for details.” The redundant public card is omitted unless
it carries an aggregate error. A disposable rendering harness checks complete
IPv4/IPv6, scoped addresses, prefixes, and ranges at widths 1–80, and the actual
report at widths 80/100/120. It also checks unchanged JSON, legacy report display,
visible aggregate errors, and ordinary text truncation.

The follow-up `myip --interfaces` option also passed ultra-effort brainstorm,
plan, design, implementation, and verification reviews. Local inventory is
collected and included only when requested. Existing CLI/lookup/UI race tests
pass; disposable checks cover default/true/false flag forms in JSON, plain text,
and terminal rendering, flag scope/help, cancellation exit codes, and native
inventory with the option enabled. The standalone `interfaces` command is unchanged.

## Target certificate display (2026-09-24)

The protocol_tools ultra-effort reviewer approved brainstorming, design,
implementation, and verification for the `tlscert` default target-certificate
view and `--verbose` chain view. Leaf expiry is promoted to the main summary;
all other leaf fields remain visible. JSON always retains the complete chain.
Recognized expiry values wrap at narrow widths without losing the countdown.

Existing CLI/probe/UI/doctor race suites and the build pass. Disposable checks
cover leaf versus intermediate expiry, absent/zero/expired dates, widths 1–120,
complete target fields, JSON immutability, verbose flag forms and scope, trust
failure/cancellation exits, and TLS acquisition without application data.
Native `iresis.com` checks verify the summary, verbose chain, and complete JSON.

## Twelve-tool expansion (2026-09-26)

An independent `expansion_ultra_review` subagent at ultra effort reviewed each
tool's brainstorm, design, implementation and verification. The common reporting
architecture retains partial evidence, bounded parallel work, cancellation,
single-document JSON, and terminal snapshots that cannot block networking.

Detailed per-tool decisions and review evidence are recorded in:

- [Session and delegation tools](session-tools.md): watch, bandwidth, pathwatch,
  dnstrace. All four stages passed for every tool.
- [Protocol diagnostics](protocol-extra-tools.md): mailcheck, nat, dnssec, sshkey.
- [Local network tools](local-extra-tools.md): capture, dhcp, ipconflict, discover.

Cross-tool review fixed canceled DNS sockets that otherwise waited for their
deadlines, preserved failures racing monitor cancellation, rejected wrong-class
DNS aliases, and ensured changing route lengths remain visible. Adversarial
fixtures verify protocol correlation, bounded framing and parsing, partial
results, immutable snapshots, final report retention, exit codes and stdout
separation. Test details and supported-protocol limits remain in the linked
documents.

All twelve tools passed all four gates. Full repository vet and race tests passed,
as did native and Darwin arm64 builds. Native loopback tests covered raw ICMPv4,
ICMPv6, and tcpdump capture; terminal tests covered narrow/wide watch displays and
full IPv6/fingerprint rendering. No public services are required by test suites.
Review found and fixed promoted `bytes.Buffer.ReadFrom` methods that bypassed
subprocess output caps, including the existing traceroute adapter; `io.Copy`
regressions verify the limits.
