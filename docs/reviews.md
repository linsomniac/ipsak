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
