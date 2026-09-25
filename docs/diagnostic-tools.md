# Diagnostic command development

This expansion adds seventeen commands. Protocol, host, and stream commands have
their own development records in `probe-tools.md`, `host-tools.md`, and
`stream-tools.md`. Each command goes through brainstorm, design, implementation,
and test reviews by an independent ultra-effort agent. Review findings are
resolved before the command is considered complete.

## Shared reports

Brainstorm: extending the existing task graph and report format keeps familiar
terminal behavior, parallel queries, partial results, and script compatibility.
A separate reporting framework would add unnecessary inconsistency. The chosen
approach is a shared CLI report runner around the existing lookup task graph.

Design: independent tasks start concurrently and dependent tasks wait only for
their prerequisites. Presentation order is deterministic. One final schema-1
JSON document goes to stdout; diagnostics go to stderr. A failed diagnostic
returns 1; invalid arguments, startup, and output failures return 2; user
cancellation returns 130. Partial data survives a diagnostic error or timeout.
Interactive terminals use the existing scrollable, incrementally updated view.

Ultra brainstorm review: host_tools approved, requiring partial data retention,
argument validation before work, and separate deadline/cancellation semantics.

## doctor

Brainstorm: a shell-script wrapper would depend on several installed tools and
lose structured results. Native interface, DNS, route, TCP, TLS, and HTTP checks
offer independently useful evidence and suggestions. Route selection does not
prove the gateway responds. A host or HTTP(S) URL selects the service under test.
The default public target is explicitly documented in command help.

Design: interface inventory runs independently. Name resolution happens once;
route, TCP, TLS (for HTTPS), and HTTP checks then run concurrently. Connections
use the chosen address while retaining the original HTTP Host and TLS server
name. HTTP reads are bounded and redirects are shown without following them.
Each failed check has a specific suggestion. The default is https://example.com.

Ultra brainstorm review: host_tools approved with single resolution, correct
SNI, bounded HTTP work, and preservation of independent evidence.

## mtu

Brainstorm: parsing platform ping output is fragile. Native ICMP with explicit
don't-fragment socket settings allows careful measurement. Echoes establish a
confirmed size; packet-too-big messages or local EMSGSIZE establish upper bounds.
A timeout never proves a packet is too large.

Design: IPv4 and IPv6 raw ICMP probes include a random identifier and payload.
Replies must match the target, identifier, sequence, and token; error messages
must quote the outstanding request. Linux uses PMTU probe mode; macOS disables
fragmentation. Probe sizes include IP and ICMP headers. The search first confirms
a baseline, then tests the ceiling and narrows bounds only on explicit evidence.
Silence after bounded retries yields an inconclusive partial report. Success at
the requested ceiling means "at least", not an exact path MTU. Privilege and OS
support errors are explicit. Adaptive probes are necessarily sequential.

Ultra brainstorm review: host_tools approved with accurate bounds, validated
request matching, distinction between local/remote size errors, and header
accounting.

Protocol references: [IPv4 PMTU, RFC 1191](https://www.rfc-editor.org/rfc/rfc1191),
[IPv6 PMTU, RFC 8201](https://www.rfc-editor.org/rfc/rfc8201).

## Usage and result interpretation

```
ipsak doctor https://example.com/health --json
ipsak doctor http://127.0.0.1:8080/
ipsak mtu example.com --max 1500
ipsak mtu ::1 -6 --max 9000 --json
```

Doctor's overall deadline defaults to 10 seconds. Its HTTP body read is capped
at 64 KiB, with `read_limit_reached` exposed. Credentials, fragments, and CIDR
inputs are rejected. TLS certificate identity omits an IPv6 interface scope while
the address used for routing retains that scope. A failed check returns 1 and
keeps its diagnostic data; interruption returns 130.

MTU defaults to IPv4 baseline 576 bytes or IPv6 baseline 1280 bytes, ceiling
1500 bytes, two attempts per unanswered size, and one second per attempt, within
the overall command deadline. `--min`, `--max`, `--attempts`, `--probe-timeout`,
`-4`, and `-6` adjust these. Supported ranges are IPv4 68–65535 bytes and IPv6
1280–65535 bytes. The result distinguishes `at_least`, `exact`, `inconclusive`,
`below_minimum`, and contradictory evidence (`inconsistent`). A size hint in a
validated ICMP error can reduce the upper bound; a successful echo confirms the
lower bound. `path_mtu` is null unless the bounds converge.

Linux uses raw ICMP with PMTU probe mode. macOS uses raw ICMP with fragmentation
disabled. Socket permission failures return 2 with the capability/privilege
requirement. Per-probe cancellation interrupts socket deadlines and joins the
deadline callback before socket reuse. The socket is closed at command end.

## Review and validation record

The independent ultra-effort `host_tools` reviewer approved all four stages for
the shared report runner, doctor, and mtu. Findings resolved during review:

- Preserve partial data and distinguish deadline failure from cancellation.
- Label bounded HTTP body reads and retain failed-verification certificate data.
- Validate literal MTU destinations before socket creation; resolution failures
  still produce JSON and return 1, including preexpired deadlines.
- Correlate ICMP replies and quoted errors; never infer packet size from silence.

Deterministic race-tested fixtures cover simultaneous doctor branches, a single
resolution, pinned connections with the original HTTP Host, TLS failures,
redirects, bounded bodies, DNS failure with independent interface data, MTU
search convergence and conflicting evidence, minimum quotes and malformed
IPv4/IPv6 responses, cancellation, JSON, and exit codes.

Native Linux MTU tests ran in a disposable user/network namespace without
changing host capabilities or networking. IPv4 and IPv6 ceiling probes succeeded;
setting only the isolated loopback MTU to 1400 produced exact 1400-byte results
for both families, including rejected 1401-byte probes. The normal unprivileged
environment also confirmed the actionable permission error.

The independent ultra-effort `protocol_tools` reviewer approved brainstorm,
design, implementation, and tests for compact interactive sockets, neighbors,
and interface views. These preserve complete plain/JSON data, clean untrusted
terminal characters, and obey narrow-terminal width limits. Review removed an
unnecessary generic JSON conversion from the live rendering path.
