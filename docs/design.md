# Go implementation plan

The Go CLI uses explicit subcommands: `info`, `ping`, `dns`, `whois`,
`calc`, `trace`, and `myip`. Invoking it without arguments shows help.
Target shorthand is replaced with a helpful error pointing to `info`.

## Lookup design

`internal/lookup` owns target normalization, network providers, and a small
dependency-aware job runner. Independent providers run in goroutines and
publish immutable results through a channel. RPKI waits only for ASN; it does
not wait for location, RDAP, or reputation. Every network operation shares a
command deadline and cancellation context. Partial results and provider errors
remain visible. Private/special-use addresses skip irrelevant public services.

Commands return a documented JSON envelope with ordered sections, their source,
data, errors, and skips. This is a new schema, not Python JSON compatibility.
`calc` uses constant-space integer arithmetic for IPv4 and IPv6.

DNS uses the system nameservers with TCP retry for truncated UDP answers. ASN
uses Team Cymru, location uses HTTPS ipwho.is, RDAP discovers the authoritative
registry through IANA's bootstrap data, and RPKI uses RIPEstat. Reputation distinguishes NXDOMAIN from
timeouts, DNS errors, and provider refusal codes, and skips IPv6 lists that
only support IPv4. Public-IP discovery races HTTPS providers, then runs info.
Traceroute uses installed `traceroute`/`tracepath` with context cancellation and
explicit dependency errors; raw parallel traceroute is deferred.

## Ping design

`internal/ping` separates native ICMP transport, scheduling, and accounting.
It attempts datagram ICMP first, then raw sockets. Permission failures provide
an actionable explanation. Logical packet IDs start at 1 and never wrap at
16 bits: a random session token and full ID in the echo payload identify replies.
Responses must match the destination, token, and wire sequence.

The engine sends on an independent schedule, with bounded in-flight probes.
It captures reply times at user-space receipt, ignores duplicates/foreign packets, and
classifies timeouts by each probe's deadline. Outcomes are committed in send
order so out-of-order replies cannot fragment loss runs. Late replies do not
rewrite finalized losses. Outstanding probes on interruption are reported as
pending, not lost. A completed finite run waits for the last probe's deadline.

The expiration cutoff is captured before draining already published replies.
This prevents queued replies from becoming loss under scheduling delays; kernel
arrival times before user-space receipt are not measured. Status snapshots are
coalesced in a mutex-protected mailbox; transitions have a separate bounded queue.
If output stalls for more than 1024 transitions, the engine stops with an explicit
error. JSON retains the last 128 loss events and a lifetime event count.

Loss intervals are inclusive: IDs 7–15 represent nine packets. Each contiguous
run starts one history line, updates in place while active, and closes when the
next successful packet is committed. Counters and a bounded sparkline occupy
one live status line. Historical loss events are printed into terminal
scrollback so memory remains bounded in an indefinite session.

## Presentation and validation

Bubble Tea and Lip Gloss provide inline terminal rendering, resize handling,
color, incremental lookups, and q/Ctrl-C cancellation. Successful completion
leaves a readable report. Piped output and `--plain` contain no cursor controls;
ping prints loss start/recovery events and a final summary. `--json` emits one
final JSON document. `NO_COLOR` disables color while preserving live behavior.
Untrusted network strings are sanitized before terminal rendering.

Validate with deterministic provider HTTP/DNS fixtures, job dependency and
cancellation tests, subnet edge cases, ping reorder/timeout/duplicate/wrap tests,
CLI output tests, race detector and vet, native loopback probes, terminal
smoke tests, and Linux/macOS build checks. Ultra-effort subagents review this
plan, the detailed design, and the implementation; findings are resolved before
completion.
