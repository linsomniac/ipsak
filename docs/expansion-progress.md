# Network tool expansion

Requested tools: capture, mailcheck, pathwatch, nat, dnssec, sshkey, dhcp,
ipconflict, watch, bandwidth, dnstrace, discover.

Each tool receives separate brainstorm, design, implementation, and verification
verdicts from the independent `expansion_ultra_review` agent at ultra effort.
The shared architecture review passed: preserve the versioned report envelope,
bounded concurrency and retained partial results. Session tools coalesce live
updates, join workers on cancellation, and write one final JSON document.

Implementation ownership:

- Protocol diagnostics: `expansion_protocols`; details in `protocol-extra-tools.md`.
- Local network tools: `stream_tools`; details in `local-extra-tools.md`.
- Monitoring, throughput and delegation tracing: root; details in
  `session-tools.md`.

All twelve tools passed all four review stages. Protocol presentation refinements
and the shared reporting changes also passed independent ultra review.

Integration verification passed the complete `make check` (vet and race tests),
native build, Darwin arm64 cross-build, and fixture-based command checks.
Native IPv4/IPv6 loopback pathwatch and tcpdump-backed loopback capture passed.
Terminal watch smoke checks passed at widths 40/80/120; disposable compact
rendering checks preserve full IPv6/fingerprints, sanitize controls, and leave
JSON unchanged. The fixture suites require loopback sockets but do not require
raw privileges or public services.

The review additionally fixed a promoted `bytes.Buffer.ReadFrom` method that could
bypass subprocess output limits in capture, local command adapters, and the
existing traceroute adapter. Direct `io.Copy` regressions now exercise those
limits through the same path used by `os/exec`.
