# TCP streams, verified transfers, and an HTTP diagnostic server

These commands use TCP. `connect` and `listen` exchange raw bytes;
`send` and `receive` speak the ipsak transfer protocol and must be paired.
No command encrypts or authenticates the peer. SHA-256 detects transfer corruption;
it does not establish a peer's identity.

## Brainstorm and design decisions

Each command passed a separate ultra-effort sibling brainstorm review before its
design was submitted. The reviewer is the `host_tools` agent.

| Command | Alternatives considered | Chosen design and review guidance |
| --- | --- | --- |
| connect | shelling out to nc; native TCP; TCP and UDP | Native TCP duplex with stdin EOF half-closing writes, then draining the response. Preserve directional errors and cancel blocked stdin. |
| listen | single TCP session; multiple concurrent clients; UDP | One TCP connection, loopback default, actual ephemeral address announced on stderr. Byte ordering stays unambiguous. |
| send | raw copy; whole-file buffering; bounded verified frames | 64 KiB frames, SHA-256 and byte count, receiver acknowledgement only after successful output commit. Either peer may listen. |
| receive | direct overwrite; buffered validation; atomic streamed file | Same-directory private temporary file, checksum verification, race-safe no-overwrite publication; explicit replacement with `--force`. Standard output remains streaming and can contain partial bytes on failure. |
| serve | directory sharing; shell/raw HTTP; native diagnostic HTTP | Echo request metadata/body, or configured status/body/delay; bounded bodies, headers, concurrency and timeouts; graceful stop. |

The Ncat [basic usage](https://nmap.org/ncat/guide/ncat-usage.html) and
[file-transfer guide](https://nmap.org/ncat/guide/ncat-file-transfer.html) informed
the separate connection direction and payload direction. ipsak uses loopback for
an omitted bind address. Python's
[HTTP server documentation](https://docs.python.org/3/library/http.server.html)
informed the decision to make diagnostic responses explicit, without implicit
directory sharing. Implementation follows Go's
[TCP half-close](https://pkg.go.dev/net#TCPConn.CloseWrite),
[HTTP shutdown](https://pkg.go.dev/net/http#Server.Shutdown), and
[atomic no-overwrite link](https://pkg.go.dev/os#Link) contracts.

## Command contract

```
printf 'GET / HTTP/1.0\r\n\r\n' | ipsak connect example.com:80
ipsak listen 9000
ipsak receive saved.bin --listen 0.0.0.0:9000
ipsak send original.bin --connect receiver.example:9000
ipsak send original.bin --listen 0.0.0.0:9000
ipsak receive saved.bin --connect sender.example:9000
printf 'hello' | ipsak send --connect 127.0.0.1:9000
ipsak receive --listen 9000 > received.bin
ipsak serve 8080 --status 503 --body 'maintenance' --duration 1m
```

An omitted filename or `-` selects stdin for send and stdout for receive.
Exactly one of `--listen` and `--connect` is required for each transfer command.
A bare listening port binds `127.0.0.1`; `:9000`, `0.0.0.0:9000`, or `[::]:9000`
explicitly selects broader exposure. Port zero requests an ephemeral listener.

Raw payload never shares stdout with progress or metadata. `--json` produces one
final summary on stdout; connect/listen therefore require `--output PATH`, and
receive requires a filename when JSON is requested. Such invalid combinations
fail before filesystem or socket activity. Readiness and terminal progress use
stderr. Named output uses mode 0600 and defaults to refusing overwrite.

Raw streams and transfers have a command-local `--timeout`, default zero for an
unlimited session until completion or Ctrl-C. An explicit timeout bounds the
whole session, including accept time. TCP dialing has a ten-second deadline,
also bounded by any shorter session deadline. For serve, the inherited timeout
(default ten seconds) is per request; `--duration` optionally bounds server lifetime.
Interruptions produce partial summaries and exit 130; operational failures are
nonzero. A planned serve duration expires successfully.

The transfer protocol is versioned by the eight-byte `IPSAK1\r\n` magic.
Every data frame has a big-endian uint32 length, at most 65536 bytes. A zero
length ends the stream, followed by uint64 payload count and 32-byte SHA-256.
The sender half-closes its TCP write side. The receiver requires EOF, validates
count and digest, commits output, then acknowledges with `IPSAKOK1`, count and
digest. The sender succeeds only after verifying this acknowledgement. No remote
filename is accepted. A failed acknowledgement can leave a successfully committed
receiver file while the sender reports failure. Streaming stdout cannot roll
back bytes already written. `--max-bytes` optionally caps the received payload.

CLI file and pipe readers are cancellable without closing caller-owned stdin.
Embedding callers may use bounded memory readers, regular files, or the explicit
context reader interface. Unknown potentially blocking custom readers are
rejected rather than creating an unjoinable input goroutine.
Embedding output writers must return promptly; caller-owned generic writers are
never closed. CLI pipe output uses an owned descriptor duplicate and deadlines
to interrupt a blocked write. Embedding callers must not concurrently use or
change descriptor flags during a session; the original flags are restored after
all writes finish, and the original descriptor remains open.

## Review and validation evidence

The independent ultra-effort `host_tools` sibling reviewed every stage before
the next stage. Every command received an individual verdict.

| Command | Brainstorm | Design | Implementation | Test review |
| --- | --- | --- | --- | --- |
| connect | Approved | Approved | Approved; retain both TCP halves after FIN | Approved: exact binary stdout, JSON capture, half-close/drain, blocked input/output cancellation |
| listen | Approved | Approved | Approved; loopback default, one accept | Approved: actual ephemeral bind, accepted payload, cancellation and listener cleanup |
| send | Approved | Approved | Approved; ACK plus EOF, nonblocking regular-file open | Approved: file and stdin, both connection directions, empty/binary/multiframe payload, failed or missing ACK, FIFO rejection |
| receive | Approved | Approved | Approved; verify and commit before ACK | Approved: count/hash/trailer/truncation/oversize failures, byte limit, write/commit failures, atomic no-overwrite race, force replacement, symlink rejection, temporary cleanup |
| serve | Approved | Approved | Approved; bounded handler and graceful joined shutdown | Approved: echo and base64 payload, configured/empty body, 503/204/413, slow headers, released connection slots, readiness failure, finite JSON shutdown |

Follow-up reviews approved unlimited session defaults with an optional explicit
deadline and a separate ten-second dial limit; context cancellation exits 130,
whereas deadlines exit 1. Tests cover timeout flag placement, zero and fractional
seconds, pre-canceled and pre-expired JSON for all five commands, and a finite
accept deadline. A review also approved cancellable writes to inherited blocking
pipes. The regression fills a pipe before writing, cancels the blocked operation,
and checks that the caller's descriptor and original flags survive. An inherited
`/dev/null` input is recognized by device identity, regardless of filename.

Validation completed with Go 1.26.7 and `GOCACHE=/tmp/ipsak-go-build`:

- Deterministic loopback and CLI tests in `internal/stream/*_test.go` and
  `internal/cli/stream_commands_test.go` pass.
- The complete stream/CLI selection passes `go test -race -buildvcs=false`.
- `go vet ./internal/stream ./internal/cli` passes.
- The full application cross-builds for `darwin/arm64` with `-buildvcs=false`.

All network tests use local fixtures; no public service is required. Raw streams
and transfers use fixed-size buffers. Files are private until successful
completion and publication; receives additionally require integrity verification.
Failed transfers do not delete existing destinations.
