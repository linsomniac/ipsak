# Mail, STUN, DNSSEC, and SSH diagnostics

These commands use the same finite report envelope as `dnscheck`: one JSON
document with schema version, ordered sections, partial evidence, and explicit
errors. `--timeout` bounds the complete report. Ctrl-C cancels network work.
Individual DNS, SMTP, STUN, and SSH operations also have short upper bounds.
All implementations are native Go and support Linux and macOS.

Interactive summaries keep policy states, alias provenance, errors, mapping
comparisons, validation chains, and complete SSH fingerprints visible. Encoded
DKIM keys, DNSSEC signature bodies, and SSH public-key blobs are omitted only in
the compact view. Plain and JSON output retain every field.

| Command | Examples | What the result establishes |
| --- | --- | --- |
| `mailcheck` | `ipsak mailcheck example.com --selector selector1 --json`; `ipsak mailcheck example.com --starttls` | Published exact-domain MX, SPF, DMARC, and optional DKIM TXT records; optional greeting/EHLO and verified STARTTLS on up to three MX hosts |
| `nat` | `ipsak nat --json`; `ipsak nat --server stun.example.com:3478` | Server-reported public UDP mappings on a shared socket per address family |
| `dnssec` | `ipsak dnssec example.com --type A --resolver 1.1.1.1 --json` | Local cryptographic verification of the supported exact-owner positive RRset and its DNSKEY/DS chain to bundled IANA root anchors |
| `sshkey` | `ipsak sshkey example.com`; `ipsak sshkey example.com:2222 --fingerprint SHA256:… --json` | One host key presented during an SSH handshake, its SHA256 fingerprint, and optional equality to a supplied fingerprint |

## Interpretation and limits

`mailcheck` starts up to four DNS lookups concurrently against the first system
resolver, or the numeric `--resolver` override. It joins split TXT strings and
distinguishes missing records, NXDOMAIN, and query errors. Multiple SPF, DMARC,
or DKIM policy records fail with their evidence retained. Only exact-owner IN
records are accepted. Each lookup follows at most eight CNAME aliases within one
two-second budget, reusing in-message target records or querying the target.
Original and canonical names are reported. Conflicting aliases, loops, and
same-owner alias/data combinations fail explicitly. SPF version selection is
case-insensitive and requires a space or end-of-record after `v=spf1`, following
[RFC 7208 record selection](https://www.rfc-editor.org/rfc/rfc7208.html#section-4.5).
A valid null MX is the
sole `MX 0 .` record. Mixed or nonzero-preference null MX records fail and suppress
SMTP. No implicit A/AAAA mail routing fallback is probed. DKIM selectors are
supplied explicitly and never guessed. The snapshot does not evaluate SPF
includes, organizational-domain DMARC fallback, DKIM signatures, or delivery.

SMTP is opt-in. `--starttls` implies SMTP, requires STARTTLS advertisement, and
validates TLS identity and trust. `--smtp-port` defaults to 25. At most three MX
hosts, ordered by preference and name, are contacted concurrently for three
seconds each. Only the greeting, a fixed `EHLO ipsak.invalid`, and optionally
STARTTLS plus a second EHLO are exchanged. No authentication, recipients, or
messages are sent. SMTP responses are limited to 64 KiB per plaintext/TLS phase.

`nat` supports up to eight STUN servers. Each hostname uses its first resolved
address, without fallback to additional addresses. IPv4 and IPv6 use separate
sockets and separate comparisons. Transactions use random IDs, source-endpoint
checks, bounded retransmission, complete-datagram parsing, IPv4/IPv6
XOR-MAPPED-ADDRESS, and legacy MAPPED-ADDRESS. Server errors and malformed replies
remain associated with their original server. STUN observations are
unauthenticated. Equal mappings, different mappings, and insufficient observations
are reported without declaring a NAT type or inbound reachability.

`dnssec` queries with DO and CD, using the recursive resolver as untrusted
transport. It checks signatures, validity times, complete RRsets, signer ancestry,
DNSKEY protocol/zone/revocation flags, and authenticated DS digests. Supported
algorithms are RSA/SHA256, RSA/SHA512, ECDSA P-256/P-384, and Ed25519; supported
DS digests are SHA256 and SHA384. Validation is bounded to 32 queries, 16 chain
levels, and ten seconds, further shortened by `--timeout`. Its states are:

- `secure`: positive exact-owner data verified to a bundled root anchor.
- `insecure`: an authenticated parent-zone exact NSEC proves an unsigned
  delegation. The answer data itself is not authenticated.
- `bogus`: supported signatures, validity dates, or DS/key matches failed in the
  supported validation path.
- `inconclusive`: insufficient data, transport failures, unsigned data without a
  supported proof, unsupported algorithms, CNAME/DNAME paths, wildcard expansion,
  general negative answers, or NSEC3 denial. An AD bit never changes this outcome.

The answer list contains only the exact requested owner, IN class, and type plus
its covering signatures. Unrelated resolver-supplied records never appear beside
a secure result. Common unsigned answers without a supported authenticated
delegation proof remain inconclusive.

Inconclusive and bogus results exit unsuccessfully while preserving observations.
Secure and authenticated insecure results complete successfully. The root anchor
snapshot was checked against [IANA's authoritative XML](https://data.iana.org/root-anchors/root-anchors.xml)
over HTTPS on 2026-09-26: key tags 20326 (KSK-2017) and 38696 (KSK-2024). Anchor
updates require a reviewed release; there is no RFC 5011 automatic update.

`sshkey` uses `golang.org/x/crypto/ssh` to perform key exchange and verify the
server's key-exchange signature. An explicit callback sentinel stops the
handshake before authentication. This proves possession of the reported key;
matching a supplied fingerprint compares that key with the supplied pin. Identity
trust depends on how the pin was obtained. Only one negotiated key is observed; this does not
enumerate every host key or consult known_hosts. Pins must be canonical OpenSSH
`SHA256:` fingerprints. A mismatch retains the observed key and exits with an
error. The complete handshake has a five-second upper bound.

## Protocol references

Implementation decisions follow [DNSSEC validation, RFC 4035](https://www.rfc-editor.org/rfc/rfc4035.html),
[STUN, RFC 8489](https://www.rfc-editor.org/rfc/rfc8489.html), and the
[IANA trust anchor publication](https://www.iana.org/dnssec/files).

## Review record

The independent reviewer is `/root/expansion_ultra_review`, running with ultra
reasoning. Each tool advances separately through brainstorm, design,
implementation, and test review gates.

| Tool | Brainstorm | Design | Implementation | Tests |
| --- | --- | --- | --- | --- |
| mailcheck | PASS | PASS | PASS | PASS |
| nat | PASS | PASS | PASS | PASS |
| dnssec | PASS, narrow validator scope | PASS | PASS | PASS |
| sshkey | PASS | PASS | PASS | PASS |

Initial implementation review corrections already incorporated exact DNS owner
and class filtering, strict null MX handling,
malformed-policy errors, and complete UDP datagram reads.

## Fixture validation

All automated protocol tests use generated keys and loopback servers, without
public DNS, SMTP, STUN, or SSH dependencies. Loopback socket tests require the
environment's normal local-network permission.

| Tool | Verified behavior |
| --- | --- |
| mailcheck | Four concurrent DNS lookups; UDP-to-TCP fallback and in-flight cancellation; split TXT strings; missing/NXDOMAIN/SERVFAIL; unrelated owner and class rejection; inline and followup aliases, canonical MX, loops/conflicts/coexisting-data rejection, eight-alias limit and target cancellation; case-insensitive SPF with strict version termination; duplicate policy errors; valid, mixed and nonzero null MX; SMTP command restrictions; successful trusted STARTTLS, untrusted certificate rejection, missing STARTTLS, bounded input and stalled-server cancellation |
| nat | IPv4/IPv6 XOR and legacy mapping decode; server errors; malformed lengths, attributes and fingerprints; wrong transaction/source rejection; same source socket at two servers; partial failure and cancellation |
| dnssec | Generated root/child chain with actual signatures; secure result and TCP fallback; tampered/expired signatures, DS mismatch and incomplete RRsets; unsupported algorithms, AD-only unsigned answers, wildcard and wrong signer/class limits; DNSKEY protocol/zone flags; authenticated exact NSEC and forged/wrong-bitmap/owner/self-signed denial rejection; pre-cancellation, in-flight cancellation and missing answer; unrelated records excluded from secure output |
| sshkey | Real SSH key exchange; observed/pinned/mismatched fingerprints; strict pin syntax; no authentication requests; stalled handshake cancellation and connection closure |

CLI fixtures verify command help, invalid arguments, default mailcheck without a
selector, stable JSON envelopes on success and failure, retained mismatch evidence,
AD-only DNSSEC remaining inconclusive, and exit 130 on cancellation for all four.

Executed successfully:

```text
GOCACHE=/tmp/ipsak-go-build go test -race ./internal/mailcheck ./internal/dnssec ./internal/sshkey
GOCACHE=/tmp/ipsak-go-build go test -race ./internal/natprobe
GOCACHE=/tmp/ipsak-go-build go test -race ./internal/cli -run '^TestProtocolExtra'
GOCACHE=/tmp/ipsak-go-build go vet ./internal/mailcheck ./internal/natprobe ./internal/dnssec ./internal/sshkey
GOOS=darwin GOARCH=arm64 GOCACHE=/tmp/ipsak-go-build go build ./internal/mailcheck ./internal/natprobe ./internal/dnssec ./internal/sshkey
```

The initial race run detected STUN grouping reading observations after a worker
started updating them. Group membership is now collected before either socket
worker starts, and the rerun passes under the race detector.

The ultra reviewer independently reran all four native suites with the race
detector, inspected the CLI fixtures and additional transport regressions, and
approved all four final test gates. The reviewer also verified in the SSH library
source that exchange-signature verification precedes the host-key callback.

An integration audit then requested DNSSEC output scoping and common mail CNAME
support. The ultra reviewer approved the amendment designs and implementations;
new adversarial fixtures and protocol CLI checks pass under the race detector.
The reviewer approved both amended test gates, including CLI alias provenance;
the final CLI rerun, vet, and Darwin arm64 build pass. No review blockers remain.

A final presentation amendment adds fresh `CompactLines` summaries to all four
results. Its designs and implementations passed ultra review. A disposable
harness exercised the actual renderer at widths 24, 40, and 80, confirming full
IPv6/fingerprint recovery, visible errors and provenance, terminal-control
sanitization, fresh returned slices, and unchanged raw JSON/plain evidence.
The ultra reviewer approved presentation verification individually for all four
tools; vet and Darwin arm64 builds also passed. No presentation review blockers
remain.
