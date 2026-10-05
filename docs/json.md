# JSON contract (schema version 1)

`--json` emits one document on stdout at completion. Progress and terminal
escapes are absent. Errors are also described on stderr with a nonzero exit code.
Argument, startup, and output-writer failures can occur before a document exists.

Lookup and finite diagnostic commands use the same report envelope:

```json
{
  "schema_version": 1,
  "command": "calc",
  "target": "192.0.2.0/31",
  "sections": [
    {
      "key": "subnet",
      "title": "Subnet",
      "source": "local calculation",
      "status": "ok",
      "data": {
        "cidr": "192.0.2.0/31",
        "network": "192.0.2.0",
        "broadcast": "192.0.2.1",
        "netmask": "255.255.255.254",
        "wildcard": "0.0.0.1",
        "first_host": "192.0.2.0",
        "last_host": "192.0.2.1",
        "addresses": "2",
        "usable": "2",
        "ip_version": 4
      },
      "duration_ms": 0
    }
  ]
}
```

Sections remain in presentation order, independent of completion order. Keys are
stable machine identifiers; titles and source descriptions are presentation text.
Final status is `ok`, `error`, or `skipped`. An `error` string explains unsuccessful
sections. A section can have both `data` and `error` when partial data is useful.
`duration_ms` includes time waiting for dependencies. No final section is pending.

| Section key | Data |
| --- | --- |
| `target` | Normalized `name`, `kind`, chosen `ip`, `classification` |
| `dns`, `ptr` | `records`: record-type keys with string arrays; `errors`: per-type failures |
| `asn` | Numeric `asn`, `prefix`, `country`, `registry`, `allocated`; optional `other_origins` |
| `asn_name` | `name` of the primary ASN |
| `geo` | `ip`, country/region/city, coordinates, connection ISP/org, timezone ID |
| `whois` | Network `name`, `handle`, `range`, country, organization, embedded abuse contacts and dates |
| `rpki` | `asn`, `prefix`, `status`: `valid`, `invalid`, `invalid_asn`, `invalid_length`, or `unknown` (no ROA) |
| `reputation` | Array of zone results: `zone`, `status`, optional return `codes` and `error` |
| `subnet` | Arithmetic network range; address and usable counts are strings |
| `trace` | `engine`, raw `output`, optional `networks` map, enrichment `errors`, `note`, `truncated` |
| `local` | With `myip --interfaces`: `hostname`, interfaces with `name` and `addresses` (including CIDR prefixes) |
| `public` | Discovered `ip` and HTTPS `source` |
| `public_ipv4`, `public_ipv6` | Each family's discovered `ip` and HTTPS `source` |

`myip` probes IPv4 and IPv6 concurrently with separate connection pools, racing
providers within each family. Both addresses appear in their named sections.
`public` retains the first successful response for compatibility; `target` is
that same address, used for the detailed DNS, registration, and location lookups.
The display calls it **Address used for details** and omits the redundant `public`
card unless discovery fails. JSON retains every section and complete address.
`local` is included only with `--interfaces`; local interfaces are omitted by
default from terminal, plain text, and JSON output. The report has no input `target`.

Detailed lookups start as soon as either family succeeds. The other family gets
up to two more seconds, within the overall `--timeout`. An unavailable family is
`skipped` when the other succeeds; it does not by itself cause a nonzero exit.
If both fail, discovery is an error. Overall cancellation/deadlines remain errors.
HTTPS proxy settings are honored: the forced connection family then applies to
the proxy, and results describe the public egress seen by the provider. A provider
response must still match the requested address family.

Multi-origin RPKI validates the primary observed origin only; other origin ASNs
remain visible in `asn.other_origins`.

## Additional diagnostic sections

These retain schema version 1 and the envelope above. Independent queries run
concurrently and retain deterministic presentation order. Failure can include
useful `data`; inspect section status before interpreting a result as successful.

| Command / section key | Data contract |
| --- | --- |
| `doctor`: `interfaces`, `dns`, `route`, `tcp`, `tls`, `http` | Each check has `summary`, optional typed `details`, and `hint` on failure. `tls` is omitted for HTTP targets. A DNS failure skips dependent checks while preserving interface results. |
| `tlscert`: `tls` | `address`, `server_name`, negotiated `protocol`/`cipher`/`alpn`, `trusted`, optional `verification_error`, `revocation_checked: false`, and ordered `certificates` with subject, issuer, serial, names, validity dates, SHA-256 fingerprint, and CA flag. |
| `httpinfo`: `http` | Ordered `hops`, `final_url`, `body_limit`. Each hop includes URL, HTTP status, protocol, headers, remote address, body byte count/truncation, timing fields, and optional error. Body content is discarded. |
| `dnscheck`: `dnscheck` | `name`, ordered resolver/type `queries`, per-type `comparisons`, and `note`. Queries include RCODE, flags, transport, duration, answers (name/type/TTL/value), and optional error. Comparisons distinguish agreement, disagreement, and insufficient data; no local DNSSEC validation is claimed. |
| `mtu`: `mtu` | `address`, `ip_version`, `conclusion`, nullable `largest_confirmed`, `upper_bound`, `smallest_rejected`, `path_mtu`, `requested_max`, ordered `probes`, and `note`. Probe status is `reply`, `too_big`, `timeout`, or `error`; size failures distinguish local socket from remote source. |
| `sockets`: `sockets` | `sockets`, `count`, `notes`. Each row contains protocol/family/state, local/remote address and nullable port, nullable queues, processes (PID/name/FD), and process-availability status. |
| `route`: `route` | Destination/address/interface, nullable source/gateway/matching prefix, `source_method`, `next_hop_kind`, route type/table, and notes. Missing gateway alone does not indicate failure; a route may be local or on-link. |
| `interfaces`: `interfaces` | Ordered `interfaces` and notes. Rows contain identity, flags, addresses, MTU, state, nullable counters/throughput and explicit availability status. Counter reset or missing samples never produce invented rates. |
| `neighbors`: `neighbors` | `neighbors`, `count`, `note`. Rows include address/family/interface, nullable MAC, states, and router flag. An empty cache is a valid result. |
| `wake`: `wake` | MAC, destination, optional source/interface, requested/sent packet counts, packet size, and explicit lack of confirmed delivery/wake-up. |
| `lookingglass`: `lookingglass_N_PROVIDER` | Provider/source URL/resource, observation times, normalized `routes`, total count/truncation, `has_routes`, warnings, and scope. `N` is the one-based requested-provider order. |
| `ntptime`: `ntp` | Server/address, version/leap/stratum, reference or kiss code, client/server timestamps, offset/delay/root metrics, validity, and `authenticated: false`, `clock_changed: false`. |

MTU `conclusion` is `at_least`, `exact`, `inconclusive`, `below_minimum`, or
`inconsistent`. Only `exact` has a non-null `path_mtu`. A confirmed ceiling is a
lower bound; a timeout does not create an upper bound. Sizes include IP and ICMP
headers. Resolution failure can instead produce a `target` error section;
raw-socket startup failure can occur before JSON exists.

HTTP timings are milliseconds. `first_byte_ms` measures elapsed time from request
start, and `total_ms` includes bounded body reading; the components should not be
summed as disjoint intervals. Connect timing can include parallel dial attempts.
NTP offset/delay fields are meaningful only when `valid` is true. DNS AD is a
resolver assertion. Empty looking-glass observations do not establish global
route absence. See the [protocol](probe-tools.md) and [host](host-tools.md)
contracts for platform and provider details.

`tlscert --verbose` changes human output only: the default shows the target
certificate, while verbose adds the presented chain. JSON always retains the
complete `certificates` array and its original validity timestamps. The summary's
human-readable `expires` row uses the target certificate's `not_after`, including
days remaining; it is not a separate JSON field.

## Streams and servers

`connect`, `listen`, `send`, `receive`, and `serve` emit one final summary when
`--json` is selected:

```json
{
  "schema_version": 1,
  "command": "send",
  "status": "ok",
  "local": "127.0.0.1:40000",
  "remote": "127.0.0.1:9000",
  "elapsed_seconds": 0.02,
  "stream": {
    "bytes_sent": 5,
    "bytes_received": 0,
    "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "verified": true,
    "committed": true
  }
}
```

Optional `output` identifies a named destination and `error` explains failure.
`status` is `ok`, `error`, or `interrupted`. Stream counters count payload bytes,
not framing. Raw connections do not claim checksum verification. A sender's
`verified` means a matching acknowledgement arrived after receiver commit; the
receiver's `committed` records its output commit; on the sender, `committed`
records the acknowledged receiver commit. Streaming stdout cannot roll
back already-written bytes. Named output is published only after successful
completion, with explicit `--force` needed to replace an existing file. `receive`
also requires integrity verification; raw `connect`/`listen` captures commit
after duplex completion without claiming checksum verification.

`serve` uses `server` instead of `stream`, containing its listening address and
request/rejection/error counts. A configured server duration completes normally; user interruption
returns 130 with a partial summary. Stream operations default to no overall
deadline (`--timeout 0`); explicit timeouts and expired parent deadlines return 1.
Argument errors and report-write failures return 2.

Payload never shares stdout with JSON: `receive --json` requires a filename;
`connect --json` and `listen --json` require `--output FILE`. Invalid combinations
fail before filesystem/socket activity. `send --json` may read stdin. Readiness
and interactive transfer progress use stderr. See [stream tools](stream-tools.md)
for the wire protocol and both connection directions.

Ping uses `{ "schema_version": 1, "command": "ping", "ping": { ... } }`:

- Counters: `sent`, `received`, `lost`, `pending`, `late`, `loss_events`.
- Timing: `last_ms`, `min_ms`, `avg_ms`, `max_ms`, `elapsed_seconds`. RTT values are
  zero when no timely reply was received.
- `loss_percent` is `100 * lost / sent`, or zero before any transmissions.
- `target`, `address`, `done`, `interrupted`, and optional `error` describe the session.
  `interrupted` includes an elapsed duration, cancellation, and keyboard stop.
- `recent_losses` contains up to 128 latest completed events. `loss_events` is the
  lifetime event count, including an open event. Terminal/plain output streams all
  completed events during normal consumption.
- Events contain inclusive `first_id`, `last_id`, `count`, RFC3339 `started`/`ended`
  timestamps, and `recovered`. An event ended by stopping has `recovered: false`.
  `active_loss` exists in live snapshots only; final events are closed without
  inventing recovery. `started` is the first lost probe's send time and a recovered
  `ended` is the subsequent successful probe's receive time.

Loss is finalized in send order. Counts distinguish timed-out probes from pending
ones; duplicate/foreign replies do not increase counters. Recent late replies are
reported without rewriting a loss. In a complete finite run `pending` is zero.

## CIDR ping

CIDR targets use `{ "schema_version": 1, "command": "ping", "sweep": {...} }`.
Host targets retain the `ping` payload above. A sweep includes:

- `cidr`: normalized prefix; `total`: all addresses including prefix endpoints.
- Settings: `count_per_address` (0 means continuous), `rate_pps`, `interval_ms`,
  `timeout_ms`, and `planned_probes` (0 in continuous mode).
- Address counts: `probed` (at least one attempted send), `completed` (all
  configured attempts settled), and the mutually exclusive categories
  `responded`, `no_reply`, `errors`, `incomplete`, `unprobed`. Their sum is `total`.
  A host that ever replied is `responded`, including when later sends fail or
  remain pending. `errors` counts hosts with failed sends and no replies;
  `no_reply` requires all attempts to have settled without replies or send
  errors. Other attempted, nonresponding hosts are `incomplete`.
- Packet counters: `attempts`, `sent`, `received`, `lost`, `pending`, `late`,
  `send_errors`. `attempts = sent + send_errors` and
  `sent = received + lost + pending`. Failed sends consume configured attempts.
- `rtt`: `null` before any timely replies, otherwise `samples`, `min_ms`,
  `avg_ms`, `max_ms`, `stddev_ms`. Aggregate statistics weight individual
  accepted replies equally; standard deviation is the population value.
- `elapsed_seconds`, `done`, `partial` (fewer than `total` addresses completed),
  optional `stop_reason` (`duration` or `interrupted`), and optional fatal `error`.
  Continuous mode always has `completed: 0` and `partial: true`.
- `hosts`: every address in numeric order, regardless of text-mode `--all`.
  Each row contains `address`, `status`, the same packet counters, `loss_percent`
  (`100 * lost / sent`, 0 before sending), nullable `rtt`, and an optional
  `error` holding the latest local send error. A row's error remains visible
  even if that address also responded.

Duplicate and foreign replies are ignored. Unique late replies are counted only
within a window of 1024 recently settled probes, without changing prior losses.
Pending probes remain pending on interruption, duration expiry, or fatal errors.
No reverse DNS or provider lookups accompany a sweep.

## Additional diagnostics and sessions

`capture`, `mailcheck`, `pathwatch`, `nat`, `dnssec`, `sshkey`, `dhcp`,
`ipconflict`, `watch`, `bandwidth`, `dnstrace`, and `discover` use the common
`schema_version: 1`, `command`, `target`, `sections` envelope. Long-running tools
emit one final JSON report on completion or interruption; intermediate snapshots
are terminal-only. Progress/readiness never shares JSON stdout. An error section
can retain useful data, and a successful observation is not a general claim of
network health.

- `watch`: target counters (`checks`, `successes`, `failures`, `pending`), last
  status/timing, bounded outage/recovery `events`, and `events_dropped`.
  `condition_met` distinguishes an achieved readiness condition from an ordinary
  end of monitoring. Earlier failures remain visible even when `--until all-up`
  eventually succeeds.
- `pathwatch`: `hops` and an independently sampled `destination`. Reply counts
  at intermediate hops do not establish transit packet loss. Pending probes are
  separate from timeouts. `reached_ttl` describes the most recent round; source
  and path-change history have explicit omission counters.
- `bandwidth`: role, peer, requested duration and sequential `phases`. Each phase
  includes direction (relative to connector), byte count, elapsed milliseconds,
  Mbps, measurement provenance and `complete`. Sender progress is provisional;
  completed measurements use receiver timing and validated byte-count receipts.
- `dnstrace`: ordered delegation/alias `hops`, per-server observations, selected
  server, records, and any `system_resolver_fallback`. Completed authoritative
  `nxdomain` and `nodata` outcomes are valid traces. `dnssec_validated` is false.
- `dnssec`: `state` is `secure`, `insecure`, `bogus`, or `inconclusive`, with a
  reason and validation chain. `resolver_ad` is observed metadata, not trusted
  evidence. Unsupported denial/alias/wildcard cases stay inconclusive.
- `capture`: retained packet summaries and scan/match counts; binary pcap output
  requires a separate filename. Retention limits and malformed/truncated packets
  are visible. Payload bytes are not printed in reports.
- `dhcp`: passive lease evidence and, only with `--probe`, separately identified
  offers. An offer is not an acquired lease. Historical evidence is not proof
  of current configuration.
- `ipconflict`: observed owners and explicit conflict/in-use/inconclusive
  interpretation. Silence never establishes that an address is unused.
- `discover`: advertised service instances with interface/family scope, SRV/TXT
  information, addresses/endpoints, and incomplete results where resolution did
  not finish. Discovering a service does not test endpoint reachability.
- `nat`, `mailcheck`, and `sshkey` retain observations, provenance and failures
  for their respective protocol checks. NAT mappings do not imply a definitive
  NAT classification, mail configuration does not imply deliverability, and an
  observed SSH fingerprint requires a trusted comparison to establish identity.

Argument/output errors remain exit 2 and user interruption exit 130. Finite
sessions have command-specific success criteria documented in
[session tools](session-tools.md), [protocol tools](protocol-extra-tools.md), and
[local tools](local-extra-tools.md). In particular, a planned duration does not
itself signal failure, while a monitor with no completed checks does not succeed.

Consumers should ignore unknown fields and optional sections. Check status before
assuming a section has data. Counts wider than JavaScript's safe integer range
need a JSON decoder that preserves integers (subnet counts are already strings).
