# JSON contract (schema version 1)

`--json` emits one document on stdout at completion. Progress and terminal
escapes are absent. Errors are also described on stderr with a nonzero exit code.
Argument, startup, and output-writer failures can occur before a document exists.

Lookup commands (`info`, `dns`, `whois`, `calc`, `trace`, `myip`) use:

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
| `local` | `hostname`, interfaces with `name` and `addresses` (including CIDR prefixes) |
| `public` | Discovered `ip` and HTTPS `source` |

`myip` includes `local` and `public`, followed by normal info sections. It has no
input `target`. Multi-origin RPKI validates the primary observed origin only; other
origin ASNs remain visible in `asn.other_origins`.

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

Consumers should ignore unknown fields and optional sections. Check status before
assuming a section has data. Counts wider than JavaScript's safe integer range
need a JSON decoder that preserves integers (subnet counts are already strings).
