# ipsak

A little clarity for your network. A Go rewrite of the [IP Swiss Army Knife](https://github.com/linsomniac/ipsak), with concurrent lookups and a quiet, live ping monitor.

```sh
make build
./bin/ipsak info 8.8.8.8
./bin/ipsak ping example.com
```

Requires Go 1.25 or newer. Linux and macOS are supported. There is no Python runtime dependency. To install this checkout on your PATH:

```sh
go install -buildvcs=false ./cmd/ipsak
```

## Explore

| Command | What it does |
| --- | --- |
| `ipsak info <ip\|cidr\|domain>` | DNS, ASN, organization, approximate location, RDAP registration, RPKI, and DNS blocklists |
| `ipsak ping <ip\|cidr\|domain>` | Live host latency or a network sweep with responder counts and timing |
| `ipsak dns <ip\|domain>` | A, AAAA, CNAME, MX, NS, TXT, SOA, or reverse PTR |
| `ipsak whois <ip\|domain>` | IP registration through RDAP; domains resolve to an IP |
| `ipsak calc <cidr>` | Constant-space subnet arithmetic, including IPv6 `/0` |
| `ipsak trace <ip\|domain>` | System traceroute, with optional per-hop ASN enrichment |
| `ipsak myip` | Local interfaces, public-IP discovery, and full public-IP information |

`info` is now an explicit subcommand. `ipsak 8.8.8.8` explains the new invocation. Running `ipsak` alone shows help. URLs, host:port input, bracketed IPv6, internationalized domains, and IPv6 interface zones are accepted where applicable. A domain's IPv4 address is preferred, with IPv6 fallback; ping also has `-4` and `-6`.

Independent lookups start together and appear as they complete. RPKI starts as soon as ASN/prefix discovery finishes. A slow or unavailable provider leaves the other results intact. Domain DNS is independent of address resolution. Special-use IPs are classified locally and skip public information services.

```sh
ipsak info example.com --trace --timeout 15s
ipsak dns example.com --json
ipsak calc 2001:db8::/64
ipsak trace 8.8.8.8 --probes 3 --asn
ipsak myip --plain
```

## Watch a connection

```sh
ipsak ping 8.8.8.8
ipsak ping example.com -c 20 -i 250ms --timeout 800ms
ipsak ping ::1 -6 --duration 30s
ipsak ping 127.0.0.1 -c 5 --json
```

Healthy probes update one status line. A loss event adds an editable row above it; the count and inclusive ID range grow until the connection responds again. Completed events remain in scrollback, and the next outage gets a new row. For example:

```text
14:03:12  Lost 9 packets, ids 7–15 · recovered
14:08:31  Lost 2 packets, ids 42–43 · ongoing
● 8.8.8.8  ↑43 ↓32  loss 11 (25.6%)  RTT 14.20 ms  avg 13.80 ms
```

On wide terminals, a sparkline shows the last 40 outcomes; `×` marks loss. Narrow terminals use compact counters. Press **q**, **Esc**, or **Ctrl-C** to stop and leave a summary. Lookup dashboards also support **↑/↓** or **j/k** to scroll, and **g/Home** to return to the top.

Ping accounting is deliberately precise:

- IDs start at 1. `7–15` means nine packets. A session token and full logical ID protect against unrelated replies and 16-bit sequence wrapping.
- Loss means no accepted echo reply within the per-probe timeout. Out-of-order replies are folded in send order. Duplicate replies never increase received counts. ICMP error messages currently settle through the reply timeout.
- Late replies do not rewrite recorded outages. Unique late replies within the most recent 1024 committed probes are counted separately. RTT measures application send to user-space receive time.
- `--count` stops sending, then waits for every probe to receive a reply or time out. On interruption or `--duration`, unresolved probes remain **pending**. They are excluded from the lost count; loss percentage is `lost / sent`.
- Live status cannot block the ICMP receiver. Memory is bounded: 40 sparkline samples, 128 recent loss events, and a 1024-transition output queue. An indefinitely stalled output consumer stops the session with an explicit error.

Ping first tries an unprivileged ICMP datagram socket, then a raw socket. On Linux, unprivileged use depends on `net.ipv4.ping_group_range`. Where necessary, an administrator can grant the built binary `CAP_NET_RAW`:

```sh
sudo setcap cap_net_raw+ep ./bin/ipsak
```

Rebuilding replaces that capability. Raw sockets on other systems may require elevated privileges. Socket failures include the actual operating-system errors.

## Meet a network

Give `ping` a CIDR to discover which addresses respond to ICMP and compare their
latency. The default sweep sends **3 probes per address**, at up to **100 packets
per second** across the network, then leaves a summary and a table of responders.
The live display shows progress, the number of addresses that have responded,
and a preview of their ping times.

```sh
ipsak ping 192.168.1.0/24
ipsak ping 192.168.1.0/24 -c 1             # a quick sweep
ipsak ping 192.168.1.0/24 --all            # include silent addresses in the table
ipsak ping 192.168.1.0/24 -c 0 --duration 1m
ipsak ping 2001:db8::/120 -6 --json
```

`-c` counts attempts **per address**. Explicit `-c 0` watches until stopped;
without a CIDR, ping still runs continuously by default. `-i` is the minimum gap
between probes to each address, default 1s. `--rate` controls the global ceiling
(1–1000 packets/s); round duration and pending replies may make a host's actual
interval longer. Each address has at most one outstanding probe. `--timeout`
remains the individual reply deadline, default 1s.

Every address in the normalized CIDR is included, including its endpoints. For
example, `192.168.1.42/24` sweeps `.0` through `.255`; `/31`, `/32`, `/127`, and
`/128` are supported. A local send error is shown for the affected address and
the sweep continues. Prefixes containing multicast, unspecified, or limited
broadcast addresses are rejected. IPv4-mapped IPv6 CIDRs and IPv6 link-local
CIDRs (which need an interface scope) are unsupported.

The default limit is **4096 addresses**, checked before creating sockets or
expanding the range. Raise it with `--max-hosts`, up to **65536**; larger ranges,
including typical IPv6 `/64`s, need a smaller subnet. `--rate`, `--max-hosts`, and
`--all` apply only to CIDRs.

Results distinguish unique responding addresses from received packets. Each
responder has replies/sent, loss, and min/average/max RTT. The network summary
weights all timely replies equally and adds population standard deviation.
Unavailable timing is shown as unavailable, and JSON uses `null`. Silent
addresses are labeled **no reply**, because filtering can prevent ICMP responses.
In continuous mode, **responded** means at least once during the session.

Press **q**, **Esc**, or **Ctrl-C** to keep a partial report. Pending packets and
unprobed addresses remain separate from timed-out probes. `--duration` also
preserves partial results. Plain output prints a banner and final report; JSON
always includes every address. See the [research and design notes](docs/cidr-ping.md).

## Output and options

| Option | Meaning |
| --- | --- |
| `--json`, `-j` | One final JSON document on stdout; diagnostics go to stderr |
| `--plain` | Plain text, without colors or cursor control |
| `--no-color` or `NO_COLOR` | Disable color while retaining live terminal updates |
| `--timeout`, `-T` | Overall lookup deadline, default **10s**; per-probe ping timeout, default **1s** |
| `--trace`, `-t` | Include traceroute in `info` |
| `--probes`, `-q` | Probes per traceroute hop, 1–10; default 3 |
| `--asn`, `-a` | Include ASN and AS name for traceroute addresses |
| `--count`, `-c` | Probes per address; default continuous for a host, 3 for a CIDR; explicit 0 means continuous |
| `--interval`, `-i` | Minimum ping interval per address; default 1s, minimum 10ms |
| `--rate` | CIDR ping: global packets/s ceiling, default 100; range 1–1000 |
| `--max-hosts` | CIDR ping: address limit, default 4096; maximum 65536 |
| `--all` | CIDR ping: also show silent and unprobed addresses |
| `--duration` | Stop ping after an elapsed duration, such as `5m` |
| `--ipv4`, `-4`; `--ipv6`, `-6` | Select ping address family |
| `--version`, `-V` | Print the version |

Timeouts and ping intervals accept numeric seconds (`0.25`) or Go durations (`250ms`). Ping hostname resolution has a separate 10s limit. A ping timeout is at most one hour; single-host timeout/interval must allow no more than 4094 pending probes. A CIDR sweep permits at most 4096 pending probes across all addresses. The engines do not send catch-up bursts after scheduling delays.

Live rendering requires a terminal on both stdin and stdout and a non-dumb `TERM`. Redirected output has no ANSI escapes. Plain ping prints loss start/end events and a final summary, without per-packet lines. Final text reports can abbreviate long fields to fit a terminal; `--plain` and `--json` retain full values. Terminal-bound external values have control characters removed.

Exit codes: **0** for successful lookups or ping with replies and no loss, **1** for partial lookup failures or ping loss/no replies, **2** for invalid arguments and operational errors, **130** for user interruption. An elapsed `--duration` uses the normal ping result code. Partial lookup and interrupted ping JSON remain available.

CIDR sweeps use **0** when at least one address responded, even if other
addresses were silent or had send errors; **1** when none responded; **2** for
fatal errors, or no responders with local send errors; **130** for user
interruption. A duration limit uses those same result codes and marks incomplete
coverage in the report. Successful send counts exclude failed attempts.

The JSON schema is new and versioned; it does not preserve Python's field layout. See [the JSON contract](docs/json.md).

## Data sources and porting notes

DNS uses `/etc/resolv.conf`, retries truncated UDP responses over TCP, and follows bounded CNAME chains. ASN and AS names come from Team Cymru. Location uses HTTPS ipwho.is. RDAP uses IANA's IPv4/IPv6 bootstrap to select the authoritative registry over HTTPS. RPKI uses RIPEstat with the observed ASN/prefix. Public-IP discovery races ipify, icanhazip, and ifconfig.me, then cancels the remaining requests. These commands contact the named services with the queried public IP or domain and use their unauthenticated endpoints and rate limits.

Location is approximate. Classification identifies operational special-use ranges; “Public” does not assert that an address is allocated or reachable. DNSBL results distinguish listed, not listed (NXDOMAIN), and unavailable (including refusal codes and empty answers). The configured Spamhaus, SpamCop, and Barracuda zones support IPv4 only. IPv6 reputation is explicitly skipped. SORBS is not carried over. DNSBL results are evidence from the individual lists, not a general safety verdict.

Subnet counts are decimal strings in JSON so IPv6 values retain precision. IPv4 `/31` and `/32` include all addresses. IPv6 `/127` and `/128` include all addresses; broader IPv6 networks exclude the subnet-router anycast address from the displayed usable range. IPv6 has no broadcast field.

**Traceroute currently requires `traceroute` or `tracepath` on PATH.** Its system output and optional address-to-ASN/name map are retained, including partial output on timeout. `tracepath` controls its own probe count. The Python native parallel traceroute engine, reverse hop-name enrichment, and structured per-hop RTT/loss schema have not been ported; this is the deliberate exception to command-level feature coverage. RDAP extracts embedded contacts but does not fetch linked entity documents.

## Development

```sh
make build
make check              # go vet and go test -race
go test ./...
```

Tests use deterministic packet accounting, fake transports and HTTP responses, and local UDP/TCP DNS fixtures. They do not query public services or require raw sockets. The DNS fixtures need permission to open loopback sockets. CI runs on Linux and macOS. The [design notes](docs/design.md) describe concurrency, loss semantics, and the ultra-effort review process.

Licensed under [CC0 1.0](LICENSE), following the original project.
