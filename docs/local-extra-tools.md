# Local packet, DHCP, address-owner, and service diagnostics

Each tool follows its own brainstorm → design → implementation → test cycle.
The independent ultra-effort `expansion_ultra_review` agent reviews every stage.

| Tool | Brainstorm alternatives and choice | Design review | Implementation review | Test review |
| --- | --- | --- | --- | --- |
| capture | Native per-OS capture or libpcap dependency versus tcpdump acquisition plus a native bounded classic-pcap reader; chose the latter for Linux/macOS portability. Brainstorm approved. | Approved: stream matched records to private output, retain typed summaries, distinguish scanned/matched, explicit unsupported formats. | Approved: bounded packet/process parsing, joined subprocess cleanup, atomic output. | Approved: malformed/link/transport fixtures, subprocess failure/cancel/overflow, atomic and CLI tests; race passed. |
| dhcp | Configuration-only view, invoking a lease-changing client, or native discover-only probing; chose passive lease evidence plus explicit DISCOVER offers without REQUEST. Brainstorm approved. | Approved: exclusive client port, interface isolation, transaction/MAC/options validation, no offer-as-lease claims. | Approved: bounded OS lease adapters and correlated, interface-bound discover-only session. | Approved: lease formats/scope, offer/options/provenance, injected session cancellation and CLI tests; race passed. |
| ipconflict | Cached neighbor inference, native BPF, or scoped active probe adapters; chose known arping variants for IPv4 and native IPv6 NS/NA observations. Brainstorm approved. | Approved: owner observation rather than full DAD; validated provenance and target; silence is inconclusive. | Approved: flavor-specific ARP arguments, owner classification and validated native NA evidence. | Approved: adapter arguments/output, owner states, NS/NA checksums/provenance and CLI tests; race passed. |
| discover | OS-specific dns-sd/avahi commands or native mDNS; chose bounded multicast DNS-SD browse and resolution on selected interfaces. Brainstorm approved. | Approved: concurrent interface workers, bounded records/questions/TXT, complete and incomplete services, scoped IPv6 endpoints. | Approved: phased browse/resolve, scoped cache, flush grace, joined workers and immutable snapshots. | Approved: browse/resolve fixtures, cache bounds/expiry/flush, live socket cancellation and CLI tests; race passed. |

## Usage

```
ipsak capture --interface eth0 --duration 5s --protocol tcp --port 443
ipsak capture --read sample.pcap --host 192.0.2.1 --json
ipsak capture --interface en0 --write sample.pcap --count 100
ipsak dhcp
ipsak dhcp --interface en0
ipsak dhcp --lease-file dhclient.leases --json
ipsak dhcp --interface eth0 --probe --duration 5s
ipsak ipconflict 192.0.2.10 --interface eth0
ipsak ipconflict fe80::1234%en0 --interface en0
ipsak discover --interface en0 --type _ipp._tcp
ipsak discover --ipv6 --duration 10s --json
```

All commands support final structured JSON, cancellation, and nonzero operational
failures. Invalid arguments exit 2, runtime errors exit 1, and interruption exits
130. Capture, conflict observations, and discovery use a live session with a
finite observation window. An explicitly supplied `--timeout` can shorten that
window. Duration and interval flags accept seconds or Go durations, for example
`--duration 5` or `--duration 5s`. DHCP inspection/probing uses the overall lookup timeout, default ten
seconds; increase it when selecting a longer offer observation window.

## Capture

Live capture requires `tcpdump` and operating-system capture permissions. It
selects the first up non-loopback interface unless one is specified. It invokes
tcpdump directly, without a shell, disables promiscuous mode, and reads pcap
records as they arrive. Common protocol, host, and port filters apply identically
to live and offline packet summaries. Payload contents are never printed.

The reader supports classic pcap, both byte orders, microsecond/nanosecond
timestamps, Ethernet with up to two VLAN tags, BSD loopback, raw IP, and Linux
cooked v1/v2. Unsupported pcapng/link types fail explicitly. IPv4/IPv6 transport,
fragments, bounded extension headers, and ARP produce typed packet evidence.
Truncated or malformed packet headers remain visible in summaries.

Defaults: 100 matched packets, 100,000 examined records, 256 captured bytes per
live packet, five seconds. Limits: 10,000 summaries, 1,000,000 examined records,
65,535 bytes per packet, one-minute window. Packet payloads are streamed and
discarded; only summaries are retained. `--write FILE` saves matched complete
records using a private atomic output, refusing overwrite unless `--force`.
Interruption retains complete captured records when possible. stdout contains
the human/JSON report; binary pcap requires a filename.

## DHCPv4

Passive Linux inspection tries systemd-networkd lease records and NetworkManager
DHCP4 options; macOS uses `ipconfig getpacket`. Explicit lease files may contain
systemd key/value records, dhclient lease blocks, nmcli option text, or macOS
packet text. Absence of supported evidence is reported, never inferred from
static interface addresses. Lease records can be historical. This command does
not implement DHCPv6.

`--probe` requires an explicit Ethernet interface and exclusive UDP client port
68. Privileges or an existing DHCP client can prevent probing. Linux binds the
socket to the device; macOS binds its interface index. DISCOVER uses a random
transaction ID, the interface's actual hardware address, and the broadcast reply
flag. Depending on existing configuration, the UDP source address may be the
interface's current address. Up to three DISCOVER messages are sent during the observation window; DHCPREQUEST,
renewal, release, address assignment, and route/DNS changes are never performed.
Replies require matching interface, server source port, transaction, hardware
address, cookie, offer type, valid option lengths, and server/address evidence.
Offers are bounded to 64 and are distinct from accepted leases.

## Address-owner observations

IPv4 requires known iputils arping (Linux) or Thomas Habets arping (Linux/macOS,
including Homebrew). The adapter detects its argument format and rejects unknown
variants. iputils accepts only whole-second intervals; Habets supports fractional
seconds. IPv6 uses native raw ICMPv6 with an interface source address, multicast
solicited-node destination, hop limit 255, and source link-layer option. Replies
must match interface, hop limit, destination, target, type/code, checksum, and a
valid target link-layer option. Raw socket privileges are required.

This observes owners rather than implementing the complete RFC 5227/4862 DAD
state machines. One external owner means the address is in use. Multiple
different external MACs, or an external owner of an address configured locally,
produce conflict evidence and exit 1. Own-MAC observations are excluded. Proxy
ARP/NDP and virtual addressing may explain observed owners. Silence always stays
inconclusive, and the command never declares an address free or changes interface
configuration.

## Service discovery

Native mDNS sockets browse multicast UDP 5353 on up, multicast-capable interfaces.
Defaults include service-type enumeration and HTTP, HTTPS, SSH, and IPP. PTR
instances lead to SRV/TXT queries, followed by host A/AAAA queries. Independent
interfaces/families run concurrently. Results include friendly instance names,
interface, service type, target, port, TXT data and endpoints; IPv6 link-local
addresses retain interface zones. Incomplete records remain visible.

The implementation validates response source port, interface, TTL/hop limit 255,
DNS response identity/status and class with cache-flush masking. TTL-zero goodbye
records remove observations. Cache-flush announcements protect records received
within the last second and give older omitted records a one-second grace period,
preserving split RRsets. Limits include eight interfaces, sixteen explicit
types, 64 enumerated types, 1,024 cached records/one MiB per interface, 256 distinct
questions per interface, 4,096 received datagrams per interface, 256 final
services, and four KiB TXT per service. No advertised endpoint is contacted.

## Primary references

- [tcpdump's official manual source](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)
- [DHCP protocol, RFC 2131](https://www.rfc-editor.org/rfc/rfc2131)
- [DHCP options, RFC 2132](https://www.rfc-editor.org/rfc/rfc2132)
- [NetworkManager nmcli manual](https://networkmanager.dev/docs/api/latest/nmcli.html)
- [Apple ipconfig manual source](https://github.com/apple-oss-distributions/bootp/blob/main/ipconfig.tproj/ipconfig.8)
- [IPv4 conflict detection, RFC 5227](https://www.rfc-editor.org/rfc/rfc5227)
- [IPv6 duplicate address detection, RFC 4862](https://www.rfc-editor.org/rfc/rfc4862)
- [iputils arping source](https://github.com/iputils/iputils/blob/master/arping.c)
- [Thomas Habets arping manual](https://github.com/ThomasHabets/arping/blob/master/doc/arping.8)
- [Multicast DNS, RFC 6762](https://www.rfc-editor.org/rfc/rfc6762)
- [DNS-Based Service Discovery, RFC 6763](https://www.rfc-editor.org/rfc/rfc6763)

## Validation and review closure

All four tools completed independent ultra-effort review at every stage. The
review led to joined stderr inspection, propagation of subprocess failures after
packet EOF, integral iputils intervals, mDNS cache-flush grace for split RRsets,
and immutable live discovery snapshots. Testing caught a Go `io.Copy` method
promotion issue: embedding `bytes.Buffer` exposed `ReadFrom`, bypassing bounded
`Write`. Named buffer fields now enforce the limit in capture and local command
adapters; direct-copy and subprocess overflow regressions cover it.

The targeted race suite passed for `internal/localnet`, `internal/pcapture`,
`internal/dhcpdiag`, `internal/ipconflict`, `internal/discovery`, and the new CLI
tests. `go vet` passed for these packages and `internal/cli`; a Darwin arm64 build
passed. The full repository `make check` also passed. A native tcpdump loopback
smoke captured four TCP packets from a local HTTP exchange, producing typed
summaries without payload contents. Exact targeted command:

```
GOCACHE=/tmp/ipsak-go-build go test -race -buildvcs=false \
  ./internal/localnet ./internal/pcapture ./internal/dhcpdiag \
  ./internal/ipconflict ./internal/discovery ./internal/cli \
  -run 'Test(CommandOutput|PCAP|Capture|DHCP|ARP|Owner|NDP|Discovery|Local)' \
  -count=1 -timeout=60s
```

Fixtures exercise both classic-pcap byte orders/timestamp formats, supported link
headers, TCP/UDP/ARP and IPv6 extensions/fragments; atomic capture failure and
subprocess termination; DHCP options/overload, OS lease formats, interface scope
and receive provenance; both arping variants, owner classification and validated
NDP wire packets; complete/incomplete DNS-SD resolution, scoped endpoints,
malformed replies, cache limits/expiry/flush, live updates and worker cancellation.
CLI tests cover help, invalid arguments, numeric durations, structured JSON,
readable output, file safety, operational failures and cancellation exit 130.

Default tests use local packet/command fixtures and require no capture, DHCP,
ARP, or raw ICMP privileges. Active DHCP, physical-link ARP/NDP, and macOS runtime
behavior have not been tested on a physical network in this environment; the
macOS evidence is compilation plus platform-adapter fixtures.
