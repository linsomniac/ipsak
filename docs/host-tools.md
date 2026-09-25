# Host network tools

All five commands use the version 1 `lookup.Report` JSON envelope. `--json`
produces one final document, retaining partial data on failure. `--timeout`
bounds the whole operation. Cancellation returns 130, operational failure 1,
and malformed arguments 2. Plain text uses the shared escape-free renderer.

System adapters use argument vectors, never a shell. Each subprocess has a
4 MiB stdout cap, 8 KiB stderr cap, and bounded pipe cleanup. Exceeding a cap
fails and cancels the subprocess. Tables also have a 20,000-row cap per adapter
or family. Independent family queries run concurrently. Missing utilities are
actionable errors; malformed records retain already parsed rows with an error.

## sockets

```sh
ipsak sockets --listening
ipsak sockets --protocol tcp --port 443 --json
```

Shows protocol, family, state, local/remote address and port, queues, and available
PID/name/file descriptor owners. Wildcard ports and unavailable queues are JSON
`null`. IPv4 and IPv6 `%interface` bindings are retained in addresses. `--port`
matches either endpoint. `--listening` selects TCP `LISTEN` and UDP `UNCONN`;
unconnected UDP is a bound socket, not proof of application readiness.

Linux requires `ss` (iproute2) and reads the current network namespace. Missing
ownership is explicitly unavailable. macOS requires `lsof` and lists accessible
process-owned socket files, one row per PID/file descriptor; kernel-only or
inaccessible sockets may be absent. macOS queue lengths are unavailable.

Brainstorm compared `/proc`, netlink, `ss`, macOS sysctl, and `lsof`. Design chose
strict numeric `ss` and NUL-delimited `lsof` adapters, separate collection,
filtering, and sorting. Tests cover IPv4/IPv6, device-bound IPv4, multiple owners,
NUL file boundaries, missing queues, conflicting fields, malformed partial rows,
and row limits. Native Linux smoke exposed device-bound IPv4 and externally
scoped `[IPv6]%interface` syntax; both have regression fixtures.

## route

```sh
ipsak route 192.0.2.1
ipsak route 2001:db8::1 --json
```

Reports the selected address, interface, source, gateway or on-link next hop,
and matching prefix when available. Domains use the shared system resolver,
which prefers IPv4. Route selection does not prove host or gateway reachability.

Linux requires `ip`, querying selected routes and `fibmatch` independently.
Optional matching-prefix failure is a note; missing route selection is an error.
macOS uses numeric `route -n get`. If no source is returned, UDP connection
setup asks the kernel without sending a packet. This fallback is labeled with
its possible policy-routing difference. Unknown source/prefix is `null` with a
note; a direct route has a null gateway and `next_hop_kind: on-link`.
macOS local, reject, and blackhole flags are preserved; reject/blackhole routes
retain their details while returning an operational failure.

Brainstorm compared source-only UDP setup, `/proc`, and OS selection. Design
chose authoritative OS selection and optional matching detail. Tests cover
gateways, sources, local/on-link routes, malformed required data, Darwin netmasks
and scoped IPv6 defaults, and preflight unicast/CIDR validation. Linux loopback
route selection is also exercised natively.

## interfaces

```sh
ipsak interfaces
ipsak interfaces --interface eth0 --sample 1s --json
```

Shows index, addresses, flags, administrative up state, MAC, and MTU. Linux also
reports sysfs operational state and byte, packet, error, and drop counters.
Other systems explicitly mark unavailable counters. Address enumeration errors
preserve interface data but fail the section.

`--sample` accepts 100ms–30s within the overall deadline and computes rates from
actual monotonic elapsed time. Resets, wraps, identity changes, and missing
counters produce unavailable rates. Disappeared interfaces retain their first
snapshot with an explicit status.

Brainstorm compared command adapters, stdlib inventory, continuous watch, and
bounded sampling. Design chose stdlib plus Linux counters and two snapshots.
Tests cover counter fixtures, rates, resets, disappearance, identity changes,
cancellation, and invalid sampling arguments. Linux inventory is tested natively.

## neighbors

```sh
ipsak neighbors --json
ipsak neighbors --ipv6 --interface en0
```

Shows cached ARP/NDP address, interface, link address, state, and router flag.
Unknown link addresses are `null`; incomplete and failed entries are retained.
Linux requires JSON `ip neighbor show`. macOS queries `arp -an` and `ndp -an`
concurrently unless one family is selected. A failed family preserves the other
family's data while failing the section. Cache presence does not prove liveness;
the command performs no active discovery.

Brainstorm compared IPv4-only `/proc`, OS tools, and routing sockets. Design
selected adapters covering both families with explicit cache states. Tests cover
Linux JSON, incomplete entries, Darwin one-digit MAC octets, permanent/state/
router fields, scopes, malformed data, and empty caches. Linux native cache
retrieval is also verified.

## wake

```sh
ipsak wake 00:11:22:33:44:55
ipsak wake 00:11:22:33:44:55 --destination 192.0.2.255 --count 3 --interval 100ms
```

Sends a 102-byte magic packet through IPv4 UDP, default `255.255.255.255:9`.
MACs must have six octets and be nonzero individual addresses. The destination
must be numeric IPv4 unicast or broadcast; ports are 1–65535. Count is 1–100,
interval 10ms–1m. `--interface` selects an up interface's IPv4 source address;
the OS still chooses the outgoing route. Broadcast is explicitly enabled on
Linux/macOS. Cancellation closes the owned socket and interrupts pacing.
Successful writes are counted exactly and never imply delivery or device wake-up.

Brainstorm compared raw Ethernet and UDP packets. Design chose portable UDP,
bounded pacing, and cancellation. Tests verify every payload byte, invalid MACs
and options, exact repeated loopback packets, partial counts after cancellation,
and clean CLI JSON. Tests do not wake physical machines.

## Independent review and validation

An ultra-effort sibling (`protocol_tools`) reviewed each command separately at
brainstorm, design, implementation, and test stages. macOS adapters received
additional brainstorm/design reviews. Review changes included explicit unknown
fields, partial failures, source/gateway family checks, prefix containment,
address error propagation, and scoped IPv4 endpoint parsing.

The overflow test caught promoted `io.ReaderFrom` bypassing an embedded buffer's
`Write` cap. The corrected buffer exposes only bounded writes. A helper
subprocess regression test exceeds the cap and verifies cancellation.

```sh
GOCACHE=/tmp/ipsak-go-build go test -race -buildvcs=false ./internal/hostnet ./internal/cli \
  -run 'Test(Socket|Route|Neighbor|Darwin|Interface|Counter|Magic|Wake|BoundedCommand|Host)' -count=1
```

Darwin adapters are fixture-tested and cross-built from Linux. Native macOS
execution is unavailable in this environment and is not claimed as tested.

## Primary references

- [Go net package](https://pkg.go.dev/net): inventory and UDP APIs.
- [iproute2 ss](https://man7.org/linux/man-pages/man8/ss.8.html): socket tables and process fields.
- [iproute2 route](https://man7.org/linux/man-pages/man8/ip-route.8.html): selected routes and `fibmatch`.
- [iproute2 neighbors](https://man7.org/linux/man-pages/man8/ip-neighbour.8.html): cache states and families.
- [lsof upstream manual](https://github.com/lsof-org/lsof/blob/master/Lsof.8): field identifiers and NUL boundaries.
- [Apple route manual](https://github.com/apple-oss-distributions/network_cmds/blob/main/route.tproj/route.8).
- [Apple ARP source](https://github.com/apple-oss-distributions/network_cmds/blob/main/arp.tproj/arp.c) and [NDP source](https://github.com/apple-oss-distributions/network_cmds/blob/main/ndp.tproj/ndp.c): native formats.
