# CIDR ping: design and research

`ipsak ping 192.168.1.0/24` should answer two questions at a glance: how many
addresses responded, and how long did their replies take?

## Research and choices

- [fping](https://www.fping.org/fping.8.html) schedules multiple targets round
  robin, separates global packet spacing from each host's probe interval, and
  reports per-host response statistics. Its CIDR generation omits IPv4 network
  and broadcast addresses. We use paced round-robin scheduling and per-address
  statistics, but include every address in the supplied CIDR as requested.
- [Nmap host discovery](https://nmap.org/book/man-host-discovery.html) can use
  ARP, neighbor discovery, TCP, and ICMP. Our result specifically measures ICMP
  echo responses. Silence is labeled **no reply**, never **down**.
- [gping](https://github.com/orf/gping) makes multiple hosts' latency glanceable
  with a live graph. A subnet needs a bounded progress display and readable
  responder table; hundreds of overlapping graph lines would obscure the answer.

The selected experience is a finite sweep by default. An endless default makes
it difficult to know when the network has been covered. Three probes per address
give a small latency sample and expose intermittent replies. A single host keeps
its existing continuous default. No reverse DNS or unrelated lookups delay results.

## Command contract

- CIDRs are normalized and all addresses, including endpoints, are attempted in
  numeric order each round. IPv4 `/31` and `/32`, IPv6 `/127` and `/128` work.
- Default `--count` is 3 per address for CIDRs; explicit `-c 0` watches until
  stopped. `-c 1` is a quick sweep. `--interval` retains its meaning as the
  minimum interval between probes of an individual address, default 1 second.
- CIDR-only `--rate` caps the whole sweep at 100 packets/second by default
  (1–1000 allowed). Scheduling never catches up with bursts. At most one probe
  per address and 4096 total probes are outstanding; rate is a ceiling.
- `--timeout` remains a per-probe deadline, default 1 second. Finite completion
  drains every outstanding probe. `--duration`, q, Esc, and Ctrl-C preserve
  partial results, pending packets, and addresses not yet probed.
- CIDR-only `--max-hosts` defaults to 4096 and can be raised to 65536. Size is
  checked before allocation or socket creation. Larger IPv6 ranges receive an
  actionable error to choose a smaller subnet. Multicast, unspecified, limited broadcast,
  IPv4-mapped IPv6 prefixes, and IPv6 link-local ranges without an interface
  scope are rejected explicitly.
- Per-address send errors are retained and other addresses continue. Socket
  receive errors stop the sweep. Failed sends are distinct from timed-out probes.

## Presentation and data

The live view shows settled-probe progress, responded-address count, elapsed
time, aggregate RTT, and a bounded preview of responding addresses. It adapts
to terminal size. The final report lists responding addresses in numeric order
with replies/sent, loss, and min/avg/max RTT, plus summary counts. Send errors
are always shown, including on addresses that also responded. `--all` adds
silent, incomplete, and unprobed addresses. Output uses words as
well as color. Plain output has a starting banner and final report; JSON has
only one final document and always includes all addresses.

For example, this plain report came from the IPv4 loopback smoke test
(`ipsak ping 127.0.0.0/30 -c 2 -i 10ms --plain`; timings vary):

```text
ipsak  /  PING SWEEP  ·  127.0.0.0/30
4 addresses · 2 attempts/address · up to 100 packets/s
every 10ms/address or slower · timeout 1s · Ctrl-C to stop

Finished · 127.0.0.0/30 · 0.1s
4 of 4 addresses responded · 0 no reply
8 sent · 8 received · 0 lost
RTT min/avg/max/stddev = 0.032/0.089/0.216/0.072 ms

ADDRESS    REPLIES/SENT     LOSS           MIN/AVG/MAX (ms)  STATUS
127.0.0.0           2/2     0.0%          0.032/0.051/0.069  responded
127.0.0.1           2/2     0.0%          0.041/0.045/0.049  responded
127.0.0.2           2/2     0.0%          0.036/0.122/0.209  responded
127.0.0.3           2/2     0.0%          0.061/0.139/0.216  responded
```

Aggregate timing is weighted over accepted timely echo replies, with min, mean,
max, and population standard deviation. No replies means unavailable timing,
not a misleading zero-millisecond result. Unique responding addresses are
separate from received packets. Duplicate, foreign, and late replies never
inflate the count; late replies are counted in a bounded recent window.

CIDR JSON uses `{ "schema_version": 1, "command": "ping", "sweep": {...} }`.
Existing host-ping JSON stays unchanged. Each host retains attempts, successful
sends, replies, timeouts, pending probes, send errors, and timing. A response
means at least one accepted echo reply during the session, not current presence.

Exit codes for a CIDR are 0 when the sweep has at least one responder,
1 for no responders, 2 for argument/fatal operational errors or no responders
with local send errors, and 130 for user
interruption. A duration limit uses the normal result code while clearly marking
the result partial. Sparse networks are expected; silence at unused addresses
does not make a useful discovery sweep fail.

## Implementation and validation plan

Extend the native ICMP transport with addressed sends and source-bearing replies,
keeping the existing host interface. A separate sweep scheduler owns a single
socket, round-robin scheduling, bounded pending/recent maps, and per-address
statistics. A mutex mailbox coalesces bounded live snapshots independently of
packet receipt. Final snapshots include the complete bounded address table.

Validate range normalization and limits; IPv4/IPv6 boundaries; default/explicit
flags; per-host and aggregate accounting; duplicate, foreign, late and reordered
replies; send/read failures; pacing and cancellation; JSON and exit codes;
terminal widths and keyboard stop. Use deterministic fake transports, race/vet,
native loopback probes, PTY smoke checks, and a macOS cross-build. Ultra-effort
subagents review brainstorming, this plan, and the implementation, with findings
recorded after fixes.

The final ultra-effort review found no unresolved issues in the reviewed fixes.
See [review and validation notes](reviews.md#cidr-ping-extension).
