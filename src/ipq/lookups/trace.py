"""Traceroute orchestration: raw engine + enrichment + system fallback.

AIDEV-NOTE: Tries the fast parallel raw-socket engine first (requires root/CAP_NET_RAW).
Falls back to system traceroute/tracepath when unprivileged.
Enriches results with parallel reverse DNS and optional per-hop ASN lookups.
"""

import asyncio
import ipaddress
import re
import shutil
import subprocess

import dns.asyncresolver
import dns.exception
import dns.reversename

from ipq.models import TraceHop


async def run_traceroute(
    target: str,
    *,
    timeout: float = 10.0,
    count: int = 5,
    max_hops: int = 30,
    with_asn: bool = False,
) -> list[TraceHop]:
    """Run traceroute to target with parallel probing and enrichment.

    Tries raw ICMP engine first, falls back to system traceroute.
    """
    # Try the fast parallel engine first (requires root/CAP_NET_RAW)
    try:
        hops = await _traceroute_raw(target, timeout=timeout, count=count, max_hops=max_hops)
    except (PermissionError, OSError):
        import sys

        print(
            "\033[33mNote: Using system traceroute (slower, UDP). "
            "Run with sudo for fast ICMP tracing.\033[0m",
            file=sys.stderr,
        )
        hops = await _traceroute_system(target, timeout=timeout, count=count)

    if not hops:
        return hops

    # Enrich with parallel reverse DNS and optional ASN
    enrichment_tasks: list[asyncio.Task[None]] = []
    enrichment_tasks.append(asyncio.create_task(_enrich_hostnames(hops, timeout=min(timeout, 3.0))))
    if with_asn:
        enrichment_tasks.append(asyncio.create_task(_enrich_asn(hops, timeout=min(timeout, 3.0))))
    await asyncio.gather(*enrichment_tasks, return_exceptions=True)

    return hops


async def _traceroute_raw(
    target: str, *, timeout: float = 10.0, count: int = 5, max_hops: int = 30
) -> list[TraceHop]:
    """Parallel traceroute via raw ICMP sockets."""
    from ipq.lookups.trace_engine import parallel_trace

    loop = asyncio.get_running_loop()
    hop_data = await loop.run_in_executor(
        None,
        lambda: parallel_trace(target, max_hops=max_hops, count=count, timeout=min(timeout, 3.0)),
    )

    return [
        TraceHop(
            hop=h.ttl,
            ip=h.responding_ip,
            rtt_ms=round(h.avg_rtt, 2) if h.avg_rtt is not None else None,
            rtt_min=round(h.min_rtt, 2) if h.min_rtt is not None else None,
            rtt_max=round(h.max_rtt, 2) if h.max_rtt is not None else None,
            loss_pct=round(h.loss_pct, 1),
        )
        for h in hop_data
    ]


# --- Enrichment ---


async def _enrich_hostnames(hops: list[TraceHop], *, timeout: float = 3.0) -> None:
    """Parallel reverse DNS for all hop IPs."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout

    unique_ips = {h.ip for h in hops if h.ip is not None}

    async def _resolve_one(ip: str) -> tuple[str, str | None]:
        try:
            rev = dns.reversename.from_address(ip)
            answer = await resolver.resolve(rev, "PTR")
            return ip, str(answer[0]).rstrip(".")
        except (dns.exception.DNSException, ValueError):
            return ip, None

    results = await asyncio.gather(*[_resolve_one(ip) for ip in unique_ips])
    hostname_map = {ip: name for ip, name in results if name is not None}

    for hop in hops:
        if hop.ip and hop.ip in hostname_map:
            hop.hostname = hostname_map[hop.ip]


async def _enrich_asn(hops: list[TraceHop], *, timeout: float = 3.0) -> None:
    """Parallel Team Cymru ASN lookup for all hop IPs.

    AIDEV-NOTE: Reuses the same DNS-based Team Cymru approach as asn.py.
    Each IP gets two DNS queries: origin (ASN+prefix) and AS name.
    All queries run concurrently.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout

    unique_ips = {h.ip for h in hops if h.ip is not None and _is_global(h.ip)}

    async def _lookup_one(ip: str) -> tuple[str, int | None, str | None]:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version == 4:
                octets = str(addr).split(".")
                origin_q = ".".join(reversed(octets)) + ".origin.asn.cymru.com"
            else:
                expanded = addr.exploded.replace(":", "")
                nibbles = list(reversed(expanded))
                origin_q = ".".join(nibbles) + ".origin6.asn.cymru.com"

            answer = await resolver.resolve(origin_q, "TXT")
            txt = str(answer[0]).strip('"')
            fields = [f.strip() for f in txt.split("|")]
            asn_num = int(fields[0]) if fields[0].strip() else None

            name = None
            if asn_num:
                try:
                    name_answer = await resolver.resolve(f"AS{asn_num}.asn.cymru.com", "TXT")
                    name_txt = str(name_answer[0]).strip('"')
                    name_fields = [f.strip() for f in name_txt.split("|")]
                    name = name_fields[4].strip() if len(name_fields) > 4 else None
                except dns.exception.DNSException:
                    pass

            return ip, asn_num, name
        except (dns.exception.DNSException, ValueError, IndexError):
            return ip, None, None

    results = await asyncio.gather(*[_lookup_one(ip) for ip in unique_ips])
    asn_map = {ip: (asn, name) for ip, asn, name in results if asn is not None}

    for hop in hops:
        if hop.ip and hop.ip in asn_map:
            hop.asn, hop.asn_name = asn_map[hop.ip]


def _is_global(ip: str) -> bool:
    """Check if an IP is globally routable (skip private/bogon for ASN lookups)."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# --- System fallback (for unprivileged execution) ---


# AIDEV-NOTE: The original regex had a bug: `.*?` (lazy) combined with
# an optional RTT group meant RTT was never captured. This version uses
# a simpler approach: match the hop line prefix, then separately extract
# all RTT values with a second regex.
_TRACE_LINE_RE = re.compile(r"^\s*(\d+)\s+(.*)")
_RTT_RE = re.compile(r"(\d+\.?\d*)\s*ms")
_HOST_RE = re.compile(r"(\S+)\s+\(([^)]+)\)")
_TRACEPATH_HOP_RE = re.compile(r"^\s*(\d+)[?]?:\s+(.*)")


def _parse_traceroute(stdout: str) -> list[TraceHop]:
    """Parse standard traceroute output."""
    hops: list[TraceHop] = []
    for line in stdout.splitlines():
        m = _TRACE_LINE_RE.match(line)
        if not m:
            continue

        hop_num = int(m.group(1))
        rest = m.group(2)

        # Count stars and RTTs for loss calculation
        stars = rest.count("*")
        rtts = [float(x) for x in _RTT_RE.findall(rest)]
        total_probes = stars + len(rtts)
        if total_probes == 0:
            continue

        # Extract hostname and IP
        host_match = _HOST_RE.search(rest)
        hostname = host_match.group(1) if host_match else None
        ip = host_match.group(2) if host_match else None

        # If no (ip) pattern, check if the first token is an IP
        if ip is None and hostname is None:
            tokens = rest.split()
            if tokens and tokens[0] != "*":
                try:
                    ipaddress.ip_address(tokens[0])
                    ip = tokens[0]
                except ValueError:
                    hostname = tokens[0]

        if ip is None and hostname is None:
            # All stars
            hops.append(TraceHop(hop=hop_num, loss_pct=100.0))
            continue

        avg_rtt = sum(rtts) / len(rtts) if rtts else None
        min_rtt = min(rtts) if rtts else None
        max_rtt = max(rtts) if rtts else None
        loss = (stars / total_probes * 100) if total_probes > 0 else None

        hops.append(
            TraceHop(
                hop=hop_num,
                ip=ip or hostname,
                hostname=hostname if hostname and hostname != ip else None,
                rtt_ms=round(avg_rtt, 2) if avg_rtt is not None else None,
                rtt_min=round(min_rtt, 2) if min_rtt is not None else None,
                rtt_max=round(max_rtt, 2) if max_rtt is not None else None,
                loss_pct=round(loss, 1) if loss is not None else None,
            )
        )
    return hops


def _parse_tracepath(stdout: str) -> list[TraceHop]:
    """Parse tracepath output."""
    seen: dict[int, TraceHop] = {}
    for line in stdout.splitlines():
        m = _TRACEPATH_HOP_RE.match(line)
        if not m:
            continue

        hop_num = int(m.group(1))
        rest = m.group(2).strip()

        if not rest or "pmtu" in rest:
            continue
        if hop_num in seen:
            continue

        if "no reply" in rest:
            seen[hop_num] = TraceHop(hop=hop_num, loss_pct=100.0)
            continue

        host_match = re.match(r"(\S+)(?:\s+\(([^)]+)\))?", rest)
        hostname = host_match.group(1) if host_match else None
        ip = host_match.group(2) if host_match else None

        rtt_match = _RTT_RE.search(rest)
        rtt = float(rtt_match.group(1)) if rtt_match else None

        seen[hop_num] = TraceHop(
            hop=hop_num,
            ip=ip or hostname,
            hostname=hostname if hostname and hostname != ip else None,
            rtt_ms=rtt,
        )

    return sorted(seen.values(), key=lambda h: h.hop)


async def _traceroute_system(
    target: str, *, timeout: float = 10.0, count: int = 5
) -> list[TraceHop]:
    """Traceroute using system traceroute/tracepath command.

    AIDEV-NOTE: Uses subprocess.run in a thread executor instead of
    asyncio.create_subprocess_exec to avoid Python 3.12+ event-loop-closed
    errors during subprocess transport cleanup (__del__).

    The system fallback is serial so uses fewer probes (max 3) and a
    longer subprocess timeout than the CLI timeout. The -w 1 flag
    reduces per-probe wait to 1 second for faster completion.
    """
    cmd = None
    for prog in ("traceroute", "tracepath"):
        if shutil.which(prog):
            cmd = prog
            break

    if cmd is None:
        raise RuntimeError(
            "No traceroute tool available (install traceroute or run with CAP_NET_RAW)"
        )

    # Cap probes at 3 for serial execution — more would be too slow
    sys_count = min(count, 3)
    # Serial traceroute is slow: up to 30 hops × sys_count probes × 1s wait.
    # Cap at 30s — partial output is captured on timeout.
    subprocess_timeout = max(timeout, 30.0)

    if cmd == "traceroute":
        args = [cmd, "-m", "30", "-w", "1", "-q", str(sys_count), target]
    else:
        args = [cmd, "-b", "-m", "30", target]

    loop = asyncio.get_running_loop()
    stdout_bytes = b""
    try:
        completed = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: subprocess.run(args, capture_output=True, timeout=subprocess_timeout),
            ),
            timeout=subprocess_timeout + 5,
        )
        stdout_bytes = completed.stdout
    except subprocess.TimeoutExpired as e:
        stdout_bytes = e.output or b""

    stdout = stdout_bytes.decode(errors="replace")
    if cmd == "tracepath":
        return _parse_tracepath(stdout)
    return _parse_traceroute(stdout)
