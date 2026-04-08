"""Traceroute functionality (opt-in, may require privileges)."""

import asyncio
import re
import shutil
import subprocess

from ipq.models import TraceHop


async def run_traceroute(target: str, *, timeout: float = 30.0) -> list[TraceHop]:
    """Run traceroute to target, trying multiple methods.

    Tries in order:
    1. icmplib (if installed, needs root/capabilities)
    2. System traceroute command (fallback)
    """
    # Try icmplib first
    try:
        return await _traceroute_icmplib(target, timeout=timeout)
    except (ImportError, PermissionError):
        pass

    # Fall back to system traceroute
    return await _traceroute_system(target, timeout=timeout)


async def _traceroute_icmplib(target: str, *, timeout: float = 30.0) -> list[TraceHop]:
    """Traceroute using icmplib (needs icmplib installed + root/cap_net_raw)."""
    import icmplib  # type: ignore[import-untyped]

    loop = asyncio.get_running_loop()
    result = await asyncio.wait_for(
        loop.run_in_executor(
            None,
            lambda: icmplib.traceroute(target, max_hops=30, count=1, timeout=2),
        ),
        timeout=timeout,
    )

    hops: list[TraceHop] = []
    for hop in result:
        hops.append(
            TraceHop(
                hop=hop.distance,
                ip=hop.address if hop.address != "*" else None,
                rtt_ms=hop.avg_rtt if hop.avg_rtt > 0 else None,
                loss_pct=hop.packet_loss * 100,
            )
        )
    return hops


# AIDEV-NOTE: Parses standard traceroute output format:
#   " 1  gateway (10.0.0.1)  1.234 ms  1.456 ms  1.789 ms"
#   " 2  * * *"
_TRACE_LINE_RE = re.compile(
    r"^\s*(\d+)\s+" r"(?:(\S+)\s+\(([^)]+)\)|(\*)).*?" r"(?:(\d+\.?\d*)\s*ms)?",
)

# AIDEV-NOTE: tracepath has a different output format from traceroute.
# Hop lines: " 1:  hostname (ip)  0.630ms" or " 2:  no reply"
# Uses -b flag to get both hostname and IP in output.
_TRACEPATH_HOP_RE = re.compile(r"^\s*(\d+)[?]?:\s+(.*)")
_RTT_RE = re.compile(r"(\d+\.?\d*)\s*ms")


def _parse_traceroute(stdout: str) -> list[TraceHop]:
    """Parse standard traceroute output."""
    hops: list[TraceHop] = []
    for line in stdout.splitlines():
        m = _TRACE_LINE_RE.match(line)
        if not m:
            continue

        hop_num = int(m.group(1))
        hostname = m.group(2)
        ip = m.group(3)
        is_star = m.group(4) == "*"
        rtt = float(m.group(5)) if m.group(5) else None

        if is_star:
            hops.append(TraceHop(hop=hop_num))
        else:
            hops.append(
                TraceHop(
                    hop=hop_num,
                    ip=ip or hostname,
                    hostname=hostname if hostname != ip else None,
                    rtt_ms=rtt,
                )
            )
    return hops


def _parse_tracepath(stdout: str) -> list[TraceHop]:
    """Parse tracepath output (different format from traceroute)."""
    seen: dict[int, TraceHop] = {}
    for line in stdout.splitlines():
        m = _TRACEPATH_HOP_RE.match(line)
        if not m:
            continue

        hop_num = int(m.group(1))
        rest = m.group(2).strip()

        if not rest or "pmtu" in rest:
            continue

        # Keep first response per hop (tracepath may show retries)
        if hop_num in seen:
            continue

        if "no reply" in rest:
            seen[hop_num] = TraceHop(hop=hop_num)
            continue

        # Parse hostname and optional (IP)
        parts_match = re.match(r"(\S+)(?:\s+\(([^)]+)\))?", rest)
        hostname = parts_match.group(1) if parts_match else None
        ip = parts_match.group(2) if parts_match else None

        rtt_match = _RTT_RE.search(rest)
        rtt = float(rtt_match.group(1)) if rtt_match else None

        seen[hop_num] = TraceHop(
            hop=hop_num,
            ip=ip or hostname,
            hostname=hostname if hostname and hostname != ip else None,
            rtt_ms=rtt,
        )

    return sorted(seen.values(), key=lambda h: h.hop)


async def _traceroute_system(target: str, *, timeout: float = 30.0) -> list[TraceHop]:
    """Traceroute using system traceroute/tracepath command.

    AIDEV-NOTE: Uses subprocess.run in a thread executor instead of
    asyncio.create_subprocess_exec to avoid Python 3.12+ event-loop-closed
    errors during subprocess transport cleanup (__del__).
    """
    cmd = None
    for prog in ("traceroute", "tracepath"):
        if shutil.which(prog):
            cmd = prog
            break

    if cmd is None:
        raise RuntimeError("No traceroute tool available (install traceroute or icmplib)")

    if cmd == "traceroute":
        args = [cmd, "-m", "30", "-w", "2", "-q", "1", target]
    else:
        args = [cmd, "-b", "-m", "30", target]

    loop = asyncio.get_running_loop()
    stdout_bytes = b""
    try:
        completed = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: subprocess.run(args, capture_output=True, timeout=timeout),
            ),
            timeout=timeout + 5,
        )
        stdout_bytes = completed.stdout
    except subprocess.TimeoutExpired as e:
        # Use partial output captured before timeout
        stdout_bytes = e.output or b""

    stdout = stdout_bytes.decode(errors="replace")
    if cmd == "tracepath":
        return _parse_tracepath(stdout)
    return _parse_traceroute(stdout)
