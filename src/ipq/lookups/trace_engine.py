"""Fast parallel traceroute engine using raw ICMP sockets.

AIDEV-NOTE: This module sends ICMP Echo Requests for ALL TTL values simultaneously
through a single raw socket, then collects responses with select(). This completes
a full trace in ~2-3 seconds instead of the ~30+ seconds of serial traceroute.

Requires root or CAP_NET_RAW capability. Raises PermissionError if unavailable.
IPv4 only — IPv6 targets fall back to system traceroute in the orchestration layer.
"""

import os
import select
import socket
import struct
import time
from collections import Counter
from dataclasses import dataclass, field


# AIDEV-NOTE: Sequence encoding: seq = ttl * MAX_PROBES + probe_index.
# MAX_PROBES=16 supports up to 16 probes/hop. With max_hops=30, max seq=496,
# well within the 16-bit ICMP sequence field.
MAX_PROBES = 16

# ICMP type constants
_ECHO_REQUEST = 8
_ECHO_REPLY = 0
_TIME_EXCEEDED = 11
_DEST_UNREACHABLE = 3


@dataclass
class ProbeResult:
    """Result from a single ICMP probe."""

    responder_ip: str
    rtt_ms: float
    is_target: bool = False


@dataclass
class HopData:
    """Aggregated results for one hop (TTL value)."""

    ttl: int
    probes_sent: int = 0
    results: list[ProbeResult | None] = field(default_factory=list)

    @property
    def responding_ip(self) -> str | None:
        """Most common responder IP (handles ECMP)."""
        ips = [r.responder_ip for r in self.results if r is not None]
        if not ips:
            return None
        counts = Counter(ips)
        return counts.most_common(1)[0][0]

    @property
    def avg_rtt(self) -> float | None:
        rtts = [r.rtt_ms for r in self.results if r is not None]
        return sum(rtts) / len(rtts) if rtts else None

    @property
    def min_rtt(self) -> float | None:
        rtts = [r.rtt_ms for r in self.results if r is not None]
        return min(rtts) if rtts else None

    @property
    def max_rtt(self) -> float | None:
        rtts = [r.rtt_ms for r in self.results if r is not None]
        return max(rtts) if rtts else None

    @property
    def loss_pct(self) -> float:
        if not self.results:
            return 100.0
        lost = sum(1 for r in self.results if r is None)
        return (lost / len(self.results)) * 100.0

    @property
    def probes_received(self) -> int:
        return sum(1 for r in self.results if r is not None)


def _checksum(data: bytes) -> int:
    """Compute ICMP checksum per RFC 1071."""
    if len(data) % 2:
        data += b"\x00"
    s: int = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_echo_request(icmp_id: int, seq: int) -> bytes:
    """Build an ICMP Echo Request packet (type 8, code 0)."""
    # 56 bytes of payload (standard ping size)
    payload = struct.pack("!d", time.monotonic()) + b"\x00" * 48
    header = struct.pack("!BBHHH", _ECHO_REQUEST, 0, 0, icmp_id, seq)
    cksum = _checksum(header + payload)
    header = struct.pack("!BBHHH", _ECHO_REQUEST, 0, cksum, icmp_id, seq)
    return header + payload


# AIDEV-NOTE: ICMP response parsing must handle variable-length IP headers.
# The IHL (Internet Header Length) field is the low 4 bits of byte 0, in 32-bit words.
# Never assume 20 bytes — some routers add IP options.
def _parse_response(buf: bytes, icmp_id: int) -> tuple[int, str, int] | None:
    """Parse an ICMP response packet.

    Returns (sequence, responder_ip, icmp_type) or None if not matching our ID.
    """
    if len(buf) < 28:
        return None

    # Outer IP header — variable length
    outer_ihl = (buf[0] & 0x0F) * 4
    if len(buf) < outer_ihl + 8:
        return None

    responder_ip = socket.inet_ntoa(buf[12:16])
    icmp_type = buf[outer_ihl]

    if icmp_type == _ECHO_REPLY:
        # ID and seq are directly in the ICMP header
        if len(buf) < outer_ihl + 8:
            return None
        resp_id, resp_seq = struct.unpack("!HH", buf[outer_ihl + 4 : outer_ihl + 8])
        if resp_id == icmp_id:
            return resp_seq, responder_ip, icmp_type
        return None

    if icmp_type in (_TIME_EXCEEDED, _DEST_UNREACHABLE):
        # The original IP packet is embedded after the 8-byte ICMP header.
        # Layout: outer_IP | ICMP_header(8) | inner_IP | inner_ICMP(8+)
        inner_ip_start = outer_ihl + 8
        if len(buf) < inner_ip_start + 20:
            return None
        inner_ihl = (buf[inner_ip_start] & 0x0F) * 4
        inner_icmp_start = inner_ip_start + inner_ihl
        if len(buf) < inner_icmp_start + 8:
            return None
        # Extract ID and seq from the embedded ICMP Echo Request
        resp_id, resp_seq = struct.unpack("!HH", buf[inner_icmp_start + 4 : inner_icmp_start + 8])
        if resp_id == icmp_id:
            return resp_seq, responder_ip, icmp_type
        return None

    return None


def parallel_trace(
    target: str,
    *,
    max_hops: int = 30,
    count: int = 5,
    timeout: float = 2.5,
) -> list[HopData]:
    """Send parallel ICMP probes for all TTLs and collect results.

    Args:
        target: Target hostname or IP address.
        max_hops: Maximum number of hops to probe.
        count: Number of probes per hop.
        timeout: Seconds to wait for responses after sending.

    Returns:
        List of HopData for TTLs 1 through the hop where target was reached
        (or max_hops if never reached).

    Raises:
        PermissionError: If raw socket creation fails (no root/CAP_NET_RAW).
        OSError: If target cannot be resolved.
    """
    if count > MAX_PROBES:
        count = MAX_PROBES

    target_ip = socket.gethostbyname(target)
    icmp_id = os.getpid() & 0xFFFF

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except OSError as e:
        if e.errno in (1, 13):  # EPERM, EACCES
            raise PermissionError(str(e)) from e
        raise

    sock.setblocking(False)
    # Large receive buffer to avoid drops when many responses arrive at once
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256 * 1024)

    sent_times: dict[int, float] = {}  # seq -> monotonic time
    responses: dict[int, ProbeResult] = {}  # seq -> result
    target_reached_ttl = max_hops + 1

    # AIDEV-NOTE: Responses arrive in the kernel buffer as soon as routers reply,
    # often within 1ms. If we send all probes first then read, RTTs are inflated
    # by the total send duration (~80ms for 5 rounds). Fix: drain the socket
    # between each send round so recv_time closely matches actual arrival.
    def _drain() -> None:
        """Read all currently available responses from the socket."""
        nonlocal target_reached_ttl
        while True:
            try:
                data, _addr = sock.recvfrom(1500)
                recv_time = time.monotonic()
            except BlockingIOError:
                return

            parsed = _parse_response(data, icmp_id)
            if parsed is None:
                continue

            seq, responder_ip, icmp_type = parsed
            if seq not in sent_times or seq in responses:
                continue

            rtt_ms = (recv_time - sent_times[seq]) * 1000
            is_target = responder_ip == target_ip
            responses[seq] = ProbeResult(
                responder_ip=responder_ip,
                rtt_ms=rtt_ms,
                is_target=is_target,
            )

            if is_target or icmp_type == _DEST_UNREACHABLE:
                ttl_val = seq // MAX_PROBES
                target_reached_ttl = min(target_reached_ttl, ttl_val)

    try:
        # --- Phase 1: Send probes, draining responses between rounds ---
        for probe_idx in range(count):
            for ttl in range(1, max_hops + 1):
                seq = ttl * MAX_PROBES + probe_idx
                packet = _build_echo_request(icmp_id, seq)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                try:
                    sock.sendto(packet, (target_ip, 0))
                except OSError:
                    continue
                sent_times[seq] = time.monotonic()

            # Drain responses that arrived during this send round
            _drain()

            # AIDEV-NOTE: We must NOT use time.sleep() between rounds — responses
            # from fast hops (< 1ms) arrive during the sleep and their RTT gets
            # inflated by the sleep duration. Instead, use select() to wait briefly
            # while still reading responses as they arrive.
            if probe_idx < count - 1:
                wait_end = time.monotonic() + 0.005  # 5ms gap between rounds
                while time.monotonic() < wait_end:
                    remaining = wait_end - time.monotonic()
                    if remaining <= 0:
                        break
                    ready, _, _ = select.select([sock], [], [], remaining)
                    if ready:
                        _drain()

        # --- Phase 2: Collect remaining responses until timeout ---
        deadline = time.monotonic() + timeout
        grace_deadline: float | None = None

        while True:
            now = time.monotonic()
            if grace_deadline is not None and now >= grace_deadline:
                break
            if now >= deadline:
                break

            effective_deadline = min(deadline, grace_deadline) if grace_deadline else deadline
            remaining = effective_deadline - now
            if remaining <= 0:
                break

            ready, _, _ = select.select([sock], [], [], min(remaining, 0.05))
            if not ready:
                continue

            _drain()

            # Check if target was reached during this drain
            if target_reached_ttl <= max_hops and grace_deadline is None:
                grace_deadline = time.monotonic() + 0.5

    finally:
        sock.close()

    # --- Phase 3: Compile per-hop results ---
    effective_max = min(max_hops, target_reached_ttl)
    hops: list[HopData] = []
    for ttl in range(1, effective_max + 1):
        hop = HopData(ttl=ttl, probes_sent=count)
        for probe_idx in range(count):
            seq = ttl * MAX_PROBES + probe_idx
            hop.results.append(responses.get(seq))
        hops.append(hop)

    return hops
