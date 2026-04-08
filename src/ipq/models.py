"""Data models for ipq query results."""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class DNSResults:
    """DNS lookup results (forward and reverse)."""

    ptr: str | None = None
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    soa: str | None = None


@dataclass
class ASNResult:
    """ASN information from Team Cymru DNS."""

    asn: int | None = None
    name: str | None = None
    prefix: str | None = None
    country: str | None = None
    registry: str | None = None
    allocated: str | None = None


@dataclass
class GeoResult:
    """GeoIP information."""

    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    timezone: str | None = None
    isp: str | None = None
    org: str | None = None


@dataclass
class WhoisResult:
    """WHOIS/RDAP information for IPs."""

    net_range: str | None = None
    net_name: str | None = None
    net_cidr: str | None = None
    org: str | None = None
    abuse_email: str | None = None
    created: str | None = None
    updated: str | None = None
    description: str | None = None
    country: str | None = None


@dataclass
class SubnetResult:
    """Subnet calculator results for CIDRs."""

    network: str | None = None
    broadcast: str | None = None
    netmask: str | None = None
    wildcard: str | None = None
    first_host: str | None = None
    last_host: str | None = None
    num_addresses: int | None = None
    num_hosts: int | None = None
    prefix_len: int | None = None
    ip_version: int = 4


@dataclass
class RPKIResult:
    """RPKI route origin validation."""

    status: str | None = None  # Valid, Invalid, Not Found, Unknown
    description: str | None = None


@dataclass
class BogonResult:
    """Bogon/special-use address detection."""

    is_bogon: bool = False
    ip_type: str = "Public"
    description: str | None = None
    rfc: str | None = None


@dataclass
class ReputationResult:
    """DNSBL reputation check results."""

    listed_on: list[str] = field(default_factory=list)
    clean_on: list[str] = field(default_factory=list)
    checked: int = 0


@dataclass
class TraceHop:
    """Single hop in a traceroute."""

    hop: int = 0
    ip: str | None = None
    hostname: str | None = None
    rtt_ms: float | None = None
    rtt_min: float | None = None
    rtt_max: float | None = None
    loss_pct: float | None = None
    asn: int | None = None
    asn_name: str | None = None


@dataclass
class QueryResult:
    """Complete result for an ipq query."""

    target: str
    target_type: str  # ipv4, ipv6, cidr4, cidr6, domain
    ip: str | None = None

    dns: DNSResults | None = None
    asn: ASNResult | None = None
    geo: GeoResult | None = None
    whois: WhoisResult | None = None
    subnet: SubnetResult | None = None
    rpki: RPKIResult | None = None
    bogon: BogonResult | None = None
    reputation: ReputationResult | None = None
    trace: list[TraceHop] | None = None

    errors: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict, omitting None values."""
        raw = asdict(self)
        return _strip_none(raw)


def _strip_none(d: Any) -> Any:
    """Recursively remove None values from dicts."""
    if isinstance(d, dict):
        return {k: _strip_none(v) for k, v in d.items() if v is not None}
    if isinstance(d, list):
        return [_strip_none(i) for i in d]
    return d
