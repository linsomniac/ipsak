"""Lookup orchestration for ipq.

Runs all applicable lookups concurrently and collects results.
"""

import asyncio

import httpx

from ipq.lookups.asn import lookup_asn_cymru
from ipq.lookups.bogon import check_bogon
from ipq.lookups.dns import lookup_dns_records, lookup_ptr
from ipq.lookups.geo import lookup_geo
from ipq.lookups.reputation import check_dnsbl
from ipq.lookups.rpki import lookup_rpki
from ipq.lookups.subnet import calculate_subnet
from ipq.lookups.trace import run_traceroute
from ipq.lookups.whois import lookup_whois
from ipq.models import QueryResult


# AIDEV-NOTE: Orchestration runs lookups in two phases:
#   Phase 1: All independent lookups concurrently
#   Phase 2: RPKI (depends on ASN result for prefix)
# Team Cymru ASN lookup is fast (~100ms DNS), so RPKI fires quickly after.
async def run_info_lookups(
    target: str,
    target_type: str,
    ip: str | None,
    *,
    do_trace: bool = False,
    timeout: float = 10.0,
) -> QueryResult:
    """Run all applicable lookups for the info command."""
    result = QueryResult(target=target, target_type=target_type, ip=ip)

    # Bogon check is instant (stdlib only)
    if ip:
        result.bogon = check_bogon(ip)

    # Subnet calc is instant for CIDRs
    if target_type.startswith("cidr"):
        result.subnet = calculate_subnet(target)

    is_bogon = result.bogon is not None and result.bogon.is_bogon

    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
        tasks: dict[str, asyncio.Task[object]] = {}

        if ip:
            tasks["ptr"] = asyncio.create_task(lookup_ptr(ip, timeout=timeout))
            # Skip network lookups for bogon/private IPs — they'll always fail
            # Skip network lookups for bogon/private IPs — they'll always fail
            if not is_bogon:
                tasks["geo"] = asyncio.create_task(lookup_geo(ip, client))
                tasks["whois"] = asyncio.create_task(lookup_whois(ip, timeout=timeout))
                tasks["asn"] = asyncio.create_task(lookup_asn_cymru(ip, timeout=timeout))
                tasks["dnsbl"] = asyncio.create_task(check_dnsbl(ip, timeout=timeout))

        if target_type == "domain":
            tasks["dns"] = asyncio.create_task(lookup_dns_records(target, timeout=timeout))

        if not tasks:
            return result

        # Phase 1: Wait for ASN first (fast), fire RPKI with ASN data
        asn_task = tasks.pop("asn", None)
        if asn_task is not None:
            try:
                result.asn = await asn_task
            except Exception as e:
                result.errors["asn"] = str(e)

            # Fire RPKI if we have ASN + prefix
            if result.asn and result.asn.asn and result.asn.prefix:
                tasks["rpki"] = asyncio.create_task(
                    lookup_rpki(result.asn.asn, result.asn.prefix, client)
                )

        # Phase 2: Gather remaining tasks
        names = list(tasks.keys())
        results = await asyncio.gather(
            *tasks.values(),
            return_exceptions=True,
        )

        for name, res in zip(names, results):
            if isinstance(res, BaseException):
                result.errors[name] = str(res)
            else:
                _assign_result(result, name, res)

        # Optional traceroute (after everything else)
        if do_trace and ip:
            try:
                result.trace = await run_traceroute(ip, timeout=timeout)
            except Exception as e:
                result.errors["trace"] = str(e)

    return result


def _assign_result(result: QueryResult, name: str, value: object) -> None:
    """Assign a lookup result to the appropriate QueryResult field."""
    match name:
        case "ptr":
            if result.dns is None:
                from ipq.models import DNSResults

                result.dns = DNSResults()
            result.dns.ptr = value  # type: ignore[assignment]
        case "dns":
            if result.dns is None:
                from ipq.models import DNSResults

                result.dns = DNSResults()
            # Merge DNS records into existing dns result (which may have ptr)
            if isinstance(value, dict):
                for k, v in value.items():
                    if k == "soa":
                        result.dns.soa = v
                    elif hasattr(result.dns, k.lower()):
                        setattr(result.dns, k.lower(), v)
        case "geo":
            result.geo = value  # type: ignore[assignment]
        case "whois":
            result.whois = value  # type: ignore[assignment]
        case "rpki":
            result.rpki = value  # type: ignore[assignment]
        case "dnsbl":
            result.reputation = value  # type: ignore[assignment]
