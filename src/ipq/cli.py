"""CLI entry point for ipq."""

import asyncio
from typing import Annotated

import click
import typer
from rich.console import Console
from typer.core import TyperGroup

from ipq import __version__
from ipq.display import (
    print_calc,
    print_dns,
    print_info,
    print_json,
    print_myip,
    print_trace,
    print_whois,
)
from ipq.lookups import run_info_lookups
from ipq.lookups.dns import lookup_dns_records, lookup_ptr
from ipq.lookups.subnet import calculate_subnet
from ipq.lookups.trace import run_traceroute
from ipq.lookups.whois import lookup_whois
from ipq.models import DNSResults, QueryResult
from ipq.resolve import detect_target

console = Console(stderr=True)


# AIDEV-NOTE: Custom Click group that routes unknown first arguments to the "info"
# subcommand, enabling `ipq 8.8.8.8` as shorthand for `ipq info 8.8.8.8`.
# Known subcommands (dns, whois, calc, trace) are routed normally.
class DefaultInfoGroup(TyperGroup):
    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        # If first arg isn't a known command or a flag, treat it as `info <target>`
        if args and args[0] not in self.commands and not args[0].startswith("-"):
            args = ["info"] + args
        return super().parse_args(ctx, args)


app = typer.Typer(
    name="ipq",
    help="Fast IP, CIDR, and domain information query tool for network operations.",
    cls=DefaultInfoGroup,
    add_completion=False,
    invoke_without_command=True,
)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[bool, typer.Option("--version", "-V", help="Show version")] = False,
) -> None:
    """Fast IP, CIDR, and domain information query tool."""
    if version:
        typer.echo(f"ipq {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


@app.command()
def info(
    target: Annotated[str, typer.Argument(help="IP address, CIDR, or domain to query")],
    json_output: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
    trace: Annotated[bool, typer.Option("--trace", "-t", help="Include traceroute")] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", "-T", help="Lookup timeout in seconds")
    ] = 10.0,
) -> None:
    """Show comprehensive information about a target."""
    _run_info(target, json_output=json_output, do_trace=trace, timeout=timeout)


@app.command()
def dns(
    target: Annotated[str, typer.Argument(help="Domain or IP to query DNS for")],
    json_output: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", "-T", help="Lookup timeout in seconds")
    ] = 10.0,
) -> None:
    """Look up DNS records for a domain or reverse DNS for an IP."""
    target_type, normalized = detect_target(target)

    async def _run() -> QueryResult:
        result = QueryResult(target=normalized, target_type=target_type, ip=None)
        result.dns = DNSResults()

        if target_type in ("ipv4", "ipv6"):
            result.ip = normalized
            try:
                result.dns.ptr = await lookup_ptr(normalized, timeout=timeout)
            except Exception as e:
                result.errors["ptr"] = str(e)
        elif target_type == "domain":
            try:
                records = await lookup_dns_records(normalized, timeout=timeout)
                for k, v in records.items():
                    if k == "soa":
                        result.dns.soa = v  # type: ignore[assignment]
                    elif hasattr(result.dns, k):
                        setattr(result.dns, k, v)
                if result.dns.a:
                    result.ip = result.dns.a[0]
            except Exception as e:
                result.errors["dns"] = str(e)
        else:
            _error_exit(f"Cannot look up DNS for: {target}")
        return result

    result = asyncio.run(_run())
    if json_output:
        print_json(result)
    else:
        print_dns(result)


@app.command()
def whois(
    target: Annotated[str, typer.Argument(help="IP address to query WHOIS for")],
    json_output: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", "-T", help="Lookup timeout in seconds")
    ] = 10.0,
) -> None:
    """Look up WHOIS/RDAP information for an IP."""
    target_type, normalized = detect_target(target)

    if target_type not in ("ipv4", "ipv6"):
        if target_type == "domain":
            import dns.resolver

            try:
                answers = dns.resolver.resolve(normalized, "A")
                normalized = str(answers[0])
                target_type = "ipv4"
            except Exception:
                _error_exit(f"Cannot resolve domain: {target}")
        else:
            _error_exit(f"Cannot look up WHOIS for: {target}")

    async def _run() -> QueryResult:
        result = QueryResult(target=target, target_type=target_type, ip=normalized)
        try:
            result.whois = await lookup_whois(normalized, timeout=timeout)
        except Exception as e:
            result.errors["whois"] = str(e)
        return result

    result = asyncio.run(_run())
    if json_output:
        print_json(result)
    else:
        print_whois(result)


@app.command()
def calc(
    cidr: Annotated[str, typer.Argument(help="CIDR notation network (e.g. 10.0.0.0/24)")],
    json_output: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """IP subnet calculator."""
    target_type, normalized = detect_target(cidr)
    if not target_type.startswith("cidr"):
        _error_exit(f"Not a valid CIDR: {cidr}")

    subnet = calculate_subnet(normalized)

    if json_output:
        import json
        from dataclasses import asdict

        print(json.dumps(asdict(subnet), indent=2, default=str))
    else:
        print_calc(subnet)


@app.command(name="trace")
def trace_cmd(
    target: Annotated[str, typer.Argument(help="Target to traceroute to")],
    json_output: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", "-T", help="Traceroute timeout in seconds")
    ] = 10.0,
    probes: Annotated[int, typer.Option("--probes", "-q", help="Probes per hop (1-10)")] = 5,
    asn: Annotated[bool, typer.Option("--asn", "-a", help="Show ASN for each hop")] = False,
) -> None:
    """Run traceroute to a target."""
    import time as _time

    target_type, normalized = detect_target(target)

    trace_target = normalized
    if target_type == "domain":
        import dns.resolver

        try:
            answers = dns.resolver.resolve(normalized, "A")
            trace_target = str(answers[0])
        except Exception:
            trace_target = normalized

    probes = max(1, min(10, probes))

    async def _run() -> QueryResult:
        result = QueryResult(target=target, target_type=target_type, ip=trace_target)
        try:
            result.trace = await run_traceroute(
                trace_target, timeout=timeout, count=probes, with_asn=asn
            )
        except Exception as e:
            result.errors["trace"] = str(e)
        return result

    t0 = _time.monotonic()
    result = asyncio.run(_run())
    elapsed = _time.monotonic() - t0

    if json_output:
        print_json(result)
    else:
        print_trace(result, elapsed=elapsed)


@app.command()
def myip(
    json_output: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", "-T", help="Lookup timeout in seconds")
    ] = 10.0,
) -> None:
    """Show public and local IP addresses for this system."""
    from ipq.lookups.myip import (
        discover_local_interfaces,
        discover_public_ip,
        get_hostname,
        MyIPResult,
    )

    async def _run() -> tuple[MyIPResult, QueryResult | None]:
        import httpx

        myip_result = MyIPResult(
            local_interfaces=discover_local_interfaces(),
            hostname=get_hostname(),
        )

        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            try:
                ip, source = await discover_public_ip(client)
                myip_result.public_ip = ip
                myip_result.public_source = source
            except Exception as e:
                myip_result.public_ip = None
                if not json_output:
                    console.print(f"[yellow]Warning:[/] {e}")
                return (myip_result, None)

        # Run full info lookup on the public IP
        public_info = await run_info_lookups(
            target=myip_result.public_ip,
            target_type="ipv4",
            ip=myip_result.public_ip,
            timeout=timeout,
        )
        return (myip_result, public_info)

    myip_result, public_info = asyncio.run(_run())

    if json_output:
        import json
        from dataclasses import asdict

        out = asdict(myip_result)
        if public_info:
            out["public_info"] = public_info.to_dict()
        console.print_json(json.dumps(out, indent=2, default=str))
    else:
        print_myip(myip_result, public_info)


def _run_info(
    target: str,
    *,
    json_output: bool = False,
    do_trace: bool = False,
    timeout: float = 10.0,
) -> None:
    """Run the info command (shared by callback and info subcommand)."""
    target_type, normalized = detect_target(target)

    if target_type == "unknown":
        _error_exit(f"Cannot determine type of: {target}")

    async def _run() -> QueryResult:
        ip: str | None = None

        if target_type in ("ipv4", "ipv6"):
            ip = normalized
        elif target_type == "domain":
            import dns.asyncresolver

            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = timeout
            try:
                answers = await resolver.resolve(normalized, "A")
                ip = str(answers[0])
            except Exception:
                try:
                    answers = await resolver.resolve(normalized, "AAAA")
                    ip = str(answers[0])
                except Exception:
                    pass
        elif target_type.startswith("cidr"):
            import ipaddress

            net = ipaddress.ip_network(normalized, strict=False)
            ip = str(net.network_address)

        return await run_info_lookups(
            target=normalized,
            target_type=target_type,
            ip=ip,
            do_trace=do_trace,
            timeout=timeout,
        )

    result = asyncio.run(_run())

    if json_output:
        print_json(result)
    else:
        print_info(result)


def _error_exit(msg: str) -> None:
    console.print(f"[red bold]Error:[/] {msg}")
    raise typer.Exit(1)
