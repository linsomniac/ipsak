"""Rich terminal display for ipq query results."""

import json
from typing import Any

from rich.console import Console, Group
from rich.table import Table
from rich.text import Text

from ipq.lookups.myip import MyIPResult
from ipq.models import QueryResult, SubnetResult

console = Console()


def print_json(result: QueryResult) -> None:
    """Print result as JSON."""
    console.print_json(json.dumps(result.to_dict(), indent=2, default=str))


def print_info(result: QueryResult) -> None:
    """Print the full info display with condensed layout."""
    header = _build_header(result)
    sections: list[Any] = []

    # Build section tables
    left_sections: list[Any] = []
    right_sections: list[Any] = []

    net_table = _build_network_section(result)
    if net_table:
        left_sections.append(net_table)

    geo_table = _build_geo_section(result)
    if geo_table:
        right_sections.append(geo_table)

    whois_table = _build_whois_section(result)
    if whois_table:
        left_sections.append(whois_table)

    bogon_table = _build_bogon_section(result)
    if bogon_table:
        right_sections.append(bogon_table)

    # Side-by-side layout using grid Table for wide terminals
    width = console.size.width
    if width >= 90 and left_sections and right_sections:
        grid = Table.grid(padding=(0, 4), expand=True)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        left_group = Group(*left_sections)
        right_group = Group(*right_sections)
        grid.add_row(left_group, right_group)
        sections.append(grid)
    else:
        sections.extend(left_sections)
        sections.extend(right_sections)

    # DNS records (full width, for domains)
    dns_table = _build_dns_section(result)
    if dns_table:
        sections.append(dns_table)

    # Subnet info (full width, for CIDRs)
    subnet_table = _build_subnet_section(result)
    if subnet_table:
        sections.append(subnet_table)

    # Reputation
    rep_table = _build_reputation_section(result)
    if rep_table:
        sections.append(rep_table)

    # Traceroute
    trace_table = _build_trace_section(result)
    if trace_table:
        sections.append(trace_table)

    # Errors
    err_table = _build_errors_section(result)
    if err_table:
        sections.append(err_table)

    console.print()
    console.print(Text(" "), header)
    console.print()
    if sections:
        for section in sections:
            console.print(section)
    else:
        console.print(Text("  No data available", style="dim"))
    console.print()


def print_dns(result: QueryResult) -> None:
    """Print DNS-only output."""
    if not result.dns:
        console.print("[yellow]No DNS data available[/]")
        return

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Type", style="cyan bold", min_width=6)
    table.add_column("Value")

    dns = result.dns
    if dns.ptr:
        table.add_row("PTR", dns.ptr)
    for rtype in ("a", "aaaa", "cname", "mx", "ns", "txt"):
        records = getattr(dns, rtype, [])
        for i, val in enumerate(records):
            label = rtype.upper() if i == 0 else ""
            table.add_row(label, val)
    if dns.soa:
        table.add_row("SOA", dns.soa)

    console.print()
    console.print(f"  [bold]{result.target}[/] DNS")
    console.print(table)
    _print_errors(result)


def print_whois(result: QueryResult) -> None:
    """Print WHOIS-only output."""
    if not result.whois:
        console.print("[yellow]No WHOIS data available[/]")
        return

    w = result.whois
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="cyan bold", min_width=10)
    table.add_column("Value")

    _add_row(table, "Range", w.net_range)
    _add_row(table, "Name", w.net_name)
    _add_row(table, "CIDR", w.net_cidr)
    _add_row(table, "Org", w.org)
    _add_row(table, "Country", w.country)
    _add_row(table, "Abuse", w.abuse_email)
    _add_row(table, "Created", w.created)
    _add_row(table, "Updated", w.updated)
    _add_row(table, "Description", w.description)

    console.print()
    console.print(f"  [bold]{result.target}[/] WHOIS")
    console.print(table)
    _print_errors(result)


def print_calc(subnet: SubnetResult) -> None:
    """Print subnet calculator output."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="cyan bold", min_width=12)
    table.add_column("Value")

    table.add_row("Network", subnet.network)
    table.add_row("Broadcast", subnet.broadcast)
    table.add_row("Netmask", subnet.netmask)
    table.add_row("Wildcard", subnet.wildcard)
    table.add_row("Prefix", f"/{subnet.prefix_len}")
    table.add_row("First Host", subnet.first_host)
    table.add_row("Last Host", subnet.last_host)
    table.add_row("Addresses", f"{subnet.num_addresses:,}")
    table.add_row("Usable", f"{subnet.num_hosts:,}")
    table.add_row("IP Version", f"IPv{subnet.ip_version}")

    cidr = f"{subnet.network}/{subnet.prefix_len}"
    console.print()
    console.print(f"  [bold]{cidr}[/] Subnet")
    console.print(table)


def print_trace(result: QueryResult, *, elapsed: float | None = None) -> None:
    """Print traceroute-only output."""
    trace_table = _build_trace_section(result)
    if trace_table:
        console.print()
        header = f"  [bold]{result.target}[/] Traceroute"
        console.print(header)
        console.print(trace_table)
        if elapsed is not None:
            console.print(f"  [dim]Completed in {elapsed:.1f}s[/]")
    else:
        console.print("[yellow]No traceroute data available[/]")
    _print_errors(result)


def print_myip(myip: MyIPResult, public_info: QueryResult | None) -> None:
    """Print myip output: local interfaces + public IP info."""
    console.print()

    # Local interfaces
    if myip.local_interfaces:
        table = Table(
            show_header=True, box=None, padding=(0, 2), title="Local", title_style="bold cyan"
        )
        table.add_column("Interface", style="bold")
        table.add_column("Address")

        if myip.hostname:
            table.add_row("hostname", myip.hostname)

        for iface in myip.local_interfaces:
            first = True
            for addr in iface.ipv4 + iface.ipv6:
                table.add_row(iface.name if first else "", addr)
                first = False
        console.print(table)
        console.print()

    # Public IP — reuse the info display
    if public_info:
        header = _build_header(public_info)
        console.print(Text("  Public ", style="bold cyan"), header)
        console.print()

        sections: list[Any] = []

        left_sections: list[Any] = []
        right_sections: list[Any] = []

        net_table = _build_network_section(public_info)
        if net_table:
            left_sections.append(net_table)

        geo_table = _build_geo_section(public_info)
        if geo_table:
            right_sections.append(geo_table)

        whois_table = _build_whois_section(public_info)
        if whois_table:
            left_sections.append(whois_table)

        width = console.size.width
        if width >= 90 and left_sections and right_sections:
            grid = Table.grid(padding=(0, 4), expand=True)
            grid.add_column(ratio=1)
            grid.add_column(ratio=1)
            grid.add_row(Group(*left_sections), Group(*right_sections))
            sections.append(grid)
        else:
            sections.extend(left_sections)
            sections.extend(right_sections)

        rep_table = _build_reputation_section(public_info)
        if rep_table:
            sections.append(rep_table)

        err_table = _build_errors_section(public_info)
        if err_table:
            sections.append(err_table)

        for section in sections:
            console.print(section)
    elif myip.public_ip:
        console.print(f"  [bold]Public IP:[/] {myip.public_ip}")
    else:
        console.print("  [yellow]Could not determine public IP[/]")

    console.print()


# --- Section builders ---


def _build_header(result: QueryResult) -> Text:
    """Build the panel title/header line with key summary info."""
    parts: list[tuple[str, str]] = []

    # Target IP
    ip_display = result.ip or result.target
    parts.append((ip_display, "bold white"))

    # PTR / domain
    if result.dns and result.dns.ptr and result.dns.ptr != result.target:
        parts.append((result.dns.ptr, "bold green"))
    elif result.target_type == "domain":
        parts.append((result.target, "bold green"))

    # ASN + Org
    if result.asn and result.asn.name:
        asn_str = f"AS{result.asn.asn}" if result.asn.asn else ""
        parts.append((f"{asn_str} {result.asn.name}".strip(), "yellow"))

    # Geo
    if result.geo:
        geo_parts = [p for p in (result.geo.city, result.geo.country_code) if p]
        if geo_parts:
            parts.append((", ".join(geo_parts), "cyan"))

    # Type
    if result.bogon and result.bogon.is_bogon:
        parts.append((result.bogon.ip_type, "red bold"))
    elif result.bogon:
        parts.append(("Public", "green"))

    header = Text()
    for i, (text, style) in enumerate(parts):
        if i > 0:
            header.append(" · ", style="dim")
        header.append(text, style=style)

    return header


def _build_network_section(result: QueryResult) -> Table | None:
    """Build the Network info section."""
    if not result.asn and not result.rpki:
        return None

    table = Table(
        show_header=True, box=None, padding=(0, 2), title="Network", title_style="bold cyan"
    )
    table.add_column("", style="dim", min_width=8)
    table.add_column("")

    if result.asn:
        a = result.asn
        if a.asn:
            table.add_row("ASN", f"AS{a.asn}")
        if a.name:
            table.add_row("Org", a.name)
        if a.prefix:
            table.add_row("Prefix", a.prefix)
        if a.registry:
            table.add_row("RIR", a.registry.upper())

    if result.rpki:
        status = result.rpki.status or "Unknown"
        icon = {"Valid": "[green]✓[/]", "Invalid": "[red]✗[/]", "Not Found": "[yellow]?[/]"}.get(
            status, ""
        )
        table.add_row("RPKI", f"{icon} {status}")

    return table


def _build_geo_section(result: QueryResult) -> Table | None:
    """Build the Geo info section."""
    if not result.geo:
        return None

    g = result.geo
    table = Table(
        show_header=True, box=None, padding=(0, 2), title="Location", title_style="bold cyan"
    )
    table.add_column("", style="dim", min_width=8)
    table.add_column("")

    if g.country:
        cc = f" ({g.country_code})" if g.country_code else ""
        table.add_row("Country", f"{g.country}{cc}")
    if g.region:
        table.add_row("Region", g.region)
    if g.city:
        table.add_row("City", g.city)
    if g.isp:
        table.add_row("ISP", g.isp)
    if g.org and g.org != g.isp:
        table.add_row("Org", g.org)
    if g.timezone:
        table.add_row("TZ", g.timezone)
    if g.lat is not None and g.lon is not None:
        table.add_row("Coords", f"{g.lat:.4f}, {g.lon:.4f}")

    return table


def _build_whois_section(result: QueryResult) -> Table | None:
    """Build the WHOIS info section."""
    if not result.whois:
        return None

    w = result.whois
    table = Table(
        show_header=True, box=None, padding=(0, 2), title="WHOIS", title_style="bold cyan"
    )
    table.add_column("", style="dim", min_width=8)
    table.add_column("")

    _add_row(table, "Range", w.net_range)
    _add_row(table, "Name", w.net_name)
    _add_row(table, "Org", w.org)
    _add_row(table, "Abuse", w.abuse_email)
    _add_row(table, "Country", w.country)
    _add_row(table, "Created", w.created)
    _add_row(table, "Updated", w.updated)

    return table


def _build_bogon_section(result: QueryResult) -> Table | None:
    """Build the bogon/type info section (only for non-public IPs)."""
    if not result.bogon or not result.bogon.is_bogon:
        return None

    b = result.bogon
    table = Table(
        show_header=True,
        box=None,
        padding=(0, 2),
        title="Address Type",
        title_style="bold red",
    )
    table.add_column("", style="dim", min_width=8)
    table.add_column("")

    table.add_row("Type", b.ip_type)
    if b.description:
        table.add_row("Info", b.description)
    if b.rfc:
        table.add_row("RFC", b.rfc)

    return table


def _build_dns_section(result: QueryResult) -> Table | None:
    """Build the DNS records section."""
    if not result.dns:
        return None

    dns = result.dns
    has_records = (
        dns.ptr or dns.a or dns.aaaa or dns.mx or dns.ns or dns.txt or dns.cname or dns.soa
    )

    # For IP-only queries with just a PTR, skip the section (shown in header)
    if result.target_type != "domain" and not (
        dns.a or dns.aaaa or dns.mx or dns.ns or dns.txt or dns.cname or dns.soa
    ):
        return None

    if not has_records:
        return None

    table = Table(
        show_header=True, box=None, padding=(0, 2), title="DNS Records", title_style="bold cyan"
    )
    table.add_column("Type", style="cyan bold", min_width=6)
    table.add_column("Value")

    if dns.ptr:
        table.add_row("PTR", dns.ptr)
    for rtype in ("a", "aaaa", "cname", "mx", "ns", "txt"):
        records = getattr(dns, rtype, [])
        for i, val in enumerate(records):
            label = rtype.upper() if i == 0 else ""
            table.add_row(label, val)
    if dns.soa:
        table.add_row("SOA", dns.soa)

    return table


def _build_subnet_section(result: QueryResult) -> Table | None:
    """Build the subnet calculator section."""
    if not result.subnet:
        return None

    s = result.subnet
    table = Table(
        show_header=True,
        box=None,
        padding=(0, 2),
        title="Subnet Calculator",
        title_style="bold cyan",
    )
    table.add_column("", style="dim", min_width=12)
    table.add_column("")

    table.add_row("Network", s.network)
    table.add_row("Broadcast", s.broadcast)
    table.add_row("Netmask", s.netmask)
    table.add_row("Wildcard", s.wildcard)
    table.add_row("Host Range", f"{s.first_host} - {s.last_host}")
    table.add_row("Addresses", f"{s.num_addresses:,}")
    table.add_row("Usable Hosts", f"{s.num_hosts:,}")

    return table


def _build_reputation_section(result: QueryResult) -> Table | None:
    """Build the DNSBL reputation section."""
    if not result.reputation:
        return None

    r = result.reputation
    if not r.listed_on and r.checked > 0:
        # Clean — show one-liner
        table = Table(
            show_header=True,
            box=None,
            padding=(0, 2),
            title="Reputation",
            title_style="bold cyan",
        )
        table.add_column("", style="dim")
        table.add_column("")
        table.add_row("DNSBL", f"[green]Clean[/] ({r.checked} lists checked)")
        return table

    if r.listed_on:
        table = Table(
            show_header=True,
            box=None,
            padding=(0, 2),
            title="Reputation",
            title_style="bold red",
        )
        table.add_column("", style="dim")
        table.add_column("")
        table.add_row(
            "DNSBL",
            f"[red bold]Listed on {len(r.listed_on)}/{r.checked} lists[/]",
        )
        for bl in r.listed_on:
            table.add_row("", f"[red]  ✗ {bl}[/]")
        return table

    return None


def _build_trace_section(result: QueryResult) -> Table | None:
    """Build the traceroute section."""
    if not result.trace:
        return None

    has_asn = any(h.asn is not None for h in result.trace)

    table = Table(box=None, padding=(0, 1), title="Traceroute", title_style="bold cyan")
    table.add_column("Hop", style="dim", justify="right", width=4)
    table.add_column("IP", min_width=16)
    if has_asn:
        table.add_column("ASN", min_width=8)
    table.add_column("Hostname", min_width=20, max_width=60, no_wrap=True, overflow="ellipsis")
    table.add_column("RTT", justify="right", width=10)
    table.add_column("Loss", justify="right", width=6)

    for hop in result.trace:
        ip_str = hop.ip or "*"
        host_str = hop.hostname or ""
        loss_str = f"{hop.loss_pct:.0f}%" if hop.loss_pct is not None else ""

        if hop.rtt_ms is not None:
            rtt_str = f"{hop.rtt_ms:.1f} ms"
        else:
            rtt_str = "*"

        # Color based on loss
        style = ""
        if hop.ip is None:
            style = "dim"
        elif hop.loss_pct is not None and hop.loss_pct > 0:
            style = "yellow" if hop.loss_pct < 50 else "red"

        row: list[str] = [str(hop.hop), ip_str]
        if has_asn:
            asn_str = f"AS{hop.asn}" if hop.asn else ""
            row.append(asn_str)
        row.extend([host_str, rtt_str, loss_str])

        table.add_row(*row, style=style)

    return table


def _build_errors_section(result: QueryResult) -> Table | None:
    """Build errors section if any lookups failed."""
    if not result.errors:
        return None

    table = Table(
        show_header=True,
        box=None,
        padding=(0, 2),
        title="[yellow]Errors[/]",
        title_style="bold",
    )
    table.add_column("Lookup", style="yellow", min_width=8)
    table.add_column("Error", style="dim")

    for name, err in result.errors.items():
        # Truncate long error messages
        err_short = err[:80] + "..." if len(err) > 80 else err
        table.add_row(name, err_short)

    return table


def _print_errors(result: QueryResult) -> None:
    """Print errors if any, for standalone views."""
    if result.errors:
        err_table = _build_errors_section(result)
        if err_table:
            console.print(err_table)


def _add_row(table: Table, label: str, value: str | None) -> None:
    """Add a row only if value is not None."""
    if value:
        table.add_row(label, value)
