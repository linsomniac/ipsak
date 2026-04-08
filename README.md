# ipq

Fast IP, CIDR, and domain information query tool for network operations.

One command gives you ASN, geolocation, WHOIS, DNS, RPKI validation, DNSBL reputation, subnet math, and traceroute -- all in parallel.

## Quickstart

```bash
uvx --from git+https://github.com/linsomniac/ipq ipq 8.8.8.8
```

## Demo

```
$ ipq 8.8.8.8

  8.8.8.8 · dns.google · AS15169 GOOGLE - Google LLC, US · Ashburn, US · Public

                Network                              Location
  ASN         AS15169                    Country     United States (US)
  Org         GOOGLE - Google LLC, US    Region      Virginia
  Prefix      8.8.8.0/24                City        Ashburn
  RIR         ARIN                      ISP         Google LLC
  RPKI        ✓ Valid                    Org         Google Public DNS
                 WHOIS                   TZ          America/New_York
  Range       8.8.8.0 - 8.8.8.255       Coords      39.0300, -77.5000
  Name        GOGL
  Org         Google LLC                      Reputation
  Abuse       network-abuse@google.com   DNSBL    Clean (6 lists checked)
  Country     US
  Created     2023-12-28
  Updated     2023-12-28
```

```
$ ipq dns google.com

  google.com DNS
  A         142.251.35.142
  AAAA      2607:f8b0:400f:801::200e
  MX        10 smtp.google.com.
  NS        ns1.google.com.
            ns4.google.com.
            ns2.google.com.
            ns3.google.com.
  TXT       "v=spf1 include:_spf.google.com ~all"
            ...
  SOA       ns1.google.com. dns-admin.google.com. ...
```

```
$ ipq calc 10.0.0.0/24

  10.0.0.0/24 Subnet
  Network         10.0.0.0
  Broadcast       10.0.0.255
  Netmask         255.255.255.0
  Wildcard        0.0.0.255
  Prefix          /24
  First Host      10.0.0.1
  Last Host       10.0.0.254
  Addresses       256
  Usable          254
  IP Version      IPv4
```

## Install

Requires Python 3.11+.

### Run directly from GitHub (no install)

```bash
uvx --from git+https://github.com/linsomniac/ipq ipq 8.8.8.8
```

### Install from GitHub

```bash
uv tool install git+https://github.com/linsomniac/ipq
ipq 8.8.8.8
```

### Install from source

```bash
git clone https://github.com/linsomniac/ipq.git
cd ipq
uv tool install .
```

## Usage

```
ipq <target>              # Full info (ASN, geo, WHOIS, DNS, RPKI, reputation)
ipq dns <domain|ip>       # DNS records or reverse DNS
ipq whois <target>        # WHOIS/RDAP lookup
ipq calc <cidr>           # Subnet calculator
ipq trace <target>        # Traceroute (requires: uv tool install 'ipq[trace]')
ipq myip                  # Show public and local IP addresses
```

The target can be an IPv4/IPv6 address, a CIDR block, or a domain name. When no subcommand is given, `ipq` defaults to `info`.

### Options

| Flag | Description |
|------|-------------|
| `--json` / `-j` | Output as JSON |
| `--trace` / `-t` | Include traceroute in info output |
| `--timeout` / `-T` | Lookup timeout in seconds (default: 10) |
| `--version` / `-V` | Show version |

### Traceroute

Traceroute requires the optional `icmplib` dependency and root/sudo privileges:

```bash
uv tool install 'git+https://github.com/linsomniac/ipq[trace]'
sudo ipq trace 8.8.8.8
```

## What it queries

All lookups run concurrently for fast results:

- **ASN** -- Team Cymru DNS mapping
- **Geolocation** -- ip-api.com
- **WHOIS/RDAP** -- via ipwhois library
- **DNS** -- forward (A, AAAA, CNAME, MX, NS, TXT, SOA) and reverse (PTR)
- **RPKI** -- Cloudflare RPKI validator
- **Reputation** -- DNSBL checks (Spamhaus, Barracuda, SORBS, etc.)
- **Bogon detection** -- RFC 1918, RFC 5737, loopback, link-local, etc.
- **Subnet calculator** -- network/broadcast/host range math

## License

CC0 1.0 Universal -- public domain. See [LICENSE](LICENSE).
