#!/usr/bin/env python3
"""Map web services exposed on non-standard ports for authorized hosts.

The ordinary crawl only ever sees ``:80``/``:443``. Real targets routinely run
admin panels, dashboards, APIs, and staging copies on alternate web ports
(``:8080``, ``:8443``, ``:3000`` ...). This module takes the in-scope hosts a run
already resolved, finds which of a curated set of web-service ports are open, then
HTTP(S)-probes each open port to confirm it actually speaks HTTP and records the
scheme, status, server, and title.

Two outputs are written under ``<output>/``:

* ``assets/services.txt`` -- one ``scheme://host:port/`` base URL per confirmed
  web service, deduplicated and sorted. The orchestrator feeds these to the
  crawler as extra seeds and to the fuzzer as extra scope, so a service found on
  ``:8443`` is assessed exactly like one on ``:443``.
* ``reports/ports.json`` -- the structured record (host, port, open, scheme,
  status, server, title) for the report and the database.

Port discovery prefers a real scanner when one is installed (``naabu`` >
``masscan`` > ``nmap``); otherwise it falls back to a bounded, threaded pure-Python
TCP connect scan so the feature works with no external tooling. Scanning is only
ever run against the hosts the caller supplies, which the orchestrator constrains
to the authorized scope before calling here.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import logging
import re
import shutil
import socket
import ssl
import subprocess
import sys
from pathlib import Path

LOGGER = logging.getLogger("jsintel.portscan")

# Curated set of ports that commonly carry an HTTP(S) service. Deliberately web
# focused (not a full top-1000) so a mass sweep stays fast and low-noise while
# still catching the alternate-web-port services the plain crawl misses.
DEFAULT_WEB_PORTS: tuple[int, ...] = (
    80, 81, 88, 443, 300, 442, 444, 591, 593, 832, 981, 1010, 1311, 1099,
    2082, 2083, 2086, 2087, 2095, 2096, 2480, 3000, 3128, 3333, 4000, 4243,
    4443, 4444, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5280, 5281, 5601,
    5800, 6543, 7000, 7001, 7002, 7396, 7474, 7777, 8000, 8001, 8008, 8009,
    8014, 8042, 8060, 8069, 8080, 8081, 8083, 8085, 8088, 8089, 8090, 8091,
    8118, 8123, 8172, 8181, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834,
    8880, 8888, 8983, 9000, 9001, 9043, 9060, 9080, 9090, 9091, 9200, 9443,
    9502, 9800, 9981, 10000, 10250, 11371, 12443, 15672, 16080, 17778, 18091,
    18092, 20720, 55672,
)

# Ports conventionally spoken over TLS; everything else is probed as HTTP first.
TLS_PORTS: frozenset[int] = frozenset(
    {443, 832, 981, 1311, 2083, 2087, 2096, 4443, 4444, 4993, 5281, 8172, 8243,
     8333, 8443, 9443, 12443, 16080}
)

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def parse_ports(spec: str) -> tuple[int, ...]:
    """Parse a ``80,443,8000-8100`` port spec into a sorted unique tuple."""
    ports: set[int] = set()
    for chunk in spec.replace(" ", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, _, hi_s = chunk.partition("-")
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError:
                continue
            for port in range(min(lo, hi), max(lo, hi) + 1):
                if 1 <= port <= 65535:
                    ports.add(port)
        else:
            try:
                port = int(chunk)
            except ValueError:
                continue
            if 1 <= port <= 65535:
                ports.add(port)
    return tuple(sorted(ports))


def _read_hosts(path: Path) -> list[str]:
    """Read a host list, stripping scheme/path/port and blank/comment lines."""
    hosts: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Accept "https://host:port/path", "host:port", or bare "host".
        line = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", line)
        line = line.split("/", 1)[0].split("@")[-1]
        if line.count(":") == 1:
            line = line.split(":", 1)[0]
        host = line.strip(".").lower()
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts


# --------------------------------------------------------------------------- #
# Port discovery
# --------------------------------------------------------------------------- #
def _scan_python(
    hosts: list[str], ports: tuple[int, ...], *, timeout: float, workers: int
) -> dict[str, set[int]]:
    """Threaded pure-Python TCP connect scan (no external tooling required)."""
    targets = [(host, port) for host in hosts for port in ports]
    open_ports: dict[str, set[int]] = {host: set() for host in hosts}

    def probe(target: tuple[str, int]) -> tuple[str, int, bool]:
        host, port = target
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return host, port, True
        except OSError:
            return host, port, False

    max_workers = max(1, min(workers, len(targets) or 1))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for host, port, is_open in pool.map(probe, targets):
            if is_open:
                open_ports[host].add(port)
    return open_ports


def _scan_naabu(hosts, ports, *, timeout, workers, hosts_file) -> dict[str, set[int]] | None:
    ports_arg = ",".join(str(p) for p in ports)
    cmd = ["naabu", "-silent", "-list", str(hosts_file), "-p", ports_arg,
           "-c", str(max(1, workers)), "-json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        LOGGER.warning("naabu failed (%s); falling back", error)
        return None
    result: dict[str, set[int]] = {host: set() for host in hosts}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = str(rec.get("host") or rec.get("ip") or "").lower()
        port = rec.get("port")
        if host in result and isinstance(port, int):
            result[host].add(port)
    return result


def _resolve_hosts(hosts: list[str]) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Resolve hostnames to IPs.

    Returns ``(ip_to_hosts, host_to_ips)``. A host that does not resolve is
    simply absent from ``host_to_ips``. This is what makes CDN/shared-IP targets
    work: several hostnames commonly resolve to one IP, and port state is a
    property of the IP, so results must be fanned back out to every hostname on
    that IP rather than matched by the name nmap happens to print.
    """
    def resolve(host: str) -> tuple[str, set[str]]:
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError:
            return host, set()
        return host, {info[4][0] for info in infos}

    ip_to_hosts: dict[str, set[str]] = {}
    host_to_ips: dict[str, set[str]] = {}
    workers = max(1, min(64, len(hosts) or 1))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for host, ips in pool.map(resolve, hosts):
            if not ips:
                continue
            host_to_ips[host] = ips
            for ip in ips:
                ip_to_hosts.setdefault(ip, set()).add(host)
    return ip_to_hosts, host_to_ips


def _parse_nmap_grepable(text: str) -> dict[str, set[int]]:
    """Parse nmap greppable output into ``{ip: {open_ports}}``.

    Pure function (no subprocess) so the IP-centric mapping -- the part that broke
    on CDN targets -- is unit-testable. Greppable lines look like:
    ``Host: <ip> (<name>)\\tPorts: 80/open/tcp//http///, 443/open/tcp//https///``.
    """
    by_ip: dict[str, set[int]] = {}
    for line in text.splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        m = re.match(r"Host:\s+(\S+)", line)
        if not m:
            continue
        ip = m.group(1)
        for pm in re.finditer(r"(\d+)/open/", line):
            by_ip.setdefault(ip, set()).add(int(pm.group(1)))
    return by_ip


def _scan_nmap(hosts, ports, *, timeout, hosts_file) -> dict[str, set[int]] | None:
    """Scan with nmap, keyed correctly even when hostnames share an IP (CDNs).

    We resolve the hostnames ourselves, scan the *unique IPs*, parse open ports by
    IP, then fan each IP's open ports back out to every hostname that resolved to
    it. Feeding nmap hostnames and matching on the name it prints (a PTR record for
    CDN IPs, or nothing) silently dropped every result on gala.com -- this avoids
    that entirely.
    """
    ip_to_hosts, _ = _resolve_hosts(hosts)
    unique_ips = sorted(ip_to_hosts)
    if not unique_ips:
        return {host: set() for host in hosts}
    ports_arg = ",".join(str(p) for p in ports)
    cmd = ["nmap", "-Pn", "-T4", "--open", "-p", ports_arg, "-oG", "-", *unique_ips]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        LOGGER.warning("nmap failed (%s); falling back", error)
        return None
    by_ip = _parse_nmap_grepable(proc.stdout)
    result: dict[str, set[int]] = {host: set() for host in hosts}
    for ip, open_ports in by_ip.items():
        for host in ip_to_hosts.get(ip, ()):  # fan out to every name on this IP
            result[host].update(open_ports)
    return result


def discover_ports(
    hosts: list[str],
    ports: tuple[int, ...],
    *,
    timeout: float,
    workers: int,
    hosts_file: Path,
    prefer_tools: bool = True,
) -> tuple[dict[str, set[int]], str]:
    """Return ``{host: {open_ports}}`` and the name of the scanner used."""
    if prefer_tools:
        # naabu handles hostname lists natively and is fastest; masscan needs
        # resolved IPs so we skip it for hostname input and let nmap/naabu win.
        if shutil.which("naabu"):
            result = _scan_naabu(hosts, ports, timeout=timeout, workers=workers, hosts_file=hosts_file)
            if result is not None:
                return result, "naabu"
        if shutil.which("nmap"):
            # Budget nmap generously; it resolves names itself.
            result = _scan_nmap(hosts, ports, timeout=max(timeout, 60.0 + len(hosts)), hosts_file=hosts_file)
            if result is not None:
                return result, "nmap"
    return _scan_python(hosts, ports, timeout=timeout, workers=workers), "python-connect"


# --------------------------------------------------------------------------- #
# HTTP(S) confirmation
# --------------------------------------------------------------------------- #
def _http_probe(host: str, port: int, *, timeout: float) -> dict | None:
    """Confirm an open port speaks HTTP; return service metadata or ``None``."""
    schemes = ("https", "http") if port in TLS_PORTS else ("http", "https")
    for scheme in schemes:
        info = _try_scheme(host, port, scheme, timeout=timeout)
        if info is not None:
            return info
    return None


def _try_scheme(host: str, port: int, scheme: str, *, timeout: float) -> dict | None:
    import urllib.error
    import urllib.request

    # Skip the obvious mismatches quickly (http on 443-family is usually a hang).
    url = f"{scheme}://{host}:{port}/"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "JSIntel/0.2 (+authorized-recon)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(4096)
            return _service_record(host, port, scheme, resp.status, dict(resp.headers), body, resp.geturl(), url)
    except urllib.error.HTTPError as error:  # a real HTTP response (401/403/500...)
        body = b""
        try:
            body = error.read(4096)
        except Exception:  # noqa: BLE001 - body is best-effort
            pass
        # A 400 "plain HTTP request was sent to HTTPS port" is a protocol mismatch,
        # not a service on this scheme -- reject so the caller tries the other scheme
        # (and so it is not recorded as a bogus finding).
        if error.code == 400 and b"HTTPS port" in body:
            return None
        return _service_record(host, port, scheme, error.code, dict(error.headers or {}), body, url, url)
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError, ValueError):
        return None


def _detect_cdn(headers: dict, server: str, title: str) -> str:
    """Return a CDN name if the response carries CDN fronting markers, else ''.

    A CDN-fronted host answers on the CDN's whole published alternate-port matrix
    (Cloudflare: 2082/2083/2086/2087/2095/2096/8080/8443/8880 ...) with the same
    origin, or with a CDN block page -- none of which is a distinct service. The
    marker headers let us recognise and collapse that noise per host.
    """
    lower = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    if "cf-ray" in lower or "cloudflare" in server.lower() or "cloudflare" in title.lower():
        return "cloudflare"
    if "x-amz-cf-id" in lower or "cloudfront" in server.lower():
        return "cloudfront"
    if "x-akamai-" in " ".join(lower) or "akamai" in server.lower():
        return "akamai"
    if "x-fastly" in " ".join(lower) or "fastly" in server.lower():
        return "fastly"
    return ""


def _service_record(host, port, scheme, status, headers, body, final_url, url) -> dict:
    title = ""
    m = _TITLE_RE.search(body or b"")
    if m:
        title = m.group(1).decode("utf-8", "ignore").strip()[:200]
        title = re.sub(r"\s+", " ", title)
    server = ""
    for key, value in (headers or {}).items():
        if key.lower() == "server":
            server = str(value)[:200]
            break
    body = body or b""
    return {
        "host": host,
        "port": port,
        "scheme": scheme,
        "url": f"{scheme}://{host}:{port}/",
        "status": int(status),
        "server": server,
        "title": title,
        "cdn": _detect_cdn(headers, server, title),
        "length": len(body),
        # Fingerprint of the response body, used to collapse a CDN that echoes the
        # same site across a matrix of alternate ports (Cloudflare's 2082/2083/8443/...).
        "sig": hashlib.sha1(body[:2048]).hexdigest()[:16],
        "redirect": final_url if final_url and final_url != url else "",
        "mirror_of": "",
    }


def mark_port_mirrors(services: list[dict]) -> int:
    """Flag alt-port services that merely echo a host's canonical 80/443 site.

    A host behind a CDN often answers on many alternate ports (Cloudflare exposes
    2082/2083/2086/2087/2095/2096/8080/8443/8880 ...) with byte-identical content to
    its :443 site. Those are not distinct services. For each host we pick a canonical
    response (:443, else :80) and mark every non-standard-port service whose (status,
    body-fingerprint) matches it as ``mirror_of`` that canonical URL. Returns the
    number marked. The records stay in ports.json for transparency; callers exclude
    mirrors from the distinct-service list fed to the crawler/fuzzer.
    """
    by_host: dict[str, list[dict]] = {}
    for svc in services:
        by_host.setdefault(svc["host"], []).append(svc)
    marked = 0
    for host, recs in by_host.items():
        canonical = next((r for r in recs if r["port"] == 443), None) \
            or next((r for r in recs if r["port"] == 80), None)
        # A host is CDN-fronted if any of its responses carries a CDN marker; then
        # its alternate ports are the CDN's proxy ports (same origin or a CDN block
        # page), not distinct services, so all are collapsed regardless of body.
        host_cdn = next((r.get("cdn") for r in recs if r.get("cdn")), "")
        if canonical is None and not host_cdn:
            continue
        fingerprint = (canonical["status"], canonical.get("sig")) if canonical else None
        anchor = canonical["url"] if canonical else f"cdn:{host_cdn}"
        for rec in recs:
            if rec is canonical or rec["port"] in (80, 443):
                continue
            if fingerprint is not None and (rec["status"], rec.get("sig")) == fingerprint:
                rec["mirror_of"] = canonical["url"]
                marked += 1
            elif host_cdn or rec.get("cdn"):
                rec["mirror_of"] = anchor
                marked += 1
    return marked


def confirm_web_services(
    open_ports: dict[str, set[int]], *, timeout: float, workers: int
) -> list[dict]:
    """HTTP-probe every open port; return confirmed web-service records."""
    targets = [(host, port) for host, ports in open_ports.items() for port in sorted(ports)]
    if not targets:
        return []
    services: list[dict] = []
    max_workers = max(1, min(workers, len(targets)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_http_probe, h, p, timeout=timeout): (h, p) for h, p in targets}
        for future in concurrent.futures.as_completed(futures):
            record = future.result()
            if record is not None:
                services.append(record)
    services.sort(key=lambda r: (r["host"], r["port"]))
    return services


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def run(
    output: Path,
    hosts_file: Path,
    *,
    ports: tuple[int, ...] = DEFAULT_WEB_PORTS,
    connect_timeout: float = 2.0,
    http_timeout: float = 8.0,
    workers: int = 100,
    prefer_tools: bool = True,
) -> dict:
    """Discover and confirm web services; write services.txt and ports.json."""
    hosts = _read_hosts(hosts_file)
    services_path = output / "assets" / "services.txt"
    ports_path = output / "reports" / "ports.json"
    services_path.parent.mkdir(parents=True, exist_ok=True)
    ports_path.parent.mkdir(parents=True, exist_ok=True)

    if not hosts:
        services_path.write_text("", encoding="utf-8")
        ports_path.write_text("[]\n", encoding="utf-8")
        return {"hosts": 0, "open_ports": 0, "services": 0, "scanner": "none", "extra_services": 0}

    open_ports, scanner = discover_ports(
        hosts, ports, timeout=connect_timeout, workers=workers,
        hosts_file=hosts_file, prefer_tools=prefer_tools,
    )
    open_count = sum(len(p) for p in open_ports.values())
    LOGGER.info("Port scan (%s): %d open port(s) across %d host(s)", scanner, open_count, len(hosts))

    services = confirm_web_services(open_ports, timeout=http_timeout, workers=workers)
    mirrors = mark_port_mirrors(services)
    # ports.json keeps every confirmed response (with mirror_of annotations) for
    # transparency; the crawler/fuzzer are fed only DISTINCT services so a CDN's
    # port matrix does not multiply the crawl surface by ~10x.
    ports_path.write_text(json.dumps(services, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # Distinct = not a CDN port-mirror AND not a bare 400 (a "Bad Request" to GET /
    # is a proxy/protocol rejection, not a usable web-service root -- common CDN
    # noise on alternate ports). Everything stays in ports.json regardless.
    distinct = [s for s in services if not s.get("mirror_of") and s.get("status") != 400]
    urls = sorted({s["url"] for s in distinct})
    services_path.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")

    # "Extra" services are DISTINCT ones on a non-standard web port (not 80/443).
    extra = sum(1 for s in distinct if s["port"] not in (80, 443))
    if mirrors:
        LOGGER.info("Collapsed %d CDN port-mirror(s) of a host's canonical site", mirrors)
    return {
        "hosts": len(hosts),
        "open_ports": open_count,
        "services": len(distinct),
        "services_all": len(services),
        "port_mirrors": mirrors,
        "extra_services": extra,
        "scanner": scanner,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m modules.portscan",
        description="Discover web services on non-standard ports for authorized hosts.",
    )
    parser.add_argument("--output", required=True, type=Path, help="JSIntel output directory.")
    parser.add_argument("--hosts", required=True, type=Path, help="File of in-scope hosts (one per line).")
    parser.add_argument("--ports", default="", help="Port spec (e.g. 80,443,8000-8100). Default: curated web ports.")
    parser.add_argument("--connect-timeout", type=float, default=2.0, help="TCP connect timeout (Python scan).")
    parser.add_argument("--http-timeout", type=float, default=8.0, help="HTTP(S) probe timeout.")
    parser.add_argument("--workers", type=int, default=100, help="Concurrent probes.")
    parser.add_argument("--no-tools", action="store_true", help="Force the pure-Python scan (ignore naabu/nmap).")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
    if not args.hosts.is_file():
        LOGGER.error("Hosts file not found: %s", args.hosts)
        return 2
    ports = parse_ports(args.ports) if args.ports else DEFAULT_WEB_PORTS
    summary = run(
        args.output, args.hosts, ports=ports,
        connect_timeout=args.connect_timeout, http_timeout=args.http_timeout,
        workers=max(1, args.workers), prefer_tools=not args.no_tools,
    )
    LOGGER.info(
        "Discovered %d web service(s) (%d on non-standard ports) across %d host(s) [scanner: %s].",
        summary["services"], summary["extra_services"], summary["hosts"], summary["scanner"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
