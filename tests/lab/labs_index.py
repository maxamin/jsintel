#!/usr/bin/env python3
"""Spawn a "labs index" service on a random free port in [80, 10443].

The index page links to AT LEAST ONE URL for EVERY known lab — both the running
web-application labs (Juice Shop, DVWA, WebGoat, WordPress, Django) and the
blockchain labs from ``~/blockchain-security-labs/ports.json``. Labs that have no
HTTP service of their own (the Foundry/CLI challenge repos) are still represented:
the index serves a same-host stub page for each at ``/lab/<name>`` that names the
lab and links to its real URL (when one exists).

The port is chosen at random from 80..10443 and verified free, so JSIntel's port
scanner has to actually *scan that range* to discover the service — after which its
crawler mines the per-lab links out of the index. This is a self-contained
discovery target for exercising the port-scan -> crawl -> extract path end to end.

Usage:
  python3 tests/lab/labs_index.py                 # random free port, serve forever
  python3 tests/lab/labs_index.py --port 8123     # fixed port
  python3 tests/lab/labs_index.py --print-only     # build + print the index, exit
  python3 tests/lab/labs_index.py --extra-lab name=http://host/path   # add a lab
"""
from __future__ import annotations

import argparse
import html
import json
import random
import socket
import sys
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote

MIN_PORT = 80
MAX_PORT = 10443
DEFAULT_REGISTRY = Path.home() / "blockchain-security-labs" / "ports.json"


@dataclass(frozen=True)
class Lab:
    name: str          # stable slug used in /lab/<name>
    title: str         # human title
    url: str           # real lab URL, or "" for CLI/no-HTTP labs
    kind: str = ""     # web | chain | foundry-cli | ...
    note: str = ""


def web_default_labs() -> list[Lab]:
    """The running web-application security labs (loopback estate)."""
    return [
        Lab("juice-shop", "OWASP Juice Shop", "http://127.0.0.1:3000/", "web"),
        Lab("dvwa", "Damn Vulnerable Web App", "http://127.0.0.3:8081/", "web"),
        Lab("webgoat", "WebGoat", "http://127.0.0.2:8082/WebGoat/login", "web"),
        Lab("wordpress", "WordPress", "http://127.0.0.8:8083/", "web"),
        Lab("django", "Django vuln app", "http://127.0.0.11:8092/", "web"),
    ]


def registry_labs(registry_path: Path) -> list[Lab]:
    """Blockchain labs from ports.json (anvil/ethernaut carry a URL; CLI labs don't)."""
    labs: list[Lab] = []
    try:
        reg = json.loads(Path(registry_path).read_text())
    except (OSError, json.JSONDecodeError):
        return labs
    for name, meta in (reg.get("apps") or {}).items():
        port = meta.get("port")
        url = f"http://127.0.0.1:{port}/" if port else ""
        labs.append(Lab(name, name, url, meta.get("kind", ""), meta.get("note", "")))
    return labs


def discover_labs(registry_path: Path | None = DEFAULT_REGISTRY,
                  include_web: bool = True,
                  extra: list[Lab] | None = None) -> list[Lab]:
    """Merge web + blockchain + extra labs, de-duplicated by name (first wins)."""
    out: list[Lab] = []
    seen: set[str] = set()
    for lab in ((web_default_labs() if include_web else [])
                + (registry_labs(registry_path) if registry_path else [])
                + (extra or [])):
        if lab.name in seen:
            continue
        seen.add(lab.name)
        out.append(lab)
    return out


def build_index_html(labs: list[Lab], base_url: str) -> str:
    """Index page: one entry per lab, each linking to its /lab/<name> stub."""
    rows = []
    for lab in labs:
        stub = f"{base_url}/lab/{quote(lab.name)}"
        real = (f' &middot; <a href="{html.escape(lab.url)}">{html.escape(lab.url)}</a>'
                if lab.url else " &middot; <em>CLI/Foundry lab (no HTTP service)</em>")
        rows.append(
            f'<li id="lab-{html.escape(lab.name)}">'
            f'<a href="{html.escape(stub)}">{html.escape(lab.title)}</a>'
            f' <span class="kind">[{html.escape(lab.kind or "lab")}]</span>{real}</li>'
        )
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        "<title>Security Labs Index</title></head><body>"
        "<h1>Security Labs Index</h1>"
        f"<p>{len(labs)} labs. Every lab below is linked at least once.</p>"
        "<ul>" + "".join(rows) + "</ul></body></html>"
    )


def build_lab_stub_html(lab: Lab, base_url: str) -> str:
    real = (f'<p><a href="{html.escape(lab.url)}">{html.escape(lab.url)}</a></p>'
            if lab.url else "<p><em>No HTTP service — Foundry/CLI challenge repo.</em></p>")
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        f"<title>{html.escape(lab.title)}</title></head><body>"
        f"<h1>{html.escape(lab.title)}</h1><p>kind: {html.escape(lab.kind or 'lab')}</p>"
        f"{real}"
        f"<p>{html.escape(lab.note)}</p>"
        f'<p><a href="{html.escape(base_url)}/">&larr; back to index</a></p>'
        "</body></html>"
    )


def pick_free_port(lo: int = MIN_PORT, hi: int = MAX_PORT, host: str = "127.0.0.1",
                   rng: random.Random | None = None, attempts: int = 500) -> int:
    """Return a random port in [lo, hi] that is bindable (free) on ``host``.

    Raises RuntimeError if no free port is found within ``attempts`` tries.
    """
    rng = rng or random.Random()
    for _ in range(attempts):
        port = rng.randint(lo, hi)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"no free port found in [{lo}, {hi}] on {host}")


class _IndexHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep the console quiet
        pass

    def _send(self, body: str, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        labs: list[Lab] = self.server.labs            # type: ignore[attr-defined]
        base: str = self.server.base_url              # type: ignore[attr-defined]
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/":
            self._send(build_index_html(labs, base))
            return
        if path.startswith("/lab/"):
            name = path[len("/lab/"):]
            for lab in labs:
                if lab.name == name:
                    self._send(build_lab_stub_html(lab, base))
                    return
        self._send("<h1>404</h1>", 404)


def make_server(host: str, port: int, labs: list[Lab]) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), _IndexHandler)
    srv.labs = labs                                   # type: ignore[attr-defined]
    srv.base_url = f"http://{host}:{port}"            # type: ignore[attr-defined]
    return srv


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Spawn a labs index on a random free port (80..10443).")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=None, help="fixed port (default: random free in range)")
    p.add_argument("--min-port", type=int, default=MIN_PORT)
    p.add_argument("--max-port", type=int, default=MAX_PORT)
    p.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY,
                   help="blockchain-lab ports.json to pull labs from")
    p.add_argument("--no-web", action="store_true", help="omit the built-in web-app labs")
    p.add_argument("--extra-lab", action="append", default=[], metavar="name=url",
                   help="add a lab (repeatable), e.g. --extra-lab custom=http://127.0.0.1:9/")
    p.add_argument("--seed", type=int, default=None, help="seed the random port choice")
    p.add_argument("--url-file", type=Path, default=DEFAULT_REGISTRY.parent / "labs_index_url.txt",
                   help="write the chosen index URL here")
    p.add_argument("--print-only", action="store_true", help="build + print the index HTML and exit")
    return p


def _parse_extra(items: list[str]) -> list[Lab]:
    labs = []
    for it in items:
        name, _, url = it.partition("=")
        if name:
            labs.append(Lab(name, name, url, "extra"))
    return labs


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    labs = discover_labs(registry_path=None if args.no_web and not args.registry else args.registry,
                         include_web=not args.no_web, extra=_parse_extra(args.extra_lab))
    if not labs:
        print("no labs discovered", file=sys.stderr)
        return 1

    if args.print_only:
        print(build_index_html(labs, f"http://{args.host}:0"))
        return 0

    rng = random.Random(args.seed)
    port = args.port or pick_free_port(args.min_port, args.max_port, args.host, rng)
    srv = make_server(args.host, port, labs)
    url = f"http://{args.host}:{port}/"
    try:
        args.url_file.parent.mkdir(parents=True, exist_ok=True)
        args.url_file.write_text(url + "\n")
    except OSError:
        pass
    print(f"labs index serving {len(labs)} labs at {url}  (port {port} in [{args.min_port},{args.max_port}])",
          flush=True)
    print("  labs: " + ", ".join(l.name for l in labs), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
