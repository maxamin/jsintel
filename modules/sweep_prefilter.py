#!/usr/bin/env python3
"""Drop dead hosts and wildcard-DNS duplicates before a mass sweep runs the pipeline.

In the 2026-10-09 sweep 12,833 of 13,070 targets (98%) produced at most one crawled
asset yet consumed 78% of the sweep's time (p50 39 s each): names that do not answer
over HTTP(S), and names that only exist because a parent domain answers every label
(``asia.kwenta.eth.limo``, ``crashplan.app.spot.cash``, ...) and serve the same
catch-all page. This stage sends at most two cheap GETs per target plus one per
wildcard-candidate parent, then:

* **dead**: no HTTP answer on https:// or http:// -> skipped (with ``--keep-resolving``,
  used for port-scan sweeps, only names without an address record are skipped);
* **wildcard duplicate**: the parent answers a random, certainly-unregistered label
  with the same response fingerprint (status, title, redirect shape, size within
  10%) -> only the first such target per parent is kept as the representative.

Kept targets are printed one per line; ``<output>/reports/prefilter.json`` records
every decision. Modes (``--mode``): ``full`` (default), ``wildcard`` (keep dead hosts,
e.g. when a port scan should still look at non-HTTP ports), ``off``.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import secrets
import socket
import sys
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

_TITLE_RE = re.compile(rb"<title[^>]{0,200}>(.{0,300}?)</title>", re.I | re.S)
_READ_LIMIT = 65536


@dataclass(frozen=True, slots=True)
class Fingerprint:
    status: int
    title: str
    redirect: str   # final URL shape with the probed host masked
    length: int

    def matches(self, other: "Fingerprint") -> bool:
        if (self.status, self.title, self.redirect) != (other.status, other.title, other.redirect):
            return False
        big = max(self.length, other.length)
        return big == 0 or abs(self.length - other.length) <= big * 0.10


Fetcher = Callable[[str], "tuple[int, str, bytes] | None"]  # url -> (status, final_url, body)


def requests_fetcher(timeout: float) -> Fetcher:
    """Real fetcher: one GET following redirects, body capped at 64 KiB."""
    import requests
    import urllib3

    warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (JSIntel prefilter)"

    def fetch(url: str):
        try:
            with session.get(url, timeout=timeout, verify=False, stream=True,
                             allow_redirects=True) as response:
                body = response.raw.read(_READ_LIMIT, decode_content=True) or b""
                return response.status_code, response.url, body
        except Exception:  # noqa: BLE001 - any failure means "no HTTP answer"
            return None

    return fetch


def fingerprint(host: str, status: int, final_url: str, body: bytes) -> Fingerprint:
    """Response fingerprint with the probed host masked (catch-alls echo it back)."""
    mask = host.encode()
    text = body.replace(mask, b"{H}")
    match = _TITLE_RE.search(text)
    title = re.sub(rb"\s+", b" ", match.group(1)).strip().decode("utf-8", "replace") if match else ""
    redirect = final_url.replace(host, "{H}")
    redirect = re.sub(r"^https?://", "", redirect)
    return Fingerprint(status, title.lower(), redirect, len(text))


def probe(host: str, fetch: Fetcher) -> Fingerprint | None:
    for scheme in ("https", "http"):
        answer = fetch(f"{scheme}://{host}/")
        if answer is not None:
            return fingerprint(host, *answer)
    return None


def parent_of(host: str) -> str | None:
    """Parent domain worth testing for a wildcard (never a bare TLD or eTLD+1's TLD)."""
    labels = host.split(".")
    return ".".join(labels[1:]) if len(labels) >= 3 else None


def resolves(host: str) -> bool:
    """True when ``host`` has an address record (no traffic to the host itself)."""
    try:
        return bool(socket.getaddrinfo(host, None))
    except OSError:
        return False


def prefilter(targets: list[str], fetch: Fetcher, *, mode: str = "full",
              workers: int = 32, random_label: Callable[[], str] | None = None,
              keep_resolving: bool = False,
              resolver: Callable[[str], bool] = resolves) -> dict:
    """Return ``{"kept": [...], "skipped": {target: reason}, "wildcards": {...}}``."""
    if mode == "off":
        return {"kept": list(targets), "skipped": {}, "wildcards": {}}
    random_label = random_label or (lambda: "jsintel-" + secrets.token_hex(6))
    by_parent: dict[str, list[str]] = {}
    for target in targets:
        parent = parent_of(target)
        if parent:
            by_parent.setdefault(parent, []).append(target)
    # A wildcard only matters where a parent has several targets to collapse.
    parents = [p for p, members in by_parent.items() if len(members) >= 2]
    probes = {p: f"{random_label()}.{p}" for p in parents}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        target_fp = dict(zip(targets, pool.map(lambda t: probe(t, fetch), targets)))
        wild_fp = dict(zip(parents, pool.map(lambda p: probe(probes[p], fetch), parents)))
        # With a port scan (-P), "no answer on 80/443" does not mean dead: a service
        # may listen elsewhere. Only names with no address record are dropped then.
        silent = [t for t in targets if target_fp[t] is None]
        resolving = (set(t for t, ok in zip(silent, pool.map(resolver, silent)) if ok)
                     if keep_resolving and mode == "full" else set())

    kept: list[str] = []
    skipped: dict[str, str] = {}
    representative: dict[str, str] = {}
    for target in targets:
        fp = target_fp[target]
        if fp is None:
            if mode == "full" and target not in resolving:
                skipped[target] = ("dead: no address record" if keep_resolving
                                   else "dead: no HTTP(S) answer")
                continue
            kept.append(target)
            continue
        parent = parent_of(target)
        wild = wild_fp.get(parent) if parent else None
        # Each side was fingerprinted with its own name masked, so a catch-all that
        # echoes the requested host still compares equal.
        if wild is not None and fp.matches(wild):
            first = representative.setdefault(parent, target)
            if first != target:
                skipped[target] = f"wildcard: {parent} answers any name; same page as {first}"
                continue
        kept.append(target)
    wildcards = {p: {"probe": probes[p], "representative": representative.get(p),
                     "collapsed": sum(1 for r in skipped.values() if r.startswith(f"wildcard: {p} "))}
                 for p in parents if wild_fp.get(p) is not None}
    return {"kept": kept, "skipped": skipped, "wildcards": wildcards}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m modules.sweep_prefilter")
    parser.add_argument("--output", required=True, type=Path, help="Sweep output directory.")
    parser.add_argument("--mode", choices=("full", "wildcard", "off"), default="full")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--keep-resolving", action="store_true",
                        help="Keep silent hosts whose name still resolves (for port-scan sweeps).")
    parser.add_argument("targets", nargs="*", help="Targets (default: read from stdin).")
    args = parser.parse_args(argv)
    targets = args.targets or [line.strip() for line in sys.stdin if line.strip()]
    started = time.time()
    result = prefilter(targets, requests_fetcher(args.timeout), mode=args.mode, workers=args.workers,
                       keep_resolving=args.keep_resolving)
    reports = args.output / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    record = {"mode": args.mode, "checked": len(targets), "kept": len(result["kept"]),
              "skipped_dead": sum(r.startswith("dead") for r in result["skipped"].values()),
              "skipped_wildcard": sum(r.startswith("wildcard") for r in result["skipped"].values()),
              "seconds": round(time.time() - started, 1), "wildcards": result["wildcards"],
              "skipped": result["skipped"]}
    (reports / "prefilter.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"prefilter: kept {record['kept']} of {record['checked']} "
          f"(dead {record['skipped_dead']}, wildcard duplicates {record['skipped_wildcard']})",
          file=sys.stderr)
    for target in result["kept"]:
        print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
