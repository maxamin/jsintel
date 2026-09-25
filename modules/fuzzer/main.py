"""CLI entry point for the JSIntel content-discovery fuzzer.

Live probing requires an explicit ``--scope`` (the authorization allowlist).
Without a scope the tool refuses to send requests and points the operator at
``--dry-run``, which plans and writes candidates without touching the network.
This keeps "authorized targets only" a hard precondition rather than a warning.
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .engine import run
from .models import DEFAULT_FILTER_STATUS, DEFAULT_MATCH_STATUS, FuzzConfig
from .scope import Scope

LOGGER = logging.getLogger("jsintel.fuzzer")


def _status_set(value: str, default: frozenset[int]) -> frozenset[int]:
    if not value:
        return default
    return frozenset(int(code) for code in value.replace(",", " ").split())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m modules.fuzzer",
        description="Fuzz JSIntel-discovered paths against Assetnote wordlists (authorized targets only).",
    )
    parser.add_argument("--output", required=True, type=Path, help="JSIntel output directory (contains reports/).")
    parser.add_argument(
        "--scope",
        action="append",
        default=[],
        help="Authorized host or domain (repeatable, or comma/space separated). Subdomains are included.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Plan candidates and write fuzz.json without sending requests.")
    parser.add_argument("--offline", action="store_true", help="Use only bundled seed wordlists; never download.")
    parser.add_argument("--concurrency", type=int, default=20, help="Maximum concurrent requests (default: 20).")
    parser.add_argument("--delay", type=float, default=0.0, help="Seconds to sleep before each request (throttle).")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default: 10).")
    parser.add_argument("--max-words", type=int, default=1500, help="Max wordlist entries per category (default: 1500).")
    parser.add_argument("--context-depth", type=int, default=2, help="Directory prefixes to fuzz per path (default: 2).")
    parser.add_argument("--max-candidates", type=int, default=20000, help="Hard cap on total candidate URLs.")
    parser.add_argument("--extensions", default="", help="Comma/space separated extensions to also try (e.g. .json,.bak).")
    parser.add_argument("--match-status", default="", help="Override matched HTTP status codes.")
    parser.add_argument("--filter-status", default="", help="Override filtered HTTP status codes.")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow 3xx instead of recording them.")
    parser.add_argument("--no-calibrate", action="store_true", help="Disable per-directory soft-404 calibration.")
    parser.add_argument("--user-agent", default=FuzzConfig().user_agent, help="Request User-Agent header.")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    reports_dir = args.output / "reports"
    if not reports_dir.is_dir():
        LOGGER.error("No reports directory at %s -- run the extractor first.", reports_dir)
        return 2

    scope = Scope.parse(args.scope) if args.scope else Scope()
    if not scope and not args.dry_run:
        LOGGER.error(
            "Refusing to send requests without an authorization scope. "
            "Pass --scope <authorized-domain> for a live run, or --dry-run to only plan candidates."
        )
        return 2

    extensions = tuple(
        ext if ext.startswith(".") else "." + ext
        for ext in args.extensions.replace(",", " ").split()
    )
    config = FuzzConfig(
        concurrency=max(1, args.concurrency),
        delay=max(0.0, args.delay),
        timeout=args.timeout,
        max_words_per_category=max(1, args.max_words),
        context_depth=max(1, args.context_depth),
        max_candidates=max(1, args.max_candidates),
        extensions=extensions,
        match_status=_status_set(args.match_status, DEFAULT_MATCH_STATUS),
        filter_status=_status_set(args.filter_status, DEFAULT_FILTER_STATUS),
        follow_redirects=args.follow_redirects,
        dry_run=args.dry_run,
        offline=args.offline,
        calibrate=not args.no_calibrate,
        user_agent=args.user_agent,
    )

    mode = "dry-run (no requests)" if args.dry_run else f"scope={sorted(scope.hosts)}"
    LOGGER.info("Fuzzing %s [%s]", args.output, mode)
    _results, summary = run(args.output, scope, config)
    LOGGER.info(
        "Read %d finding(s); %d in-scope path(s); %d candidate(s); %d request(s); %d interesting; %d error(s).",
        summary.findings_read,
        summary.in_scope_origins,
        summary.candidates,
        summary.requested,
        summary.interesting,
        summary.errors,
    )
    for category, count in sorted(summary.by_category.items()):
        LOGGER.info("  %-10s %d candidate(s)", category, count)
    LOGGER.info("Report written to %s", reports_dir / "fuzz.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
