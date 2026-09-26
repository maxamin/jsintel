#!/usr/bin/env python3
"""Aggregate per-target results from a mass sweep into one rolled-up report.

A mass sweep (``modules/sweep.sh``) runs the full pipeline against each target in
its own ``<output>/targets/<domain>/`` directory. This module reads each target's
per-stage reports and writes ``<output>/reports/sweep_summary.json`` and
``sweep_summary.md`` -- the single place an operator looks to see, across every
target, how many live subdomains, web services (and how many on non-standard
ports), assets, endpoints, security findings, and fuzz hits a sweep produced.

It is a pure function of the files on disk so it can be unit-tested with crafted
per-target directories and re-run standalone against a finished sweep.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _count_lines(path: Path) -> int:
    try:
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    except OSError:
        return 0


def sanitize(target: str) -> str:
    """Match the on-disk directory name sweep.sh uses for a target."""
    return target.replace("/", "_").replace(":", "_")


def aggregate(base: Path, targets: list[str]) -> dict:
    """Build the aggregate structure and write sweep_summary.{json,md}."""
    rows: list[dict] = []
    totals = {
        "targets": 0, "ok": 0, "failed": 0, "live_subdomains": 0,
        "web_services": 0, "extra_port_services": 0, "assets": 0,
        "endpoints": 0, "security_findings": 0, "fuzz_interesting": 0,
    }

    for target in targets:
        tdir = base / "targets" / sanitize(target)
        reports = tdir / "reports"
        status = "missing"
        status_file = tdir / ".sweep_status"
        if status_file.is_file():
            status = status_file.read_text(encoding="utf-8").strip()
        summary = _load_json(reports / "summary.json", {})
        summary = summary if isinstance(summary, dict) else {}
        fuzz = _load_json(reports / "fuzz_summary.json", {})
        fuzz = fuzz if isinstance(fuzz, dict) else {}
        ports = _load_json(reports / "ports.json", [])
        ports = ports if isinstance(ports, list) else []
        extra_ports = sum(1 for s in ports if isinstance(s, dict) and s.get("port") not in (80, 443))
        row = {
            "target": target,
            "status": status,
            "live_subdomains": _count_lines(tdir / "assets" / "subdomains.txt"),
            "web_services": len(ports),
            "extra_port_services": extra_ports,
            "assets": summary.get("total_assets", 0),
            "endpoints": summary.get("endpoint_count", 0),
            "security_findings": summary.get("security_finding_count", 0),
            "fuzz_probed": fuzz.get("requested", 0),
            "fuzz_interesting": fuzz.get("interesting", 0),
            "output": str(tdir),
        }
        rows.append(row)
        totals["targets"] += 1
        totals["ok"] += 1 if status == "ok" else 0
        totals["failed"] += 1 if status.startswith("failed") else 0
        for key in ("live_subdomains", "web_services", "extra_port_services",
                    "assets", "endpoints", "security_findings"):
            totals[key] += row[key]
        totals["fuzz_interesting"] += row["fuzz_interesting"]

    rows.sort(key=lambda r: (-r["security_findings"], -r["extra_port_services"], r["target"]))
    agg = {"totals": totals, "targets": rows}

    (base / "reports").mkdir(parents=True, exist_ok=True)
    (base / "reports" / "sweep_summary.json").write_text(
        json.dumps(agg, indent=2) + "\n", encoding="utf-8"
    )

    lines = [
        "# JSIntel Mass Sweep Summary", "",
        f"- Targets: {totals['targets']} ({totals['ok']} ok, {totals['failed']} failed)",
        f"- Live subdomains: {totals['live_subdomains']}",
        f"- Web services found: {totals['web_services']} "
        f"({totals['extra_port_services']} on non-standard ports)",
        f"- Assets: {totals['assets']}",
        f"- Endpoints: {totals['endpoints']}",
        f"- Security findings (low+): {totals['security_findings']}",
        f"- Fuzz interesting: {totals['fuzz_interesting']}", "",
        "## Per-target", "",
        "| Target | Status | Subs | WebSvc | AltPort | Assets | Endpoints | SecFind | FuzzHits |",
        "|---|---|--:|--:|--:|--:|--:|--:|--:|",
    ]
    for r in rows:
        lines.append(
            f"| {r['target']} | {r['status']} | {r['live_subdomains']} | {r['web_services']} | "
            f"{r['extra_port_services']} | {r['assets']} | {r['endpoints']} | "
            f"{r['security_findings']} | {r['fuzz_interesting']} |"
        )
    (base / "reports" / "sweep_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return agg


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m modules.sweep_aggregate")
    parser.add_argument("--output", required=True, type=Path, help="Sweep output base directory.")
    parser.add_argument("targets", nargs="+", help="Target domains that were swept.")
    args = parser.parse_args(argv)
    agg = aggregate(args.output, args.targets)
    t = agg["totals"]
    print(
        f"Aggregated {t['targets']} target(s) "
        f"-> {args.output / 'reports' / 'sweep_summary.md'}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
