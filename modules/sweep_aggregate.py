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
        "endpoints": 0, "security_findings": 0, "fuzz_interesting": 0, "skipped": 0,
    }
    stage_totals: dict[str, dict[str, int]] = {}
    prefilter = _load_json(base / "reports" / "prefilter.json", {})
    skipped = prefilter.get("skipped", {}) if isinstance(prefilter, dict) else {}
    skipped = skipped if isinstance(skipped, dict) else {}

    for target in targets:
        tdir = base / "targets" / sanitize(target)
        reports = tdir / "reports"
        status = "missing"
        status_file = tdir / ".sweep_status"
        if status_file.is_file():
            status = status_file.read_text(encoding="utf-8").strip()
        elif target in skipped:
            status = "skipped: " + str(skipped[target])
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
        for name, st in (summary.get("stages") or {}).items():
            if not isinstance(st, dict):
                continue
            agg_st = stage_totals.setdefault(name, {"targets": 0, "seconds": 0, "failed": 0})
            agg_st["targets"] += 1
            agg_st["seconds"] += int(st.get("seconds", 0) or 0)
            agg_st["failed"] += 1 if st.get("rc") else 0
        rows.append(row)
        totals["targets"] += 1
        totals["ok"] += 1 if status == "ok" else 0
        totals["failed"] += 1 if status.startswith("failed") else 0
        totals["skipped"] += 1 if status.startswith("skipped") else 0
        for key in ("live_subdomains", "web_services", "extra_port_services",
                    "assets", "endpoints", "security_findings"):
            totals[key] += row[key]
        totals["fuzz_interesting"] += row["fuzz_interesting"]

    rows.sort(key=lambda r: (-r["security_findings"], -r["extra_port_services"], r["target"]))
    agg = {"totals": totals, "stages": stage_totals, "targets": rows}

    (base / "reports").mkdir(parents=True, exist_ok=True)
    (base / "reports" / "sweep_summary.json").write_text(
        json.dumps(agg, indent=2) + "\n", encoding="utf-8"
    )

    lines = [
        "# JSIntel Mass Sweep Summary", "",
        f"- Targets: {totals['targets']} ({totals['ok']} ok, {totals['failed']} failed, "
        f"{totals['skipped']} skipped by the pre-filter)",
        f"- Live subdomains: {totals['live_subdomains']}",
        f"- Web services found: {totals['web_services']} "
        f"({totals['extra_port_services']} on non-standard ports)",
        f"- Assets: {totals['assets']}",
        f"- Endpoints: {totals['endpoints']}",
        f"- Security findings (low+): {totals['security_findings']}",
        f"- Fuzz interesting: {totals['fuzz_interesting']}", "",
        "## Stages", "",
        "| Stage | Targets | Total seconds | Failed |", "|---|--:|--:|--:|",
        *[f"| {n} | {v['targets']} | {v['seconds']} | {v['failed']} |"
          for n, v in sorted(stage_totals.items(), key=lambda kv: -kv[1]["seconds"])],
        "",
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


HEALTH_MIN_TARGETS = 50


def health(base: Path, targets: list[str], stages: set[str]) -> list[str]:
    """Warnings for enabled stages that produced nothing on every finished target.

    The 2026-10-09 sweep ran for a week with 0 web services and 0 screenshots on all
    13,070 targets (proxychains broke both) and nothing said so. Needs at least
    HEALTH_MIN_TARGETS finished targets before judging.
    """
    done = 0
    services = shots_tried = shots_ok = dl_total = dl_ok = 0
    for target in targets:
        tdir = base / "targets" / sanitize(target)
        status_file = tdir / ".sweep_status"
        if not status_file.is_file() or status_file.read_text(encoding="utf-8").strip() != "ok":
            continue
        summary = _load_json(tdir / "reports" / "summary.json", {})
        if not isinstance(summary, dict):
            continue
        done += 1
        pipeline = summary.get("pipeline") or {}
        services += int(summary.get("web_services", 0) or 0)
        shots_tried += int(pipeline.get("screenshots_attempted", 0) or 0)
        shots_ok += int(pipeline.get("screenshots_captured", 0) or 0)
        downloads = pipeline.get("downloads") or {}
        dl_total += sum(int(v or 0) for v in downloads.values())
        dl_ok += int(downloads.get("downloaded", 0) or 0)
    if done < HEALTH_MIN_TARGETS:
        return []
    warnings = []
    if "ports" in stages and services == 0:
        warnings.append(f"port scan found 0 web services across {done} finished targets "
                        "(broken scanner? under proxychains? check one target's ports.json)")
    if "webshot" in stages and shots_tried and shots_ok == 0:
        warnings.append(f"0 of {shots_tried} screenshots succeeded across {done} targets "
                        "(Chromium failing? check the webshot stage log)")
    if dl_total >= 100 and dl_ok == 0:
        warnings.append(f"0 of {dl_total} downloads succeeded across {done} targets")
    return warnings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m modules.sweep_aggregate")
    parser.add_argument("--output", required=True, type=Path, help="Sweep output base directory.")
    parser.add_argument("--health", default=None, metavar="STAGES",
                        help="Only check health for these enabled stages (comma list, e.g. "
                             "ports,webshot); print warnings, write nothing.")
    parser.add_argument("targets", nargs="+", help="Target domains that were swept.")
    args = parser.parse_args(argv)
    if args.health is not None:
        for warning in health(args.output, args.targets, set(filter(None, args.health.split(",")))):
            print(f"HEALTH: {warning}")
        return 0
    agg = aggregate(args.output, args.targets)
    t = agg["totals"]
    print(
        f"Aggregated {t['targets']} target(s) "
        f"-> {args.output / 'reports' / 'sweep_summary.md'}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
