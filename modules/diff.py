"""Run-to-run diff for JSIntel output directories.

Compares two completed output directories (an OLD/baseline run and a NEW run) and
reports what changed since the baseline: new/removed hosts, web services,
endpoints, and findings. This is the basis for continuous monitoring -- point it
at last week's output and this week's to surface only the delta.

The report JSONs (``reports/*.json``) are the source of truth; nothing here needs
the database. Both directories are read the same way the reporter reads them, so a
diff works across any two runs regardless of scope or target.

Usage:
    python3 -m modules.diff <old_output_dir> <new_output_dir> [-o <out_dir>]

Writes ``<out_dir>/reports/diff.json`` and ``diff.md`` (out_dir defaults to the
NEW directory). Exit status is 0 always; the caller inspects the report.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit


def _load(path: Path):
    """Load a report JSON list, tolerating a missing/empty/malformed file."""
    try:
        data = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []
    return data if isinstance(data, list) else []


def _host_of(url: str) -> str:
    if not url:
        return ""
    host = urlsplit(url).hostname
    return host.lower() if host else ""


def _index(output: Path) -> dict:
    """Reduce a run's reports to comparable key sets."""
    reports = output / "reports"
    assets = _load(reports / "assets.json")
    endpoints = _load(reports / "endpoints.json")
    findings = _load(reports / "findings.json")
    services = _load(reports / "ports.json")

    hosts: set[str] = set()
    for a in assets:
        h = _host_of(a.get("url", ""))
        if h:
            hosts.add(h)

    svc: dict[str, dict] = {}
    for s in services:
        host = (s.get("host") or _host_of(s.get("url", ""))).lower()
        port = s.get("port")
        if host and port is not None:
            hosts.add(host)
            svc[f"{host}:{port}"] = {
                "host": host, "port": port, "status": s.get("status"),
                "title": s.get("title") or "", "server": s.get("server") or "",
            }

    # Endpoints keyed by host + endpoint path (a path alone is ambiguous across hosts).
    eps: dict[str, dict] = {}
    for e in endpoints:
        host = _host_of(e.get("asset_url", ""))
        ep = e.get("endpoint", "")
        if ep:
            eps[f"{host}|{ep}"] = {"host": host, "endpoint": ep, "kind": e.get("kind", "")}

    # Findings keyed by host + type + severity + value (stable identity of a finding).
    finds: dict[str, dict] = {}
    for f in findings:
        host = _host_of(f.get("asset_url", ""))
        key = f"{host}|{f.get('finding_type','')}|{f.get('severity','')}|{f.get('value','')}"
        finds[key] = {
            "host": host, "finding_type": f.get("finding_type", ""),
            "severity": f.get("severity", ""), "value": f.get("value", ""),
        }

    return {"hosts": hosts, "services": svc, "endpoints": eps, "findings": finds}


def _delta_map(old: dict, new: dict) -> dict:
    """Added/removed for a dict keyed by identity; returns lists of the values."""
    added = [new[k] for k in new.keys() - old.keys()]
    removed = [old[k] for k in old.keys() - new.keys()]
    return {"added": added, "removed": removed}


def build_diff(old_dir: Path, new_dir: Path) -> dict:
    old, new = _index(old_dir), _index(new_dir)
    sev_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "": 0}

    def _sort_finds(items):
        return sorted(items, key=lambda f: (-sev_rank.get(f["severity"], 0), f["host"], f["finding_type"]))

    return {
        "old": str(old_dir), "new": str(new_dir),
        "hosts": {
            "added": sorted(new["hosts"] - old["hosts"]),
            "removed": sorted(old["hosts"] - new["hosts"]),
        },
        "services": _delta_map(old["services"], new["services"]),
        "endpoints": _delta_map(old["endpoints"], new["endpoints"]),
        "findings": {
            "added": _sort_finds(_delta_map(old["findings"], new["findings"])["added"]),
            "removed": _sort_finds(_delta_map(old["findings"], new["findings"])["removed"]),
        },
    }


def _render_md(d: dict) -> str:
    L = ["# JSIntel Run-to-Run Diff", "",
         f"- Baseline (old): `{d['old']}`", f"- Current (new): `{d['new']}`", ""]

    def section(title, added, removed, fmt):
        L.append(f"## {title}  (+{len(added)} / -{len(removed)})")
        if not added and not removed:
            L.append("- no change")
        for x in added:
            L.append(f"- 🟢 **new:** {fmt(x)}")
        for x in removed:
            L.append(f"- 🔴 **gone:** {fmt(x)}")
        L.append("")

    section("Hosts", d["hosts"]["added"], d["hosts"]["removed"], lambda h: h)
    section("Web services", d["services"]["added"], d["services"]["removed"],
            lambda s: f"{s['host']}:{s['port']} ({s.get('status')})" + (f" — {s['title']}" if s.get("title") else ""))
    section("Endpoints", d["endpoints"]["added"], d["endpoints"]["removed"],
            lambda e: f"`{e['endpoint']}` on {e['host'] or '?'} [{e.get('kind','')}]")
    section("Findings", d["findings"]["added"], d["findings"]["removed"],
            lambda f: f"[{f['severity']}] {f['finding_type']} on {f['host'] or '?'}: {f['value']}")
    return "\n".join(L) + "\n"


def write_diff(old_dir: Path, new_dir: Path, out_dir: Path) -> dict:
    d = build_diff(old_dir, new_dir)
    reports = out_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "diff.json").write_text(json.dumps(d, indent=2))
    (reports / "diff.md").write_text(_render_md(d))
    return d


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Diff two JSIntel output directories.")
    p.add_argument("old", type=Path, help="baseline output dir")
    p.add_argument("new", type=Path, help="current output dir")
    p.add_argument("-o", "--out", type=Path, default=None, help="where to write reports/diff.* (default: NEW dir)")
    a = p.parse_args(argv)
    out = a.out or a.new
    d = write_diff(a.old, a.new, out)
    n = lambda k: (len(d[k]["added"]), len(d[k]["removed"]))
    print(json.dumps({
        "hosts": n("hosts"), "services": n("services"),
        "endpoints": n("endpoints"), "findings": n("findings"),
        "report": str((out / "reports" / "diff.md")),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
