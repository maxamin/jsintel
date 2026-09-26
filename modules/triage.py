#!/usr/bin/env python3
"""Unified triage report: join services, endpoints, and findings per host.

The pipeline emits assets, endpoints, findings, and services as separate reports.
This module rolls them up into ONE prioritized, per-host view -- "here are the N
hosts that matter and why" -- so an operator does not have to cross-reference five
JSON files by eye. It reads the SQLite DB the reporter already builds and writes
``reports/triage.{json,md,html}``.

Per-host risk score combines three independently-observable signals:

* **Findings** -- severity of extracted security findings (a critical secret or a
  taint-to-sink is what actually matters), weighted so one critical outranks any
  pile of lows.
* **Endpoint sensitivity** -- endpoints that name sensitive surface (``/admin``,
  ``/api/Users``, auth/token/config/debug/graphql/.git ...) raise the score even
  before a finding lands on them; they are where to look next.
* **Exposure** -- a live service on a non-standard port, or one answering 200 with
  no auth, is more reachable and so more exposed.

Scoring is intentionally transparent (small integer weights, no ML) so a human can
see why a host ranks where it does; ``score_breakdown`` is included per host.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
from html import escape
from pathlib import Path
from urllib.parse import urlsplit

# --- Scoring weights -------------------------------------------------------
# One critical (100) dominates any number of lows (3); this ordering is the whole
# point of a triage ranking, so the gaps are deliberately wide.
SEVERITY_WEIGHT = {"critical": 100, "high": 40, "medium": 10, "low": 3, "info": 0}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Endpoint substrings that mark sensitive surface. Matched case-insensitively on the
# endpoint path. Kept small and legible on purpose -- these are triage hints, not a
# vuln scanner. Each distinct sensitive endpoint on a host adds ENDPOINT_HIT_WEIGHT,
# capped by ENDPOINT_SCORE_CAP so a big API surface cannot bury a real finding.
SENSITIVE_ENDPOINT_PATTERNS = [
    "admin", "auth", "login", "logout", "signin", "signup", "register",
    "token", "oauth", "session", "password", "passwd", "secret", "cred",
    "api/users", "api/user", "/users", "account", "profile",
    "config", "settings", "debug", "internal", "private", "actuator",
    "graphql", "graphiql", "swagger", "openapi", "console", "dashboard",
    "upload", "export", "backup", "dump", ".git", ".env", "phpinfo",
    "key", "apikey", "jwt", "2fa", "mfa", "sudo", "root", "shell",
]
ENDPOINT_HIT_WEIGHT = 4
ENDPOINT_SCORE_CAP = 40

# Exposure signals from the service inventory.
NONSTANDARD_PORT_WEIGHT = 5      # a live web service off :80/:443 is extra surface
OPEN_200_NOAUTH_WEIGHT = 2       # answers 200 with no auth challenge
EXPOSURE_SCORE_CAP = 30

_SENSITIVE_RE = re.compile("|".join(re.escape(p) for p in SENSITIVE_ENDPOINT_PATTERNS), re.I)


def _host_of(url: str) -> str:
    """Hostname for grouping; falls back to the raw string when unparseable."""
    if not url:
        return ""
    host = urlsplit(url).hostname
    if host:
        return host.lower()
    # Endpoints are often bare paths ("/api/x"); those have no host of their own and
    # are attributed to their asset's host by the caller, so this only trips on junk.
    return ""


def is_sensitive_endpoint(endpoint: str) -> bool:
    """True when the endpoint names sensitive surface (admin/auth/config/...)."""
    return bool(endpoint) and _SENSITIVE_RE.search(endpoint) is not None


def _max_severity(counts: dict[str, int]) -> str:
    for sev in SEVERITY_ORDER:
        if counts.get(sev):
            return sev
    return "none"


def _mask(value: str, keep: int = 4) -> str:
    """Mask a finding value for the report -- never leak full key material."""
    if not value:
        return ""
    value = value.replace("\n", " ").strip()
    if len(value) <= keep * 2:
        return value[0] + "***" if len(value) > keep else "***"
    return f"{value[:keep]}...{value[-keep:]} (len {len(value)})"


def _has_table(con: sqlite3.Connection, name: str) -> bool:
    return con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def build_triage(con: sqlite3.Connection) -> list[dict]:
    """Build the ranked per-host triage list from an open DB connection."""
    con.row_factory = sqlite3.Row
    hosts: dict[str, dict] = {}

    def host_entry(host: str) -> dict:
        return hosts.setdefault(host, {
            "host": host,
            "findings_by_severity": {},
            "top_findings": [],
            "endpoints": set(),
            "sensitive_endpoints": set(),
            "services": [],
        })

    # Findings, joined to their asset's host.
    for r in con.execute(
        "SELECT a.url AS asset_url, f.finding_type, f.severity, f.value "
        "FROM findings f JOIN assets a ON a.id=f.asset_id"
    ):
        host = _host_of(r["asset_url"])
        if not host:
            continue
        sev = (r["severity"] or "info").lower()
        # 'info' rows are code-structure inventory (call_graph/class), not security
        # issues; the reporter already excludes them from "security findings", so the
        # triage ranking excludes them too. They stay out of the score entirely.
        if sev == "info":
            continue
        e = host_entry(host)
        e["findings_by_severity"][sev] = e["findings_by_severity"].get(sev, 0) + 1
        e["top_findings"].append({
            "type": r["finding_type"], "severity": sev, "value": _mask(r["value"] or ""),
        })

    # Endpoints, joined to their asset's host.
    for r in con.execute(
        "SELECT a.url AS asset_url, e.endpoint FROM endpoints e JOIN assets a ON a.id=e.asset_id"
    ):
        host = _host_of(r["asset_url"])
        ep = r["endpoint"] or ""
        if not host or not ep:
            continue
        e = host_entry(host)
        e["endpoints"].add(ep)
        if is_sensitive_endpoint(ep):
            e["sensitive_endpoints"].add(ep)

    # Services (may be absent on an older DB or a run without a port scan).
    if _has_table(con, "services"):
        for r in con.execute(
            "SELECT host,port,scheme,url,status,server,title,mirror_of,screenshot_path,cluster "
            "FROM services WHERE mirror_of IS NULL OR mirror_of=''"
        ):
            host = (r["host"] or _host_of(r["url"])).lower()
            if not host:
                continue
            e = host_entry(host)
            e["services"].append({
                "url": r["url"], "port": r["port"], "scheme": r["scheme"],
                "status": r["status"], "server": r["server"], "title": r["title"],
                "screenshot": r["screenshot_path"], "cluster": r["cluster"],
                "nonstandard_port": r["port"] not in (80, 443),
            })

    result = [_finalize_host(e) for e in hosts.values()]
    # Highest risk first; ties broken by host name for a stable, diffable order.
    result.sort(key=lambda h: (-h["risk_score"], h["host"]))
    return result


def _finalize_host(e: dict) -> dict:
    counts = e["findings_by_severity"]
    finding_score = sum(SEVERITY_WEIGHT.get(sev, 0) * n for sev, n in counts.items())
    endpoint_score = min(len(e["sensitive_endpoints"]) * ENDPOINT_HIT_WEIGHT, ENDPOINT_SCORE_CAP)
    exposure = 0
    for svc in e["services"]:
        if svc["nonstandard_port"]:
            exposure += NONSTANDARD_PORT_WEIGHT
        if svc.get("status") == 200:
            exposure += OPEN_200_NOAUTH_WEIGHT
    exposure = min(exposure, EXPOSURE_SCORE_CAP)
    risk = finding_score + endpoint_score + exposure

    # Show the worst findings first, capped so the report stays readable.
    top = sorted(e["top_findings"],
                 key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else 99)
    return {
        "host": e["host"],
        "risk_score": risk,
        "max_severity": _max_severity(counts),
        "score_breakdown": {"findings": finding_score, "endpoints": endpoint_score, "exposure": exposure},
        "findings_by_severity": {s: counts[s] for s in SEVERITY_ORDER if s in counts},
        "finding_count": sum(counts.values()),
        "top_findings": top[:10],
        "service_count": len(e["services"]),
        "services": sorted(e["services"], key=lambda s: (s.get("port") or 0)),
        "endpoint_count": len(e["endpoints"]),
        "sensitive_endpoints": sorted(e["sensitive_endpoints"]),
    }


# --- Rendering -------------------------------------------------------------
def render_markdown(triage: list[dict]) -> str:
    lines = ["# JSIntel Triage — hosts that matter, ranked", ""]
    if not triage:
        lines += ["_No hosts with findings, endpoints, or services to rank._", ""]
        return "\n".join(lines) + "\n"
    lines += [
        f"- Hosts ranked: {len(triage)}",
        f"- Hosts with a critical/high finding: "
        f"{sum(1 for h in triage if h['max_severity'] in ('critical','high'))}",
        "",
        "| Rank | Host | Risk | Max sev | Findings | Sensitive eps | Services |",
        "|---:|---|---:|---|---|---:|---:|",
    ]
    for i, h in enumerate(triage, 1):
        sev_line = ", ".join(f"{s} {h['findings_by_severity'][s]}"
                             for s in SEVERITY_ORDER if s in h["findings_by_severity"]) or "—"
        lines.append(
            f"| {i} | {h['host']} | {h['risk_score']} | {h['max_severity']} | "
            f"{sev_line} | {len(h['sensitive_endpoints'])} | {h['service_count']} |"
        )
    lines.append("")
    for h in triage:
        lines += [f"## {h['host']} — risk {h['risk_score']} ({h['max_severity']})", ""]
        b = h["score_breakdown"]
        lines.append(f"- Score: findings {b['findings']} + endpoints {b['endpoints']} + exposure {b['exposure']}")
        if h["services"]:
            lines.append("- Services:")
            for s in h["services"]:
                flag = " ⚠ non-standard port" if s["nonstandard_port"] else ""
                title = f" — {s['title']}" if s.get("title") else ""
                lines.append(f"  - {s['url']} ({s.get('status','?')}){title}{flag}")
        if h["top_findings"]:
            lines.append("- Top findings:")
            for f in h["top_findings"]:
                lines.append(f"  - [{f['severity']}] {f['type']}: `{f['value']}`")
        if h["sensitive_endpoints"]:
            shown = h["sensitive_endpoints"][:15]
            more = f" (+{len(h['sensitive_endpoints']) - len(shown)} more)" if len(h["sensitive_endpoints"]) > len(shown) else ""
            lines.append(f"- Sensitive endpoints: {', '.join('`'+e+'`' for e in shown)}{more}")
        lines.append("")
    return "\n".join(lines) + "\n"


_SEV_COLOR = {"critical": "#b3123b", "high": "#d14400", "medium": "#b07a00",
              "low": "#3a6ea5", "none": "#6b7280", "info": "#6b7280"}


def render_html(triage: list[dict]) -> str:
    rows = []
    for i, h in enumerate(triage, 1):
        color = _SEV_COLOR.get(h["max_severity"], "#6b7280")
        eps = ", ".join(escape(e) for e in h["sensitive_endpoints"][:8])
        svcs = "<br>".join(
            f"{escape(s['url'])} <span class=dim>({s.get('status','?')})</span>"
            + (" <span class=warn>alt-port</span>" if s["nonstandard_port"] else "")
            for s in h["services"]
        )
        finds = "<br>".join(
            f"<span class=sev style='color:{_SEV_COLOR.get(f['severity'],'#333')}'>{escape(f['severity'])}</span> "
            f"{escape(f['type'])}: <code>{escape(f['value'])}</code>"
            for f in h["top_findings"]
        )
        rows.append(f"""<tr>
  <td class=rank>{i}</td>
  <td><div class=host>{escape(h['host'])}</div><div class=dim>{h['endpoint_count']} endpoints · {h['service_count']} services</div></td>
  <td class=score><span class=badge style='background:{color}'>{h['risk_score']}</span><div class=dim>{escape(h['max_severity'])}</div></td>
  <td>{finds or '<span class=dim>—</span>'}</td>
  <td>{svcs or '<span class=dim>—</span>'}</td>
  <td class=eps>{eps or '<span class=dim>—</span>'}</td>
</tr>""")
    body = "\n".join(rows) or "<tr><td colspan=6 class=dim>No hosts to rank.</td></tr>"
    total = len(triage)
    crit = sum(1 for h in triage if h["max_severity"] in ("critical", "high"))
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>JSIntel Triage</title>
<style>
  :root {{ color-scheme: light dark; --bg:#fff; --fg:#1a1a1a; --dim:#6b7280; --line:#e5e7eb; --head:#f6f7f9; }}
  @media (prefers-color-scheme: dark) {{ :root {{ --bg:#14161a; --fg:#e6e6e6; --dim:#9aa1ab; --line:#2a2e35; --head:#1c1f25; }} }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:24px; background:var(--bg); color:var(--fg);
    font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }}
  h1 {{ font-size:20px; margin:0 0 4px; }}
  .meta {{ color:var(--dim); margin-bottom:16px; }}
  table {{ border-collapse:collapse; width:100%; }}
  th,td {{ text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:top; }}
  th {{ background:var(--head); position:sticky; top:0; font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:var(--dim); }}
  .rank {{ color:var(--dim); font-variant-numeric:tabular-nums; }}
  .host {{ font-weight:600; }}
  .dim {{ color:var(--dim); font-size:12px; }}
  .warn {{ color:#d14400; font-size:11px; font-weight:600; }}
  .badge {{ color:#fff; padding:2px 9px; border-radius:999px; font-weight:700; font-variant-numeric:tabular-nums; }}
  .score {{ white-space:nowrap; }}
  .sev {{ font-weight:700; text-transform:uppercase; font-size:11px; }}
  code {{ background:color-mix(in srgb, var(--fg) 8%, transparent); padding:1px 4px; border-radius:4px; font-size:12px; word-break:break-all; }}
  .eps {{ font-size:12px; color:var(--dim); max-width:220px; }}
</style></head><body>
<h1>JSIntel Triage</h1>
<div class=meta>{total} hosts ranked · {crit} with a critical/high finding · sorted by risk score</div>
<table><thead><tr>
  <th>#</th><th>Host</th><th>Risk</th><th>Top findings</th><th>Services</th><th>Sensitive endpoints</th>
</tr></thead><tbody>
{body}
</tbody></table>
</body></html>
"""


def write_reports(output: Path, triage: list[dict]) -> dict:
    reports = output / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "triage.json").write_text(json.dumps(triage, indent=2) + "\n", encoding="utf-8")
    (reports / "triage.md").write_text(render_markdown(triage), encoding="utf-8")
    (reports / "triage.html").write_text(render_html(triage), encoding="utf-8")
    return {
        "hosts_ranked": len(triage),
        "hosts_critical_high": sum(1 for h in triage if h["max_severity"] in ("critical", "high")),
        "top_host": triage[0]["host"] if triage else None,
        "top_score": triage[0]["risk_score"] if triage else 0,
    }


def main(output: Path) -> dict:
    db = output / "database" / "recon.db"
    if not db.is_file():
        return write_reports(output, [])
    con = sqlite3.connect(db)
    try:
        triage = build_triage(con)
    finally:
        con.close()
    return write_reports(output, triage)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Build the unified per-host triage report.")
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--config", type=Path)  # accepted for pipeline symmetry; unused
    args = ap.parse_args()
    summary = main(args.output)
    print(json.dumps(summary))
