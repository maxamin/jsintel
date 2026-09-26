"""Live web-service analysis: security headers, GraphQL introspection, JWTs.

Unlike the extractor analyzers (which read downloaded JS assets), this stage probes
the *live services* discovered by the port scan (``reports/ports.json``) and emits
findings about their runtime posture:

- **Security headers** — missing/weak CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy; server-banner
  disclosure; insecure ``Set-Cookie`` flags.
- **GraphQL introspection** — probes common GraphQL paths; if introspection is
  enabled (schema returned), that is a high-severity finding.
- **JWT** — scans response headers/bodies for JWTs and flags dangerous algorithms
  (``alg: none``) or symmetric signing.

Findings are written to ``reports/security.json`` in the same shape as
``findings.json`` (``asset_url`` = the service URL), so the database ingest attaches
them to the service and the triage report surfaces them per host.

Only services already inside the authorized scope (i.e. produced by the scope-gated
port scan) are ever probed; nothing new is discovered here.

Usage: ``python3 -m modules.liveanalysis --output <dir>``
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from modules import authutil

TIMEOUT = 8
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/graphql/console", "/graphiql")
INTROSPECTION_QUERY = '{"query":"{__schema{types{name}}}"}'


def _finding(url, ftype, severity, value, sink=""):
    return {"asset_url": url, "finding_type": ftype, "severity": severity,
            "value": value, "source": "live-service", "sink": sink}


# --- Pure analyzers (no I/O) -------------------------------------------------

def analyze_security_headers(url: str, scheme: str, headers: dict, cookies: list[str]) -> list[dict]:
    """Evaluate response headers/cookies for a live service. `headers` keys are lowercased."""
    out: list[dict] = []
    h = {k.lower(): v for k, v in headers.items()}
    is_https = scheme == "https"

    if "content-security-policy" not in h:
        out.append(_finding(url, "missing_security_header", "medium",
                            "No Content-Security-Policy header", "Content-Security-Policy"))
    if "x-content-type-options" not in h or "nosniff" not in h.get("x-content-type-options", "").lower():
        out.append(_finding(url, "missing_security_header", "low",
                            "No X-Content-Type-Options: nosniff", "X-Content-Type-Options"))
    csp = h.get("content-security-policy", "")
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        out.append(_finding(url, "clickjacking", "low",
                            "No X-Frame-Options and no CSP frame-ancestors", "X-Frame-Options"))
    if is_https and "strict-transport-security" not in h:
        out.append(_finding(url, "missing_security_header", "medium",
                            "HTTPS service without Strict-Transport-Security", "Strict-Transport-Security"))
    if "referrer-policy" not in h:
        out.append(_finding(url, "missing_security_header", "info",
                            "No Referrer-Policy header", "Referrer-Policy"))
    if "permissions-policy" not in h:
        out.append(_finding(url, "missing_security_header", "info",
                            "No Permissions-Policy header", "Permissions-Policy"))

    banner = h.get("server", "") or ""
    powered = h.get("x-powered-by", "") or ""
    # A bare product name is fine; a version string is disclosure.
    if banner and re.search(r"\d", banner):
        out.append(_finding(url, "information_disclosure", "low", f"Server banner: {banner}", "Server"))
    if powered:
        out.append(_finding(url, "information_disclosure", "low", f"X-Powered-By: {powered}", "X-Powered-By"))

    for c in cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        if "httponly" not in low:
            out.append(_finding(url, "insecure_cookie", "medium", f"Cookie '{name}' missing HttpOnly", "Set-Cookie"))
        if is_https and "secure" not in low:
            out.append(_finding(url, "insecure_cookie", "medium", f"Cookie '{name}' missing Secure", "Set-Cookie"))
        if "samesite" not in low:
            out.append(_finding(url, "insecure_cookie", "low", f"Cookie '{name}' missing SameSite", "Set-Cookie"))
    return out


def analyze_introspection(service_url: str, body_json: dict, endpoint: str | None = None) -> list[dict]:
    """Given a GraphQL response to an introspection query, flag if it succeeded.

    The finding attaches to ``service_url`` (the host-level service asset) so it
    reaches the DB/triage; the specific introspection ``endpoint`` is named in the
    message.
    """
    try:
        types = body_json["data"]["__schema"]["types"]
    except (KeyError, TypeError):
        return []
    n = len(types) if isinstance(types, list) else 0
    where = f" at {endpoint}" if endpoint else ""
    return [_finding(service_url, "graphql_introspection_enabled", "high",
                     f"GraphQL introspection enabled{where} ({n} schema types exposed)", "__schema")]


def _b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def analyze_jwt(url: str, token: str) -> list[dict]:
    """Decode a JWT header and flag dangerous algorithms."""
    parts = token.split(".")
    if len(parts) < 2:
        return []
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (ValueError, json.JSONDecodeError):
        return []
    alg = str(header.get("alg", "")).lower()
    masked = token[:12] + "…" + token[-6:]
    if alg == "none":
        return [_finding(url, "jwt_alg_none", "critical",
                         f"JWT accepts 'alg: none' (unsigned): {masked}", "jwt.header.alg")]
    if alg.startswith("hs"):
        return [_finding(url, "jwt_weak_alg", "low",
                         f"JWT uses symmetric {header.get('alg')} (brute-forceable secret): {masked}", "jwt.header.alg")]
    return [_finding(url, "jwt_exposed", "info", f"JWT exposed in response ({header.get('alg')}): {masked}", "jwt")]


# --- Network probing ---------------------------------------------------------

def _fetch(url: str, data: bytes | None = None, headers: dict | None = None):
    # Send the operator-supplied session (cookie/JWT), if any, so authenticated
    # endpoints are probed as the authenticated user.
    merged = {**authutil.auth_headers(), **(headers or {})}
    req = urllib.request.Request(url, data=data, headers=merged,
                                 method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read(200_000)
            return r.status, dict(r.headers), r.headers.get_all("Set-Cookie") or [], body
    except urllib.error.HTTPError as e:  # 4xx/5xx still carry headers/body
        try:
            body = e.read(200_000)
        except Exception:
            body = b""
        return e.code, dict(e.headers or {}), (e.headers.get_all("Set-Cookie") if e.headers else []) or [], body
    except Exception:
        return None, {}, [], b""


def probe_service(service: dict, graphql_hint_paths: set[str]) -> list[dict]:
    """Probe one live service and return findings."""
    url = service.get("url") or ""
    scheme = service.get("scheme") or ("https" if str(service.get("port")) == "443" else "http")
    if not url:
        return []
    out: list[dict] = []
    status, headers, cookies, body = _fetch(url)
    if status is None:
        return []
    out += analyze_security_headers(url, scheme, headers, cookies)

    # JWTs anywhere in headers or body.
    hay = " ".join(f"{k}: {v}" for k, v in headers.items()) + " " + " ".join(cookies)
    try:
        hay += " " + body.decode("utf-8", "ignore")
    except Exception:
        pass
    seen = set()
    for tok in JWT_RE.findall(hay):
        if tok in seen:
            continue
        seen.add(tok)
        out += analyze_jwt(url, tok)

    # GraphQL: try the service root's known paths plus any hinted by extraction.
    base = url.rstrip("/")
    paths = set(GRAPHQL_PATHS) | {p for p in graphql_hint_paths if p.startswith("/")}
    for p in sorted(paths):
        gurl = base + p
        st, gh, _, gb = _fetch(gurl, data=INTROSPECTION_QUERY.encode(),
                               headers={"Content-Type": "application/json"})
        if st is None or st >= 500:
            continue
        try:
            j = json.loads(gb.decode("utf-8", "ignore"))
        except (ValueError, json.JSONDecodeError):
            continue
        found = analyze_introspection(url, j, endpoint=gurl)
        if found:
            out += found
            break  # one confirmed introspection endpoint per service is enough
    return out


def _load(path: Path):
    try:
        d = json.loads(path.read_text())
        return d if isinstance(d, list) else []
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []


def run(output: Path) -> list[dict]:
    reports = output / "reports"
    services = _load(reports / "ports.json")
    # GraphQL path hints from extracted endpoints.
    hints = {e.get("endpoint", "") for e in _load(reports / "endpoints.json")
             if "graphql" in (e.get("endpoint", "") or "").lower()}
    findings: list[dict] = []
    probed_urls: list[str] = []
    for s in services:
        if not isinstance(s, dict) or s.get("mirror_of"):
            continue
        findings += probe_service(s, hints)
        if s.get("url"):
            probed_urls.append(s["url"])
    # If the operator supplied a JWT via --jwt, analyze it too (attach to the first
    # probed service so it surfaces in triage): a weak supplied token (alg:none,
    # symmetric) is itself a finding.
    token = authutil.bearer_token()
    if token and probed_urls:
        findings += analyze_jwt(probed_urls[0], token)
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "security.json").write_text(json.dumps(findings, indent=2))
    return findings


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Live web-service security analysis.")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--config", type=Path, default=None)  # accepted for pipeline uniformity
    a = p.parse_args(argv)
    findings = run(a.output)
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    print(json.dumps({"live_findings": len(findings), "by_severity": by_sev}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
