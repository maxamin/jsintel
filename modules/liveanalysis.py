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
import sys
import urllib.error
import urllib.request
from pathlib import Path

try:  # works when run as `python -m modules.liveanalysis` or imported in tests
    from modules import authutil
except ModuleNotFoundError:  # run as a bare script (jsintel.sh): add repo root first
    import pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
    from modules import authutil

TIMEOUT = 8
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/graphql/console", "/graphiql")
INTROSPECTION_QUERY = '{"query":"{__schema{types{name}}}"}'
# Well-known API spec / docs / interactive-console paths. An exposed one hands an
# attacker the full endpoint map and often a live request console.
API_DOC_PATHS = ("/openapi.json", "/swagger.json", "/v3/api-docs", "/v2/api-docs",
                 "/docs", "/redoc", "/ui/", "/swagger-ui/", "/api-docs", "/api/docs")
_SPEC_MARKERS = ("openapi", "swagger")
_IDE_MARKERS = ("swagger-ui", "redoc", "graphiql", "graphql playground", "swaggerui")

# Sensitive files that should never be web-reachable. Each entry: path, severity,
# and a marker that must appear in the body to avoid false positives (a soft-404 or
# SPA catch-all returning 200 with HTML must not trip these).
# (path, severity, marker, html_ok): a hit needs status 200 AND (marker in body, or
# marker=="") AND — unless html_ok — the body must NOT look like an HTML page. The
# html-reject rule kills soft-404/login catch-alls that return a 200 HTML index for
# every missing path (observed on DVWA), which empty/loose markers would otherwise
# match. Plaintext/binary secrets (.git, .env, .htpasswd, backups) are never HTML;
# phpinfo/server-status ARE HTML, so they set html_ok with a distinctive marker.
SENSITIVE_FILES = (
    ("/.git/config", "high", "[core]", False),
    ("/.git/HEAD", "high", "ref:", False),
    ("/.env", "high", "", False),
    ("/.svn/entries", "high", "", False),
    ("/config.php.bak", "high", "<?php", False),
    ("/config.inc.php.bak", "high", "<?php", False),
    ("/wp-config.php.bak", "high", "<?php", False),
    ("/.htpasswd", "high", ":", False),
    ("/phpinfo.php", "medium", "phpinfo()", True),
    ("/server-status", "medium", "Apache Server Status", True),
    ("/backup.zip", "medium", "PK\x03\x04", False),
)
_HTML_MARKERS = ("<html", "<!doctype", "<body", "<head", "<script", "</div>")
# Framework debug pages / verbose error markers (a live interactive debugger or a
# full stack trace is a critical information-disclosure / RCE-adjacent finding).
_DEBUG_MARKERS = (
    ("Werkzeug Debugger", "Flask/Werkzeug interactive debugger"),
    ("__debugger__", "Werkzeug debugger"),
    ("Traceback (most recent call last)", "Python stack trace"),
    ("You're seeing this error because you have", "Django DEBUG=True"),
    ("Using the URLconf defined in", "Django DEBUG=True (technical-404)"),
    ("Django Version:", "Django debug page"),
    ("Whitelabel Error Page", "Spring Boot error page"),
    ("<title>Application Error</title>", "verbose application error"),
    ("Exception at /", "framework exception page"),
)


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


def analyze_api_doc(service_url: str, doc_url: str, status: int | None, body_text: str) -> list[dict]:
    """Flag an exposed API spec (OpenAPI/Swagger) or interactive docs/IDE.

    Attaches to ``service_url`` (the host-level service asset) so it reaches triage.
    """
    if status is None or status >= 400:
        return []
    low = (body_text or "")[:4000].lower()
    # A spec: JSON declaring openapi/swagger.
    if low.lstrip().startswith("{") and any(m in low for m in _SPEC_MARKERS):
        return [_finding(service_url, "exposed_api_spec", "medium",
                         f"Exposed API spec at {doc_url} (full endpoint map disclosed)", "openapi")]
    # An interactive console/IDE.
    if any(m in low for m in _IDE_MARKERS):
        return [_finding(service_url, "exposed_api_docs", "medium",
                         f"Exposed API docs/console at {doc_url}", "docs-ui")]
    return []


def parse_spec_paths(spec_text: str, service_url: str) -> list[dict]:
    """Pull declared paths out of an OpenAPI/Swagger spec as endpoint records.

    A leaked spec discloses the full API surface; ingesting its `paths` as endpoints
    (attributed to the service) gives triage that whole surface for free.
    """
    try:
        spec = json.loads(spec_text)
    except (ValueError, json.JSONDecodeError):
        return []
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        return []
    base_path = ""
    # OpenAPI 2 basePath; OpenAPI 3 servers[0].url path component.
    if isinstance(spec.get("basePath"), str):
        base_path = spec["basePath"].rstrip("/")
    out: list[dict] = []
    seen: set[str] = set()
    for p in spec["paths"]:
        if not isinstance(p, str) or not p.startswith("/"):
            continue
        ep = (base_path + p) if base_path else p
        if ep not in seen:
            seen.add(ep)
            out.append({"asset_url": service_url, "endpoint": ep, "kind": "api"})
    return out


def analyze_debug_page(url: str, status: int | None, body_text: str) -> list[dict]:
    """Flag an exposed interactive debugger or verbose error/stack-trace page."""
    if status is None:
        return []
    hay = (body_text or "")[:8000]
    for marker, label in _DEBUG_MARKERS:
        if marker in hay:
            return [_finding(url, "debug_page_exposed", "high",
                             f"Exposed {label} (verbose errors / debugger)", "debug")]
    return []


def analyze_sensitive_file(service_url: str, file_url: str, status: int | None,
                           body_text: str, severity: str, marker: str,
                           html_ok: bool = False) -> list[dict]:
    """Flag a web-reachable sensitive file (source control, env, backup, …)."""
    if status != 200:
        return []
    head = (body_text or "")[:4000]
    if not html_ok and any(m in head.lower() for m in _HTML_MARKERS):
        return []  # an HTML page for a plaintext/binary secret == soft-404/catch-all
    if marker and marker not in head:
        return []
    return [_finding(service_url, "sensitive_file_exposed", severity,
                     f"Sensitive file reachable: {file_url}", "sensitive-file")]


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

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not follow 3xx — return the redirect response as-is."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect())


def _fetch(url: str, data: bytes | None = None, headers: dict | None = None, follow: bool = True):
    # Send the operator-supplied session (cookie/JWT), if any, so authenticated
    # endpoints are probed as the authenticated user. `follow=False` is used when
    # probing for a specific file/spec: a 3xx (e.g. a login redirect) then means the
    # target is NOT present, and must not be mistaken for a 200 body.
    merged = {**authutil.auth_headers(), **(headers or {})}
    req = urllib.request.Request(url, data=data, headers=merged,
                                 method="POST" if data is not None else "GET")
    try:
        if follow:
            r = urllib.request.urlopen(req, timeout=TIMEOUT)
        else:
            r = _NO_REDIRECT_OPENER.open(req, timeout=TIMEOUT)
        with r:
            body = r.read(200_000)
            return r.status, dict(r.headers), r.headers.get_all("Set-Cookie") or [], body
    except urllib.error.HTTPError as e:  # 3xx (no-follow) / 4xx / 5xx carry headers/body
        try:
            body = e.read(200_000)
        except Exception:
            body = b""
        return e.code, dict(e.headers or {}), (e.headers.get_all("Set-Cookie") if e.headers else []) or [], body
    except Exception:
        return None, {}, [], b""


def probe_service(service: dict, graphql_hint_paths: set[str], endpoints_out: list | None = None) -> list[dict]:
    """Probe one live service and return findings.

    If ``endpoints_out`` is given, endpoints recovered from an exposed API spec are
    appended to it (for ingestion as endpoints, not just a finding).
    """
    url = service.get("url") or ""
    scheme = service.get("scheme") or ("https" if str(service.get("port")) == "443" else "http")
    if not url:
        return []
    out: list[dict] = []
    status, headers, cookies, body = _fetch(url)
    if status is None:
        return []
    body_text = body.decode("utf-8", "ignore") if body else ""
    out += analyze_security_headers(url, scheme, headers, cookies)
    # Debugger / verbose-error page on the landing response, AND on a deliberately
    # bogus path: many frameworks (Django, Flask, Rails) only render their
    # DEBUG/stack-trace page on an unmatched/error URL, not on the landing page.
    out += analyze_debug_page(url, status, body_text)
    est, _, _, ebody = _fetch(url.rstrip("/") + "/jsintel-nonexistent-probe-x9z", follow=False)
    out += analyze_debug_page(url, est, ebody.decode("utf-8", "ignore") if ebody else "")

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

    # Exposed API spec / docs / IDE (one finding per service is enough). When the hit
    # is a parseable spec, also harvest its declared paths as endpoints.
    for p in API_DOC_PATHS:
        st, _, _, db = _fetch(base + p, follow=False)
        dtext = db.decode("utf-8", "ignore") if db else ""
        found = analyze_api_doc(url, base + p, st, dtext)
        if found:
            out += found
            if found[0]["finding_type"] == "exposed_api_spec" and endpoints_out is not None:
                endpoints_out.extend(parse_spec_paths(dtext, url))
            break

    # Sensitive-file exposure (source control, env, backups, debug endpoints).
    for path, sev, marker, html_ok in SENSITIVE_FILES:
        st, _, _, sb = _fetch(base + path, follow=False)
        stext = sb.decode("utf-8", "ignore") if sb else ""
        out += analyze_sensitive_file(url, base + path, st, stext, sev, marker, html_ok)
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
    spec_endpoints: list[dict] = []
    for s in services:
        if not isinstance(s, dict) or s.get("mirror_of"):
            continue
        findings += probe_service(s, hints, endpoints_out=spec_endpoints)
        if s.get("url"):
            probed_urls.append(s["url"])
    # If the operator supplied a JWT via --jwt, analyze it too (attach to the first
    # probed service so it surfaces in triage): a weak supplied token (alg:none,
    # symmetric) is itself a finding.
    token = authutil.bearer_token()
    if token and probed_urls:
        findings += analyze_jwt(probed_urls[0], token)
    # De-duplicate findings (a debugger/marker can match on several probed paths).
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for f in findings:
        key = (f["asset_url"], f["finding_type"], f["severity"], f["value"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "security.json").write_text(json.dumps(deduped, indent=2))
    # Endpoints harvested from exposed specs -> ingested as endpoints by the DB.
    (reports / "api_spec_endpoints.json").write_text(json.dumps(spec_endpoints, indent=2))
    return deduped


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
