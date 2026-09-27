#!/usr/bin/env python3
"""JSIntel capture listener daemon.

A loopback HTTP + WebSocket server that receives captured HTTP exchanges and target
WebSocket frames pushed by a proxy/browser extension (Burp, Firefox devtools export,
HTTPToolkit, mitmproxy, …) and drives them through the *existing* JSIntel pipeline —
classify -> extract (JS AST + page + tech + cloud + sourcemap) -> passive live-service
analysis -> DB ingest -> reporter -> triage. The download stage is skipped: the
capture already carries the response body, so nothing is re-fetched.

The listener is passive by default. The content-discovery fuzzer and screenshotter are
active stages and are NOT run — except that ``--fuzz`` opts into fuzzing, which after a
site's scan runs the existing fuzzer scoped to ONLY the hostnames seen in that site's
captured traffic, seeded by the endpoints/URLs just mined (it then sends live requests
to those hosts; reachability from the daemon is the operator's responsibility).

Every capture is routed to the ONE store for its site (registered domain / eTLD+1 by
default), so many URIs of the same target — ``a.site.com/x.js``, ``site.com/api``,
repeated XHR to the same endpoint — collapse into a single output directory and a
single, debounced, coalesced scan. A burst of hundreds of captures across a few sites
becomes a few scans (bounded by ``--max-concurrent``), never a dir/scan per request.

Endpoints (all loopback-only by default):
  POST /ingest        one capture, a JSON array of captures, or a HAR (``{log:{entries}}``)
  POST /ws            one captured target WebSocket frame
  POST /flush         force-run the pipeline over every site now -> reports/triage
  GET  /status        per-site capture counts + which sites are processing
  GET  /reports/<site>/<name>  serve a produced report (e.g. triage.json) for one site
  WS   /stream        stream captures/frames in real time (one JSON message each)

Processing is otherwise automatic: a site is (re)scanned in the background once it has
been quiet for ``--debounce`` seconds; ``/flush`` just forces it immediately.

Capture shape (native):
  {"type":"http","url":..., "method":"GET", "status":200,
   "request_headers":{...}, "response_headers":{"content-type":...},
   "response_body":"<str>", "response_body_b64":false}
  {"type":"ws","url":"wss://…","direction":"recv","opcode":"text","payload":"…"}

Auth: if JSINTEL_LISTEN_TOKEN is set, requests must send ``X-JSIntel-Token: <token>``.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

# ---- pipeline entrypoints (reused unchanged) --------------------------------
try:
    from modules.extractor.main import run as extract_run
    from modules import database, reporter, triage, liveanalysis
    from modules.extractor.analyzers.secrets_analyzer import scan_text
except ModuleNotFoundError:  # run as a bare script
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from modules.extractor.main import run as extract_run
    from modules import database, reporter, triage, liveanalysis
    from modules.extractor.analyzers.secrets_analyzer import scan_text

_MAX_BODY = 8 * 1024 * 1024
_PAGE_EXT = ('.php', '.phtml', '.html', '.htm', '.xhtml', '.shtml', '.asp', '.aspx',
             '.jsp', '.jspx', '.do', '.action', '.cfm', '.cgi', '.pl', '.py', '.rb')
# A few common multi-label public suffixes so eTLD+1 grouping isn't fooled (not the
# full PSL — enough that co.uk/com.au/… group by the real registered domain).
_MULTI_TLD = frozenset((
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "co.jp",
    "co.nz", "co.in", "com.br", "com.cn", "com.tr", "co.za", "com.mx", "com.sg",
))


def site_key(url: str) -> str:
    """The 'project' a capture belongs to = its registered domain (eTLD+1). All URIs
    and subdomains of one target collapse to one key, so a whole site is ONE scan in
    ONE directory — never a dir/scan per URL. IPs and single-label hosts pass through."""
    host = (urlsplit(url).hostname or "").lower().strip(".")
    if not host:
        return "unknown"
    if re.fullmatch(r"[0-9.]+|\[?[0-9a-f:]+\]?", host):  # IP literal
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in _MULTI_TLD and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def classify(url: str, mime: str | None) -> str:
    """Asset type for a captured response, from its URL extension and content-type.

    Getting this wrong "mixes things up": a JS bundle typed as ``page`` skips the AST
    (no endpoints/secrets from its callgraph), a source map parsed as JS floods errors,
    a JSON API response never gets mined. So strong *code* file extensions
    (``.js/.mjs/.map/.wasm``) are trusted **over** the content-type, because servers
    very commonly mislabel them (JS as ``text/html``/``text/plain``/``octet-stream``,
    source maps as ``application/json``); for everything else the content-type is
    authoritative (it is what the browser actually acted on), then a URL fallback.
    """
    path = url.split("?", 1)[0].split("#", 1)[0].lower()
    name = path.rsplit("/", 1)[-1]
    # 1) Strong code extensions win over a (often mislabeled) content-type.
    if path.endswith((".js", ".mjs")):
        return "javascript"
    if path.endswith(".map"):
        return "source_map"
    if path.endswith(".wasm"):
        return "webassembly"
    # 2) Content-type is authoritative for captured traffic (charset/params stripped).
    m = (mime or "").split(";")[0].strip().lower()
    if m in ("application/javascript", "text/javascript", "application/x-javascript", "application/ecmascript"):
        return "javascript"
    if m == "application/wasm":
        return "webassembly"
    if m in ("text/html", "application/xhtml+xml"):
        return "page"
    if m in ("application/json", "text/json", "application/manifest+json", "application/ld+json",
             "application/hal+json", "application/vnd.api+json") or m.endswith("+json"):
        # a web-app manifest is JSON but wants the manifest analyzer
        if name in ("manifest.json", "manifest.webmanifest") or path.endswith(".webmanifest") \
                or m == "application/manifest+json":
            return "manifest"
        return "configuration"
    # 3) URL fallback when the content-type is missing/generic (octet-stream, text/plain…).
    if name in ("manifest.json", "manifest.webmanifest") or path.endswith(".webmanifest"):
        return "manifest"
    if re.search(r"(^|[._/-])(service-)?worker([._/-]|$)", path):
        return "worker"
    if path.endswith(".json"):
        return "configuration"
    if path.endswith(_PAGE_EXT) or name == "" or "." not in name:
        return "page"
    return "other"


# Header names whose values routinely carry URLs, tokens, keys or session material —
# exactly the stuff a recon tool should surface out of a captured stream.
_INTEL_REQ_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token", "x-access-token",
                      "api-key", "apikey", "referer", "origin", "x-csrf-token", "x-forwarded-for",
                      "x-forwarded-host", "proxy-authorization", "x-amz-security-token")
_INTEL_RESP_HEADERS = ("set-cookie", "location", "content-location", "link", "www-authenticate",
                       "x-api-key", "x-amz-request-id", "x-powered-by", "authorization",
                       "access-control-allow-origin", "content-security-policy", "refresh")


def capture_intel_text(url: str, method: str, req_headers: dict, resp_headers: dict) -> str:
    """Flatten a captured exchange's URL + query + selected headers into one text blob.

    The extractor's URL/endpoint miner (PageAnalyzer) and the SecretsAnalyzer both run
    on ``page`` assets, so materializing this blob as a page pseudo-asset makes them
    pull URLs, API paths and secrets out of the *request line and headers* too — not
    just the response body. Query values are URL-decoded (including double-encoding) so
    an embedded URL or token hidden in ``?next=https%3A%2F%2F…`` / ``?token=…`` becomes
    visible to the miners rather than staying opaque percent-escapes.
    """
    # Values are wrapped in double quotes so the SecretsAnalyzer's page/regex fallback
    # (which scans quoted string literals) sees a token in a header value or query value
    # just as it would in HTML/JS; PageAnalyzer's URL/path regexes match inside quotes
    # too, so URL/endpoint mining is unaffected.
    def q(s: str) -> str:
        return '"' + str(s).replace('"', "%22") + '"'

    lines = [f"{method} {q(url)}"]
    sp = urlsplit(url)
    if sp.path:
        lines.append(f"path {q(unquote(sp.path))}")
    for k, v in parse_qsl(sp.query, keep_blank_values=True):
        lines.append(f"query {k}={q(v)}")        # parse_qsl already %-decodes once
        dv = unquote(v)
        if dv != v:                               # double-encoded value -> decode again
            lines.append(f"query {k}={q(dv)}")
    for name in _INTEL_REQ_HEADERS:
        if name in req_headers:
            lines.append(f"request-header {name}: {q(req_headers[name])}")
    for name in _INTEL_RESP_HEADERS:
        if name in resp_headers:
            lines.append(f"response-header {name}: {q(resp_headers[name])}")
    return "\n".join(lines)


# =====================================================================================
# Aggressive mode: per-flow dedup ledger + raw-request/response recording tree
# =====================================================================================
# Headers that make a request semantically distinct (auth/session/content) — volatile
# headers (User-Agent, Date, trace ids) are intentionally excluded so the same logical
# flow is not treated as new on every request.
_AUTH_HEADERS = ("authorization", "cookie", "content-type", "x-api-key", "x-auth-token")


def _norm_url_for_key(url: str) -> str:
    """Normalize a URL for the flow key: lowercase host, keep port/path, sort the query."""
    sp = urlsplit(url)
    host = (sp.hostname or "").lower()
    netloc = host + (f":{sp.port}" if sp.port else "")
    query = "&".join(sorted(p for p in sp.query.split("&") if p)) if sp.query else ""
    return f"{sp.scheme}://{netloc}{sp.path or '/'}" + (f"?{query}" if query else "")


# Per-request volatile content that changes every response WITHOUT any real change —
# anti-CSRF tokens, CSP/script nonces, session ids, timestamps. Masked before the
# anomaly-comparison hash so a rotating token is not reported as a false anomaly. All
# quantifiers are BOUNDED (`{0,N}`) so these stay linear on adversarial input.
_ANOMALY_NOISE = (
    # hidden token field, name-before-value: <input name='...token...' value='X'>
    (re.compile(r"(name=['\"][^'\"]{0,80}(?:csrf|xsrf|token|nonce|authenticity|viewstate|"
                r"eventvalidation|wpnonce|csrfmiddlewaretoken)[^'\"]{0,80}['\"][^>]{0,120}"
                r"value=['\"])[^'\"]{0,8192}(['\"])", re.I), r"\1__TOKEN__\2"),
    # hidden token field, value-before-name: <input value='X' name='...token...'>
    (re.compile(r"(value=['\"])[^'\"]{0,8192}(['\"][^>]{0,120}name=['\"][^'\"]{0,80}"
                r"(?:csrf|xsrf|token|nonce|authenticity)[^'\"]{0,80}['\"])", re.I), r"\1__TOKEN__\2"),
    # CSP / inline-script nonce attribute
    (re.compile(r"(\bnonce=['\"])[^'\"]{0,256}(['\"])", re.I), r"\1__NONCE__\2"),
    # session identifiers embedded in the body
    (re.compile(r"\b(PHPSESSID|JSESSIONID|SESSIONID|CSRFTOKEN)=[A-Za-z0-9._%\-]{6,256}", re.I),
     r"\1=__SESSION__"),
    # ISO-8601 timestamps
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?"),
     "__TS__"),
)


def normalize_for_anomaly(body: str) -> str:
    """Mask per-request volatile content (CSRF tokens, nonces, session ids, timestamps)
    so an otherwise-identical response is not flagged as a (false) anomaly."""
    out = body[:_MAX_BODY]
    for pat, repl in _ANOMALY_NOISE:
        out = pat.sub(repl, out)
    return out


# Generic high-entropy tokens (random ids, build hashes, opaque handles) that add
# response-diff noise. Masked for the *signature* only; a real secret is preserved via
# the separate secret-fingerprint block, so masking here can't hide a new secret.
_HE_RE = re.compile(r"[A-Za-z0-9+/=_-]{24,}")


def _looks_random(s: str) -> bool:
    has_digit = any(c.isdigit() for c in s)
    has_alpha = any(c.isalpha() for c in s)
    if has_digit and has_alpha:
        return True
    return len(s) >= 32 and all(c in "0123456789abcdefABCDEF" for c in s)


def _mask_high_entropy(text: str) -> str:
    return _HE_RE.sub(lambda m: "__HE__" if _looks_random(m.group(0)) else m.group(0), text)


_VISUAL_SAME_MAX = 6   # perceptual-hash hamming distance below which two renders are "same"


def _json_semantic_diff(a, b, path: str = "") -> dict:
    """Recursive added/removed/changed of two parsed JSON values, as dotted paths."""
    out = {"added": [], "removed": [], "changed": []}
    if isinstance(a, dict) and isinstance(b, dict):
        for k in b.keys() - a.keys():
            out["added"].append(f"{path}.{k}".lstrip("."))
        for k in a.keys() - b.keys():
            out["removed"].append(f"{path}.{k}".lstrip("."))
        for k in a.keys() & b.keys():
            sub = _json_semantic_diff(a[k], b[k], f"{path}.{k}".lstrip("."))
            for key in out:
                out[key] += sub[key]
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out["changed"].append(f"{path}[] (len {len(a)}->{len(b)})".lstrip("."))
        for i in range(min(len(a), len(b))):
            sub = _json_semantic_diff(a[i], b[i], f"{path}[{i}]")
            for key in out:
                out[key] += sub[key]
    elif a != b:
        out["changed"].append(path or "(root)")
    return out


def flow_key(method: str, url: str, body: str, req_headers: dict) -> str:
    """Stable hash of a *flow*: method + normalized URL + request body + auth headers.
    Same key = same logical request; a difference in any of these = a new flow."""
    auth = {k: req_headers.get(k, "") for k in _AUTH_HEADERS if k in (req_headers or {})}
    material = "\n".join([(method or "GET").upper(), _norm_url_for_key(url), body or "",
                          json.dumps(auth, sort_keys=True)])
    return hashlib.sha256(material.encode("utf-8", "ignore")).hexdigest()


class FlowRecorder:
    """Records each *distinct* request/response flow under a nested ``assets/flows`` tree,
    dedupes exact repeats (same flow key + same response), and logs response-hash changes
    for a known flow as anomalies. Active only in ``--aggressive`` mode.

    Layout: ``assets/flows/<host>/<path…>/<METHOD>/<reqhash>/`` with
    ``request_<reqhash>.txt``, one ``response_<resphash>.raw`` per distinct response,
    ``screenshot_<resphash>.png`` (offline render of page responses), and ``meta.json``.
    ``assets/flows/anomaly.txt`` gets a ``<iso-ts>\\t<response path>\\t<url>`` line
    whenever a known flow returns a response whose hash differs from before.
    """

    def __init__(self, assets_dir: Path, chromium: str = "", normalize: bool = True):
        self.base = assets_dir / "flows"
        self.base.mkdir(parents=True, exist_ok=True)
        self.reports = assets_dir.parent / "reports"      # <output>/reports (for anomalies.json)
        self.anomaly_file = self.base / "anomaly.txt"
        self.ledger_file = self.base / "ledger.json"
        self._lock = threading.Lock()
        self._ledger: dict[str, dict] = {}   # flow_key -> {dir, responses:set, reqhash, meta}
        self.chromium = chromium
        self.normalize = normalize          # mask volatile noise before anomaly comparison
        # (png, html_body, flow_key, resphash) — flush renders + back-fills the phash
        self._pending_shots: list[tuple[Path, str, str, str]] = []
        self._anomalies: list[dict] = []    # structured anomaly records -> reports/anomalies.json
        self.stats = {"flows": 0, "duplicates": 0, "anomalies": 0, "responses": 0,
                      "rehydrated": 0, "visual_suppressed": 0, "new_secret_anomalies": 0}
        self._load_ledger()                 # resume dedup/anomaly state from a prior run

    def _load_ledger(self) -> None:
        """Rehydrate the flow ledger from disk so dedup + anomaly detection persist across
        daemon restarts (continuous monitoring). Corrupt/absent index -> start fresh."""
        try:
            saved = json.loads(self.ledger_file.read_text())
        except (OSError, json.JSONDecodeError):
            return
        for fk, e in (saved.items() if isinstance(saved, dict) else []):
            try:
                self._ledger[fk] = {
                    "dir": self.base / e["dir"], "reqhash": e["reqhash"], "url": e["url"],
                    "method": e["method"], "first_seen": e.get("first_seen"),
                    "last_seen": e.get("last_seen"), "responses": set(e.get("responses", [])),
                    "responses_meta": e.get("responses_meta", []),
                }
            except (KeyError, TypeError):
                continue
        self.stats["rehydrated"] = len(self._ledger)
        try:                                    # keep appending to a prior run's anomalies
            prior = json.loads((self.reports / "anomalies.json").read_text())
            if isinstance(prior, list):
                self._anomalies = prior
        except (OSError, json.JSONDecodeError):
            pass

    def _save_ledger(self) -> None:
        """Atomically persist the ledger index (sets -> lists, dirs -> relative)."""
        out = {}
        for fk, e in self._ledger.items():
            try:
                rel = e["dir"].relative_to(self.base).as_posix()
            except ValueError:
                rel = str(e["dir"])
            out[fk] = {"dir": rel, "reqhash": e["reqhash"], "url": e["url"],
                       "method": e["method"], "first_seen": e.get("first_seen"),
                       "last_seen": e.get("last_seen"), "responses": sorted(e["responses"]),
                       "responses_meta": e["responses_meta"]}
        tmp = self.ledger_file.with_suffix(".json.tmp")
        try:
            tmp.write_text(json.dumps(out))
            tmp.replace(self.ledger_file)
        except OSError:
            tmp.unlink(missing_ok=True)

    def _flow_dir(self, method: str, url: str, reqhash: str) -> Path:
        sp = urlsplit(url)
        host = (sp.hostname or "host")
        host = f"{host}_{sp.port}" if sp.port else host
        segs = [re.sub(r"[^A-Za-z0-9._-]", "_", s)[:40] for s in (sp.path or "/").split("/") if s][:6]
        d = self.base.joinpath(re.sub(r"[^A-Za-z0-9._-]", "_", host), *(segs or ["_root"]),
                               (method or "GET").upper(), reqhash)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def record(self, method, url, req_headers, req_body, status, resp_headers, resp_body, atype) -> dict | None:
        """Record one exchange. Ordering matches the pipeline design: SECRETS are
        extracted first, then the diff engine classifies the anomaly using them.

        Returns None for an exact duplicate (cycle break) or a change the image
        tie-breaker judges visually identical.
        """
        fk = flow_key(method, url, req_body, req_headers)
        reqhash = fk[:16]
        body = resp_body or ""
        resphash = hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()[:16]
        is_html = atype == "page" and "<" in body[:4000]

        # --- 1) SECRETS FIRST: fingerprint the secrets in this response body. ----------
        secret_keys = frozenset(k for k, _, _ in scan_text(body)) if body else frozenset()

        # --- 2) Secret-aware signature: normalized + high-entropy-masked body PLUS the
        #        secret fingerprints. Masking kills token/timestamp noise; the secret
        #        block guarantees a genuinely-new secret still changes the signature. ---
        norm = normalize_for_anomaly(body) if self.normalize else body
        if self.normalize:
            norm = _mask_high_entropy(norm)
        sig_material = norm + "\x00SECRETS\x00" + "\n".join(sorted(secret_keys))
        sighash = hashlib.sha256(sig_material.encode("utf-8", "ignore")).hexdigest()[:16]

        # --- Phase A (locked): dedup + gather prior state for the tie-breaker. ----------
        with self._lock:
            entry = self._ledger.get(fk)
            if entry is not None and sighash in entry["responses"]:
                self.stats["duplicates"] += 1
                return None
            known = entry is not None
            prior_secret_union: set = set()
            prior_phashes: list[str] = []
            prior_rawhash = None
            if known:
                for m in entry["responses_meta"]:
                    prior_secret_union |= set(m.get("secrets", []))
                    if m.get("phash"):
                        prior_phashes.append(m["phash"])
                if entry["responses_meta"]:
                    prior_rawhash = entry["responses_meta"][-1]["resphash"]

        # --- Phase B (UNLOCKED): lazy image tie-breaker, only for a known-flow HTML
        #     change that we can visually compare against a stored baseline pHash. ------
        phash = None
        png_tmp = None
        visual_same = False
        if known and is_html and self.chromium and prior_phashes:
            phash, png_tmp = self._render_phash(body)
            if phash:
                visual_same = any(_hamming_hex(phash, p) <= _VISUAL_SAME_MAX for p in prior_phashes)

        # --- Phase C (locked): finalize. -----------------------------------------------
        with self._lock:
            entry = self._ledger.get(fk)
            if entry is not None and sighash in entry["responses"]:   # race
                self.stats["duplicates"] += 1
                if png_tmp:
                    png_tmp.unlink(missing_ok=True)
                return None
            if known and visual_same:
                # data differs but it renders identically -> not a real anomaly.
                entry["responses"].add(sighash)
                self.stats["duplicates"] += 1
                self.stats["visual_suppressed"] += 1
                if png_tmp:
                    png_tmp.unlink(missing_ok=True)
                self._save_ledger()
                return None
            if entry is None:
                d = self._flow_dir(method, url, reqhash)
                entry = {"dir": d, "responses": set(), "reqhash": reqhash, "url": url,
                         "method": (method or "GET").upper(),
                         "first_seen": _now_iso(), "responses_meta": []}
                self._ledger[fk] = entry
                self._write_request(d, reqhash, method, url, req_headers, req_body)
                self.stats["flows"] += 1
            d = entry["dir"]
            anomaly = known                       # known flow + new signature = anomaly
            entry["responses"].add(sighash)
            self.stats["responses"] += 1
            resp_path = d / f"response_{resphash}.raw"
            self._write_response(resp_path, status, resp_headers, resp_body)
            # screenshot: reuse the tie-breaker render if we did one, else queue for flush
            shot_rel = None
            if png_tmp is not None:
                final_png = d / f"screenshot_{resphash}.png"
                try:
                    png_tmp.replace(final_png)
                    shot_rel = final_png.name
                except OSError:
                    png_tmp.unlink(missing_ok=True)
            elif self.chromium and is_html:
                png = d / f"screenshot_{resphash}.png"
                self._pending_shots.append((png, body, fk, resphash))
                shot_rel = png.name
            added = sorted(secret_keys - prior_secret_union)
            removed = sorted(prior_secret_union - secret_keys)
            severity = ("high" if added else "medium") if anomaly else "info"
            kind = "new_secret" if added else ("content_change" if anomaly else "baseline")
            entry["responses_meta"].append({"resphash": resphash, "status": status,
                                            "ts": _now_iso(), "screenshot": shot_rel,
                                            "secrets": sorted(secret_keys), "phash": phash})
            entry["last_seen"] = _now_iso()
            diff_rel = None
            if anomaly:
                diff_rel = self._write_diffs(d, prior_rawhash, resphash, body)
                self.stats["anomalies"] += 1
                if added:
                    self.stats["new_secret_anomalies"] += 1
                self._record_anomaly(entry, resp_path, url, severity, kind, added, removed, diff_rel)
            self._write_meta(d, entry)
            self._save_ledger()
            return {"dir": str(d), "reqhash": reqhash, "resphash": resphash, "anomaly": anomaly,
                    "severity": severity if anomaly else None, "kind": kind,
                    "added_secrets": added, "new_flow": len(entry["responses"]) == 1}

    def _write_request(self, d, reqhash, method, url, headers, body):
        lines = [f"{(method or 'GET').upper()} {url}"]
        for k, v in (headers or {}).items():
            lines.append(f"{k}: {v}")
        raw = "\n".join(lines) + "\n\n" + (body or "")
        (d / f"request_{reqhash}.txt").write_text(raw, encoding="utf-8", errors="ignore")

    def _write_response(self, path, status, headers, body):
        lines = [f"HTTP {status}"]
        for k, v in (headers or {}).items():
            lines.append(f"{k}: {v}")
        (path).write_text("\n".join(lines) + "\n\n" + (body or ""), encoding="utf-8", errors="ignore")

    def _write_meta(self, d, entry):
        meta = {"url": entry["url"], "method": entry["method"], "reqhash": entry["reqhash"],
                "first_seen": entry["first_seen"], "last_seen": entry.get("last_seen"),
                "responses": entry["responses_meta"]}
        (d / "meta.json").write_text(json.dumps(meta, indent=2))

    def _render_phash(self, body: str):
        """Render an HTML body offline (file://) and return (perceptual_hash, png_path).
        The PNG is a temp path the caller either promotes to evidence or deletes."""
        from modules.webshot import render_screenshot, perceptual_hash
        import tempfile
        tmp_png = Path(tempfile.mkstemp(prefix="jsintel-flow-", suffix=".png")[1])
        tmp_html = tmp_png.with_suffix(".src.html")
        try:
            tmp_html.write_text(body, encoding="utf-8", errors="ignore")
            if not render_screenshot(f"file://{tmp_html}", tmp_png, chromium=self.chromium, timeout=20.0):
                tmp_png.unlink(missing_ok=True)
                return None, None
            return perceptual_hash(tmp_png), tmp_png
        except Exception:
            tmp_png.unlink(missing_ok=True)
            return None, None
        finally:
            tmp_html.unlink(missing_ok=True)

    def _read_response_body(self, d: Path, rawhash: str) -> str:
        """Read a stored raw response and return just its body (after the header block)."""
        try:
            raw = (d / f"response_{rawhash}.raw").read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""
        return raw.split("\n\n", 1)[1] if "\n\n" in raw else raw

    def _write_diffs(self, d: Path, prior_rawhash, new_rawhash, new_body) -> str | None:
        """Write a unified diff (normalized) and, for JSON, a semantic key/value diff,
        of the previous vs new response. Returns the unified-diff path (relative)."""
        if not prior_rawhash:
            return None
        import difflib
        prev_body = self._read_response_body(d, prior_rawhash)
        a = normalize_for_anomaly(prev_body).splitlines()
        b = normalize_for_anomaly(new_body).splitlines()
        udiff = "\n".join(difflib.unified_diff(a, b, fromfile=f"response_{prior_rawhash}",
                                               tofile=f"response_{new_rawhash}", lineterm=""))
        diff_path = d / f"diff_{prior_rawhash}_{new_rawhash}.txt"
        diff_path.write_text(udiff, encoding="utf-8", errors="ignore")
        try:
            sem = _json_semantic_diff(json.loads(prev_body), json.loads(new_body))
            if any(sem.values()):
                (d / f"diff_{prior_rawhash}_{new_rawhash}.semantic.json").write_text(json.dumps(sem, indent=2))
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
        try:
            return diff_path.relative_to(self.base).as_posix()
        except ValueError:
            return diff_path.name

    def _record_anomaly(self, entry, resp_path, url, severity, kind, added, removed, diff_rel):
        """Append the human anomaly.txt line AND a structured record for reports/anomalies.json."""
        try:
            rel = resp_path.relative_to(self.base).as_posix()
        except ValueError:
            rel = str(resp_path)
        ts = _now_iso()
        with open(self.anomaly_file, "a", encoding="utf-8") as fh:
            fh.write(f"{ts}\t{severity}\t{kind}\t{rel}\t{url}\n")
        self._anomalies.append({
            "ts": ts, "url": url, "method": entry["method"], "reqhash": entry["reqhash"],
            "severity": severity, "kind": kind, "response": rel, "diff": diff_rel,
            "added_secrets": added, "removed_secrets": removed,
        })
        try:
            self.reports.mkdir(parents=True, exist_ok=True)
            (self.reports / "anomalies.json").write_text(json.dumps(self._anomalies, indent=2))
        except OSError:
            pass

    def flush_screenshots(self) -> int:
        """Render queued page responses offline (file://) via headless Chromium and
        back-fill each response's perceptual hash (so later runs can tie-break against
        it without re-rendering). Called during a scan, never under the ingest lock."""
        with self._lock:
            pending, self._pending_shots = self._pending_shots, []
        if not pending or not self.chromium:
            return 0
        from modules.webshot import render_screenshot, perceptual_hash
        done = 0
        for png, body, fk, rawhash in pending:
            tmp = png.with_suffix(".src.html")
            try:
                tmp.write_text(body, encoding="utf-8", errors="ignore")
                if render_screenshot(f"file://{tmp}", png, chromium=self.chromium, timeout=20.0):
                    done += 1
                    ph = perceptual_hash(png)
                    with self._lock:                     # back-fill the baseline pHash
                        e = self._ledger.get(fk)
                        if e:
                            for m in e["responses_meta"]:
                                if m["resphash"] == rawhash:
                                    m["phash"] = ph
                            self._save_ledger()
            except Exception:
                pass
            finally:
                tmp.unlink(missing_ok=True)
        return done


def _now_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _hamming_hex(a: str, b: str) -> int:
    """Hamming distance between two equal-length hex perceptual hashes (64 if unusable)."""
    if not a or not b or len(a) != len(b):
        return 64
    try:
        return (int(a, 16) ^ int(b, 16)).bit_count()
    except ValueError:
        return 64


class CaptureStore:
    """Accumulates captured exchanges as pipeline assets and drives processing."""

    def __init__(self, output: Path, config: Path):
        self.output = output
        self.config = config
        (output / "assets").mkdir(parents=True, exist_ok=True)
        (output / "reports").mkdir(parents=True, exist_ok=True)
        (output / "database").mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._proc_lock = threading.Lock()      # serializes processing for THIS site
        self._assets: dict[str, dict] = {}      # url -> manifest entry (deduped by url)
        self._headers: dict[str, dict] = {}  # url -> {scheme, resp, req, method}
        self._ws: list[dict] = []
        self._n = 0
        self.dirty = False
        self.site = ""          # registered-domain key (set by the registry)
        self.last_ts = 0.0      # last capture time, for debounced processing
        self.last_result: dict | None = None
        self.fuzz = False               # opt-in active content-discovery (set by registry)
        self.fuzz_args: list[str] = []  # extra args passed straight to modules.fuzzer
        self.aggressive = False         # opt-in flow-dedup ledger + raw recording tree
        self.chromium = ""              # chromium binary for offline response screenshots
        self.anomaly_normalize = True   # mask volatile noise before anomaly comparison
        self._recorder: FlowRecorder | None = None

    # -- ingest -------------------------------------------------------------
    def add_http(self, cap: dict) -> bool:
        url = cap.get("url")
        if not url or cap.get("status") in (None, 0):
            return False
        headers = {k.lower(): v for k, v in (cap.get("response_headers") or {}).items()}
        req_headers = {k.lower(): v for k, v in (cap.get("request_headers") or {}).items()}
        body = cap.get("response_body") or ""
        if cap.get("response_body_b64"):
            try:
                body = base64.b64decode(body).decode("utf-8", "ignore")
            except Exception:
                body = ""
        body = body[:_MAX_BODY]
        req_body = cap.get("request_body") or ""
        if cap.get("request_body_b64"):
            try:
                req_body = base64.b64decode(req_body).decode("utf-8", "ignore")
            except Exception:
                req_body = ""
        req_body = req_body[:_MAX_BODY]
        atype = classify(url, headers.get("content-type"))
        # Aggressive mode: dedup+record the raw flow OUTSIDE the store lock (its own lock
        # + file IO). An exact-duplicate flow returns None -> cycle break: we still keep
        # the URL-keyed asset current below, but nothing is re-recorded.
        if self.aggressive:
            if self._recorder is None:
                self._recorder = FlowRecorder(self.output / "assets", self.chromium,
                                              normalize=self.anomaly_normalize)
            try:
                self._recorder.record(cap.get("method") or "GET", url, req_headers, req_body,
                                      cap.get("status"), headers, body, atype)
            except Exception:
                pass
        with self._lock:
            entry = self._assets.get(url)
            if entry is None:
                idx = len(self._assets)
                safe = re.sub(r"[^A-Za-z0-9._-]", "_", url.split("?", 1)[0].rsplit("/", 1)[-1] or "asset")[:100]
                entry = {"url": url, "type": atype,
                         "local_path": str(self.output / "assets" / f"{idx:06d}_{safe}"),
                         "mime_type": headers.get("content-type", ""), "status": "downloaded"}
                self._assets[url] = entry
            else:
                entry["type"] = atype  # refresh type/body with the latest capture
            Path(entry["local_path"]).write_text(body, encoding="utf-8", errors="ignore")
            scheme = "https" if str(url).startswith("https") else "http"
            self._headers[url] = {"scheme": scheme, "resp": headers, "req": req_headers,
                                  "method": (cap.get("method") or "GET").upper()}
            self._n += 1
            self.dirty = True
        return True

    def add_ws(self, frame: dict) -> bool:
        url = frame.get("url")
        payload = frame.get("payload") or ""
        if not url:
            return False
        with self._lock:
            self._ws.append({"url": url, "direction": frame.get("direction", "recv"),
                             "opcode": frame.get("opcode", "text"), "payload": payload[:_MAX_BODY]})
            self.dirty = True
        return True

    def ingest_any(self, obj) -> int:
        """Accept a single capture, a list, or a HAR log. Returns count ingested."""
        n = 0
        if isinstance(obj, dict) and "log" in obj and isinstance(obj["log"], dict):
            for e in obj["log"].get("entries", []):
                if self._add_har_entry(e):
                    n += 1
            return n
        items = obj if isinstance(obj, list) else [obj]
        for it in items:
            if not isinstance(it, dict):
                continue
            if it.get("type") == "ws":
                n += 1 if self.add_ws(it) else 0
            else:
                n += 1 if self.add_http(it) else 0
        return n

    def _add_har_entry(self, e: dict) -> bool:
        req, resp = e.get("request", {}), e.get("response", {})
        content = resp.get("content", {}) or {}
        body = content.get("text", "") or ""
        if content.get("encoding") == "base64":
            try:
                body = base64.b64decode(body).decode("utf-8", "ignore")
            except Exception:
                body = ""
        headers = {h.get("name", "").lower(): h.get("value", "") for h in resp.get("headers", []) if isinstance(h, dict)}
        headers.setdefault("content-type", content.get("mimeType", ""))
        req_headers = {h.get("name", "").lower(): h.get("value", "") for h in req.get("headers", []) if isinstance(h, dict)}
        req_body = (req.get("postData", {}) or {}).get("text", "") or ""
        return self.add_http({"url": req.get("url"), "method": req.get("method", "GET"),
                              "status": resp.get("status", 0), "response_headers": headers,
                              "request_headers": req_headers, "response_body": body,
                              "request_body": req_body})

    # -- processing ---------------------------------------------------------
    def process(self, force: bool = True) -> dict | None:
        """Run the full pipeline over everything captured for THIS site.

        Coalesced + serialized: only one scan runs per site at a time. ``force``
        (e.g. an explicit /flush) waits for the lock; otherwise (the background
        debouncer) a busy site is skipped and re-marked dirty, so a burst of
        captures collapses into a single scan instead of one scan per request.
        """
        if force:
            self._proc_lock.acquire()
        elif not self._proc_lock.acquire(blocking=False):
            with self._lock:
                self.dirty = True
            return None
        try:
            with self._lock:
                if not force and not self.dirty:
                    return self.last_result
                assets = list(self._assets.values())
                ws = list(self._ws)
                headers = dict(self._headers)
                self.dirty = False
            return self._run_pipeline(assets, ws, headers)
        finally:
            self._proc_lock.release()

    def _run_pipeline(self, assets, ws, headers) -> dict:
        reports = self.output / "reports"
        # Materialize captured WS text frames AND XHR/API JSON bodies as page-type
        # pseudo-assets so the page/secrets/url analyzers mine endpoints & secrets out
        # of them too (an AST pass won't touch JSON or a raw WS frame).
        manifest = list(assets)
        for i, f in enumerate(ws):
            if f["opcode"] == "text" and f["payload"]:
                p = self.output / "assets" / f"ws_{i:06d}.txt"
                p.write_text(f["payload"], encoding="utf-8", errors="ignore")
                manifest.append({"url": f"{f['url']}#frame{i}", "type": "page",
                                 "local_path": str(p), "status": "downloaded"})
        for a in assets:
            if a.get("type") == "configuration":  # XHR/fetch JSON responses
                manifest.append({"url": f"{a['url']}#body", "type": "page",
                                 "local_path": a["local_path"], "status": "downloaded"})
        # Mine the REQUEST side too: the URL (+ its decoded query values) and the
        # request/response headers routinely carry URLs, API paths and secrets (bearer
        # tokens, cookies, API keys, redirect targets). Flatten each capture into a page
        # pseudo-asset so the URL/endpoint/secret analyzers see them, not just bodies.
        for j, (url, meta) in enumerate(headers.items()):
            text = capture_intel_text(url, meta.get("method", "GET"),
                                      meta.get("req", {}), meta.get("resp", {}))
            if not text:
                continue
            p = self.output / "assets" / f"cap_{j:06d}.txt"
            p.write_text(text, encoding="utf-8", errors="ignore")
            manifest.append({"url": f"{url}#capture", "type": "page",
                             "local_path": str(p), "status": "downloaded"})
        (reports / "assets.json").write_text(json.dumps(manifest, indent=2))
        (reports / "ws_frames.json").write_text(json.dumps(ws, indent=2))
        # 1) extract (JS AST + page + tech + cloud + sourcemap)
        extract_run(reports / "assets.json", reports)
        # 2) passive live-service analysis from the CAPTURED headers (no re-probing):
        #    reuse the security-header analyzer on what the extension already saw.
        sec = []
        for url, meta in headers.items():
            hdrs = meta.get("resp", {})
            cookies = [c for k, c in hdrs.items() if k == "set-cookie"]
            try:
                sec.extend(liveanalysis.analyze_security_headers(url, meta.get("scheme", "http"), hdrs, cookies))
            except Exception:
                pass
        (reports / "security.json").write_text(json.dumps(sec, indent=2))
        # 2b) Harvest endpoints from any captured OpenAPI/Swagger spec (a leaked spec
        #     names the whole API). Reuses liveanalysis.parse_spec_paths; the DB ingest
        #     already reads api_spec_endpoints.json.
        spec_eps: list[dict] = []
        for a in assets:
            if a.get("type") != "configuration":
                continue
            try:
                body = Path(a["local_path"]).read_text(errors="ignore")
            except OSError:
                continue
            if any(m in body[:3000].lower() for m in ('"openapi"', '"swagger"', "'openapi'", "'swagger'")):
                spec_eps.extend(liveanalysis.parse_spec_paths(body, a["url"]))
        (reports / "api_spec_endpoints.json").write_text(json.dumps(spec_eps, indent=2))
        # 2c) OPT-IN active content-discovery. The listener is otherwise passive; when
        #     --fuzz is set it runs the existing fuzzer, scoped to ONLY the hostnames
        #     seen in the captured traffic and seeded by the endpoints/URLs just mined.
        #     Runs before DB ingest so fuzz hits fold into the DB/reports/triage.
        fuzz_summary = self._run_fuzzer([a["url"] for a in assets] + list(headers)) if self.fuzz else None
        # 2d) Aggressive mode: render queued page-response screenshots offline (not under
        #     the ingest lock) and surface the flow-ledger stats.
        flow_stats = None
        if self.aggressive and self._recorder is not None:
            self._recorder.flush_screenshots()
            flow_stats = dict(self._recorder.stats)
        # 3) DB ingest + reports + triage
        database.ingest(self.output, self.config)
        reporter.main(self.output)
        triage_result = triage.main(self.output)
        result = {"site": self.site or None, "assets": len(assets), "ws_frames": len(ws),
                  "captures": self._n, "security_findings": len(sec), "triage": triage_result}
        if fuzz_summary is not None:
            result["fuzz"] = fuzz_summary
        if flow_stats is not None:
            result["flows"] = flow_stats
        self.last_result = result
        return result

    def _run_fuzzer(self, urls) -> dict:
        """Run the content-discovery fuzzer scoped to the captured hostnames only.

        Active (sends requests); reachability of the captured host from the daemon is
        the operator's responsibility. Scope is derived from the captured URLs so it can
        never widen beyond what was actually seen in traffic.
        """
        hosts = sorted({h for h in (urlsplit(u).hostname for u in urls) if h})
        if not hosts:
            return {"ran": False, "reason": "no hostnames in capture"}
        argv = ["--output", str(self.output)]
        for h in hosts:
            argv += ["--scope", h]
        argv += self.fuzz_args
        try:
            from modules.fuzzer.main import main as fuzz_main
            rc = fuzz_main(argv)
        except SystemExit as ex:
            rc = int(ex.code or 0)
        except Exception as ex:  # a fuzzer failure must never abort the capture pipeline
            return {"ran": False, "scope": hosts, "error": str(ex)}
        summary = {"ran": True, "scope": hosts, "rc": rc}
        fs = self.output / "reports" / "fuzz_summary.json"
        if fs.is_file():
            try:
                summary["results"] = json.loads(fs.read_text())
            except (OSError, json.JSONDecodeError):
                pass
        return summary

    def status(self) -> dict:
        with self._lock:
            return {"captures": self._n, "unique_assets": len(self._assets),
                    "ws_frames": len(self._ws), "pending_process": self.dirty,
                    "output": str(self.output)}


# =====================================================================================
# Per-site registry — the fix for "one site, many URIs" mess
# =====================================================================================
class SiteRegistry:
    """Routes every capture to the ONE store for its site, so a whole target is a
    single directory and a single (coalesced, debounced) scan — never a dir/scan per
    URI. Captures from ``a.site.com/x.js``, ``b.site.com/y`` and ``site.com/api`` all
    land in ``<output>/sites/site.com/``.

    A background thread submits a site for processing only once it has been *quiet*
    for ``debounce`` seconds, and a bounded ``ThreadPoolExecutor`` caps how many sites
    scan at once — so a burst of 500 captures across 3 sites becomes 3 scans, not 500,
    and resource use stays flat no matter how chatty the proxy is.
    """

    def __init__(self, output: Path, config: Path, group: str = "regdom",
                 debounce: float = 2.0, max_concurrent: int = 2,
                 fuzz: bool = False, fuzz_args: list[str] | None = None,
                 aggressive: bool = False, chromium: str = "", anomaly_normalize: bool = True):
        self.output = output
        self.config = config
        self.group = group
        self.debounce = max(0.0, debounce)
        self.fuzz = fuzz
        self.fuzz_args = list(fuzz_args or [])
        self.aggressive = aggressive
        self.chromium = chromium
        self.anomaly_normalize = anomaly_normalize
        (output / "sites").mkdir(parents=True, exist_ok=True)
        self._stores: dict[str, CaptureStore] = {}
        self._lock = threading.Lock()
        self._inflight: set[str] = set()
        self._pool = ThreadPoolExecutor(max_workers=max(1, max_concurrent),
                                        thread_name_prefix="jsintel-site")
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._debounce_loop, daemon=True)
        self._thread.start()

    def _key(self, url: str) -> str:
        if self.group == "host":  # every distinct hostname is its own project
            return (urlsplit(url).hostname or "unknown").lower().strip(".") or "unknown"
        return site_key(url)      # default: registered domain (eTLD+1)

    def store_for(self, url: str) -> CaptureStore:
        key = self._key(url)
        with self._lock:
            st = self._stores.get(key)
            if st is None:
                safe = re.sub(r"[^A-Za-z0-9._-]", "_", key)[:80] or "unknown"
                st = CaptureStore(self.output / "sites" / safe, self.config)
                st.site = key
                st.fuzz = self.fuzz
                st.fuzz_args = self.fuzz_args
                st.aggressive = self.aggressive
                st.chromium = self.chromium
                st.anomaly_normalize = self.anomaly_normalize
                self._stores[key] = st
            return st

    # -- ingest (routes each item to its site's store) ----------------------
    def ingest_any(self, obj) -> int:
        n = 0
        if isinstance(obj, dict) and isinstance(obj.get("log"), dict):  # HAR
            for e in obj["log"].get("entries", []):
                url = (e.get("request") or {}).get("url")
                if not url:
                    continue
                st = self.store_for(url)
                if st._add_har_entry(e):
                    st.last_ts = time.time()
                    n += 1
            return n
        for it in (obj if isinstance(obj, list) else [obj]):
            if not isinstance(it, dict) or not it.get("url"):
                continue
            st = self.store_for(it["url"])
            ok = st.add_ws(it) if it.get("type") == "ws" else st.add_http(it)
            if ok:
                st.last_ts = time.time()
                n += 1
        return n

    def add_ws(self, frame: dict) -> int:
        url = frame.get("url")
        if not url:
            return 0
        st = self.store_for(url)
        if st.add_ws(frame):
            st.last_ts = time.time()
            return 1
        return 0

    # -- processing ---------------------------------------------------------
    def _debounce_loop(self) -> None:
        """Submit each dirty site for a scan once it has been quiet for `debounce`s."""
        while not self._stop.wait(0.5):
            now = time.time()
            with self._lock:
                due = [(k, s) for k, s in self._stores.items()
                       if s.dirty and k not in self._inflight
                       and now - s.last_ts >= self.debounce]
                for k, s in due:
                    self._inflight.add(k)
                    self._pool.submit(self._run_site, k, s)

    def _run_site(self, key: str, store: CaptureStore) -> None:
        try:
            store.process(force=False)   # coalesced: skips if another scan holds the lock
        except Exception:
            pass
        finally:
            with self._lock:
                self._inflight.discard(key)

    def flush_all(self) -> dict:
        """Force-process every site now (explicit /flush). Returns a per-site summary."""
        with self._lock:
            stores = list(self._stores.items())
        results = {k: s.process(force=True) for k, s in stores}
        return {"sites": len(results), "results": results}

    def report_path(self, site: str, name: str) -> Path | None:
        with self._lock:
            s = self._stores.get(site)
        if s is None:
            return None
        f = s.output / "reports" / Path(name).name
        return f if f.is_file() else None

    def status(self) -> dict:
        with self._lock:
            stores = list(self._stores.items())
            inflight = set(self._inflight)
        per_site = {}
        for k, s in stores:
            d = s.status()
            d["site"] = k
            d["processing"] = k in inflight
            per_site[k] = d
        return {"group": self.group, "debounce": self.debounce, "sites": len(per_site),
                "captures": sum(d["captures"] for d in per_site.values()),
                "per_site": per_site}

    def shutdown(self) -> None:
        self._stop.set()
        self._pool.shutdown(wait=False)


# =====================================================================================
# HTTP + WebSocket server
# =====================================================================================
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _make_handler(target, token: str | None):
    is_registry = isinstance(target, SiteRegistry)
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # quiet
            pass

        def handle(self):  # a client that hangs up mid-response is normal, not an error
            try:
                super().handle()
            except (BrokenPipeError, ConnectionError):
                pass

        def _authed(self) -> bool:
            return not token or self.headers.get("X-JSIntel-Token") == token

        def _json(self, code: int, obj) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> bytes:
            n = int(self.headers.get("Content-Length", 0) or 0)
            return self.rfile.read(n) if n else b""

        def do_GET(self):
            if self.headers.get("Upgrade", "").lower() == "websocket":
                return self._websocket()
            if not self._authed():
                return self._json(401, {"error": "unauthorized"})
            if self.path == "/status":
                return self._json(200, target.status())
            if self.path.startswith("/reports/"):
                rel = self.path[len("/reports/"):]
                if is_registry:
                    # /reports/<site>/<name> — one report tree per site.
                    site, _, name = rel.partition("/")
                    f = target.report_path(site, name) if name else None
                else:
                    f = target.output / "reports" / Path(rel).name
                    f = f if f.is_file() else None
                if f:
                    data = f.read_bytes()
                    self.send_response(200); self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data))); self.end_headers()
                    return self.wfile.write(data)
                return self._json(404, {"error": "no such report"})
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            if not self._authed():
                return self._json(401, {"error": "unauthorized"})
            if self.path == "/flush":
                return self._json(200, target.flush_all() if is_registry else target.process())
            try:
                obj = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                return self._json(400, {"error": "invalid JSON"})
            if self.path == "/ingest":
                n = target.ingest_any(obj)
                out = {"ingested": n}
                if self.headers.get("X-JSIntel-Process") == "1":  # opt-in synchronous scan
                    out["result"] = target.flush_all() if is_registry else target.process()
                return self._json(200, out)
            if self.path == "/ws":
                r = target.add_ws(obj)
                return self._json(200, {"ingested": r if isinstance(r, int) else (1 if r else 0)})
            return self._json(404, {"error": "not found"})

        # -- minimal RFC6455 server (text frames of JSON captures) ----------
        def _websocket(self):
            key = self.headers.get("Sec-WebSocket-Key")
            if not key or not self._authed():
                return self._json(401, {"error": "unauthorized"})
            accept = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            try:
                while True:
                    msg = self._ws_recv()
                    if msg is None:
                        break
                    try:
                        target.ingest_any(json.loads(msg))
                    except json.JSONDecodeError:
                        pass
            except (OSError, ConnectionError):
                pass

        def _ws_recv(self) -> str | None:
            hdr = self.rfile.read(2)
            if len(hdr) < 2:
                return None
            b0, b1 = hdr[0], hdr[1]
            opcode = b0 & 0x0F
            masked = b1 & 0x80
            length = b1 & 0x7F
            if length == 126:
                length = struct.unpack(">H", self.rfile.read(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self.rfile.read(8))[0]
            if length > _MAX_BODY:
                return None
            mask = self.rfile.read(4) if masked else b"\x00\x00\x00\x00"
            data = bytearray(self.rfile.read(length))
            if masked:
                for i in range(len(data)):
                    data[i] ^= mask[i % 4]
            if opcode == 0x8:  # close
                return None
            if opcode in (0x1, 0x2):  # text / binary
                return data.decode("utf-8", "ignore")
            return ""  # ping/pong/continuation -> ignore, keep reading

    return Handler


def serve(output: Path, config: Path, host: str, port: int, token: str | None,
          group: str = "regdom", debounce: float = 2.0, max_concurrent: int = 2,
          fuzz: bool = False, fuzz_args: list[str] | None = None,
          aggressive: bool = False, chromium: str = "", anomaly_normalize: bool = True) -> None:
    registry = SiteRegistry(output, config, group=group, debounce=debounce,
                            max_concurrent=max_concurrent, fuzz=fuzz, fuzz_args=fuzz_args,
                            aggressive=aggressive, chromium=chromium,
                            anomaly_normalize=anomaly_normalize)
    httpd = ThreadingHTTPServer((host, port), _make_handler(registry, token))
    print(f"JSIntel listener on http://{host}:{port}  (output={output}, auth={'on' if token else 'off'})", flush=True)
    print(f"  grouping={group} (one dir + one coalesced scan per site), debounce={debounce}s, "
          f"max_concurrent={max_concurrent}", flush=True)
    if fuzz:
        print(f"  ACTIVE fuzzing ON (scoped to captured hosts only); fuzz_args={fuzz_args or []}", flush=True)
    if aggressive:
        print(f"  AGGRESSIVE ON: per-flow dedup + raw request/response recording under "
              f"assets/flows/ (screenshots={'on' if chromium else 'off (no chromium)'})", flush=True)
    print("  POST /ingest | POST /ws | POST /flush | GET /status | GET /reports/<site>/<name> | WS /stream", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        registry.shutdown()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="JSIntel capture listener daemon.")
    p.add_argument("--output", type=Path, default=Path("output_listener"))
    p.add_argument("--config", type=Path, default=Path("config/config.yaml"))
    p.add_argument("--host", default="127.0.0.1")  # loopback only by default (receives sensitive captures)
    p.add_argument("--port", type=int, default=8799)
    p.add_argument("--token", default=os.environ.get("JSINTEL_LISTEN_TOKEN") or None)
    p.add_argument("--group", choices=("regdom", "host"), default="regdom",
                   help="collapse captures per registered domain (default) or per hostname")
    p.add_argument("--debounce", type=float, default=2.0,
                   help="seconds a site must be quiet before it is (re)scanned")
    p.add_argument("--max-concurrent", type=int, default=2,
                   help="max sites scanned at once (caps resource use under bursty traffic)")
    p.add_argument("--fuzz", action="store_true",
                   help="OPT-IN active content-discovery: after a site's scan, fuzz the "
                        "captured hostnames (scope) seeded by discovered endpoints. Sends live traffic.")
    p.add_argument("--fuzz-arg", action="append", default=[], dest="fuzz_args",
                   help="extra arg passed straight to modules.fuzzer (repeatable), "
                        "e.g. --fuzz-arg=--dry-run --fuzz-arg=--offline")
    p.add_argument("--aggressive", action="store_true",
                   help="record each distinct request/response flow (dedup by method+URL+body+"
                        "auth headers) under assets/flows/ with a screenshot; log response-hash "
                        "changes to assets/flows/anomaly.txt. Repeated identical flows are skipped.")
    p.add_argument("--chromium", default="",
                   help="Chromium/Chrome binary for --aggressive response screenshots (default: autodetect).")
    p.add_argument("--anomaly-raw", action="store_true",
                   help="compare raw response bytes for anomalies (default: mask volatile "
                        "CSRF tokens/nonces/session ids/timestamps first, to avoid false anomalies).")
    a = p.parse_args(argv)
    chromium = ""
    if a.aggressive:
        from modules.webshot import find_chromium
        chromium = find_chromium(a.chromium)
    serve(a.output, a.config, a.host, a.port, a.token,
          group=a.group, debounce=a.debounce, max_concurrent=a.max_concurrent,
          fuzz=a.fuzz, fuzz_args=a.fuzz_args, aggressive=a.aggressive, chromium=chromium,
          anomaly_normalize=not a.anomaly_raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
