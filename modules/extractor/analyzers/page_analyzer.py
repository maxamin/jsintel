"""Server-rendered page analyzer (extra layer for non-JS technologies).

The JS AST pipeline is unchanged; this layer adds analysis for pages served by
PHP / JSP / ASP.NET / ColdFusion / CGI / Flask / plain HTML — i.e. ``asset_type ==
"page"`` (see the classifier). It extracts, from the rendered HTML:

- **Links & resources** — ``href`` / ``src`` / ``action`` targets, split into
  absolute URLs (``URLFinding``) and site-relative endpoints (``EndpointFinding``).
- **Forms** — action, method, and input names, emitted as ``form`` endpoints plus
  an informational finding (a form's fields are prime fuzzing/attack surface).
- **Inline scripts & comments** — URLs and API paths referenced inside
  ``<script>`` blocks and ``<!-- comments -->`` (server-rendered apps often print
  API bases and, in comments, stray paths/credentials).

Secret detection on page bodies is handled by the existing SecretsAnalyzer (its
regex fallback now also covers ``page`` assets), so this layer does not duplicate it.
"""
from __future__ import annotations

import re
from collections.abc import Iterable

from ..analyzer import Analyzer
from ..findings import EndpointFinding, Finding, SecurityFinding, URLFinding
from ..models import Asset

# Attribute targets: href/src/action/formaction/data-url = "...".
_ATTR_RE = re.compile(r"""\b(?:href|src|action|formaction|data-url|data-href)\s*=\s*["']([^"'<>\s]+)["']""", re.I)
# Absolute or protocol-relative URLs anywhere (inline scripts, comments, text).
_URL_RE = re.compile(r"""(?:https?:)?//[^\s"'`<>\\)]+""")
# Likely API/route paths.
_PATH_RE = re.compile(r"""(?<![\w/])/(?:api|graphql|rest|v[0-9]+|admin|login|logout|user|users|account|vulnerabilities)[A-Za-z0-9_./?=&%:\-]*""", re.I)
# NOTE: the tag-open and lazy-body quantifiers are BOUNDED (`{0,N}` not `*`). An
# unbounded `<form\b[^>]*>` or `(.*?)</form>` on a large *unterminated* input
# backtracks quadratically (a 5MB run of `<form ` hangs for minutes). Bounding both
# the open-tag length and the captured body keeps every scan linear.
_FORM_RE = re.compile(r"<form\b[^>]{0,1000}>(.{0,20000}?)</form>", re.I | re.S)
_FORM_ATTR_RE = re.compile(r"""\b(action|method)\s*=\s*["']([^"']*)["']""", re.I)
_INPUT_RE = re.compile(r"""<(?:input|select|textarea)\b[^>]{0,1000}\bname\s*=\s*["']([^"']+)["']""", re.I)
_SCRIPT_RE = re.compile(r"<script\b[^>]{0,1000}>(.{0,200000}?)</script>", re.I | re.S)
_MAX_SOURCE = 1_000_000  # cap the HTML we regex-scan; real pages are far smaller


def _extract_comments(source: str, limit: int) -> list[str]:
    """Linear HTML-comment extraction. A bounded lazy regex still backtracks
    O(positions × bound) on dense unterminated `<!--` runs; find-based scanning is
    O(n) and safe on adversarial input."""
    out: list[str] = []
    i = 0
    while len(out) < limit:
        s = source.find("<!--", i)
        if s < 0:
            break
        e = source.find("-->", s + 4)
        if e < 0:
            out.append(source[s + 4:s + 4 + 2000])
            break
        out.append(source[s + 4:e][:2000])
        i = e + 3
    return out
_COMMENT_KEYWORD_RE = re.compile(r"\b(TODO|FIXME|password|passwd|secret|api[_-]?key|token|backdoor|debug|/[A-Za-z0-9_./-]{2,})\b", re.I)

_SKIP_PREFIX = ("mailto:", "tel:", "javascript:", "data:", "#")
_CAP = 400  # per-page cap on any one finding kind, to stay bounded on huge pages

# Query-parameter names that commonly map to injection/traversal/SSRF/redirect sinks.
_RISKY_PARAM = re.compile(r"^(id|page|file|filename|path|dir|url|uri|redirect|redir|next|return|dest|cmd|exec|command|q|query|search|include|template|view|doc|load|read|src)$", re.I)
_QS_PARAM_RE = re.compile(r"[?&]([A-Za-z0-9_.\[\]-]+)=")
# A hidden field name that looks like an anti-CSRF token.
_CSRF_FIELD = re.compile(r"(csrf|xsrf|token|nonce|authenticity|__requestverificationtoken|_token)", re.I)


def _risky_params(target: str) -> list[str]:
    return [p for p in _QS_PARAM_RE.findall(target) if _RISKY_PARAM.match(p)]


def _is_absolute(u: str) -> bool:
    return u.startswith("http://") or u.startswith("https://") or u.startswith("//")


class PageAnalyzer(Analyzer):
    id = "pages"
    description = "Extract links, forms, endpoints, and inline references from server-rendered pages"
    supported_asset_types = ("page",)

    def analyze(self, asset: Asset, source: str) -> Iterable[Finding]:
        if len(source) > _MAX_SOURCE:
            source = source[:_MAX_SOURCE]  # bound all regex work on pathological pages
        urls: set[str] = set()
        endpoints: set[str] = set()

        # 1) Attribute targets (href/src/action/…).
        for raw in self._capped(_ATTR_RE.findall(source)):
            v = raw.strip()
            if not v or v.lower().startswith(_SKIP_PREFIX):
                continue
            if _is_absolute(v):
                urls.add(v)
            elif v.startswith("/") or not v.startswith(("http", "//")):
                endpoints.add(v.split("#", 1)[0])

        # 2) Absolute URLs + API paths in inline scripts and page text.
        scripts = "\n".join(self._capped(_SCRIPT_RE.findall(source)))
        for hay in (source, scripts):
            urls.update(self._capped(_URL_RE.findall(hay)))
            endpoints.update(self._capped(_PATH_RE.findall(hay)))

        for u in sorted(urls)[:_CAP]:
            yield URLFinding(asset_url=asset.url, url=u)
        for ep in sorted(endpoints)[:_CAP]:
            kind = "api" if _PATH_RE.match(ep) else "link"
            yield EndpointFinding(asset_url=asset.url, endpoint=ep, kind=kind)

        # Injectable-parameter candidates: query params whose names map to common
        # injection/traversal/SSRF/redirect sinks (e.g. DVWA `?page=`, `?id=`).
        risky_seen: set[str] = set()
        for target in list(urls) + list(endpoints):
            for name in _risky_params(target):
                if name.lower() in risky_seen:
                    continue
                risky_seen.add(name.lower())
                yield SecurityFinding(asset_url=asset.url, finding_type="reflected_param_candidate",
                                      severity="low", value=f"param '{name}' in {target[:120]}", sink="query-param")

        # 3) Forms → endpoints + an informational finding (attack/fuzz surface).
        for body in self._capped(_FORM_RE.findall(source)):
            attrs = {k.lower(): v for k, v in _FORM_ATTR_RE.findall(_form_open(source, body))}
            action = (attrs.get("action") or "").split("#", 1)[0].strip()
            method = (attrs.get("method") or "GET").upper()
            fields = sorted(set(_INPUT_RE.findall(body)))[:40]
            if action and not action.lower().startswith(_SKIP_PREFIX):
                if _is_absolute(action):
                    yield URLFinding(asset_url=asset.url, url=action)
                else:
                    yield EndpointFinding(asset_url=asset.url, endpoint=action, kind="form")
            desc = f"{method} form action='{action or '(self)'}' fields=[{', '.join(fields)}]"
            yield SecurityFinding(asset_url=asset.url, finding_type="html_form",
                                  severity="info", value=desc[:300])
            # A state-changing (POST) form with no anti-CSRF token field is a CSRF
            # candidate. Password/login forms are the highest-value cases.
            if method == "POST" and not any(_CSRF_FIELD.search(f) for f in fields):
                yield SecurityFinding(asset_url=asset.url, finding_type="form_without_csrf_token",
                                      severity="low",
                                      value=f"POST form action='{action or '(self)'}' has no anti-CSRF token field",
                                      sink="csrf")

        # 4) Interesting HTML comments (paths, TODOs, credential-ish keywords).
        for c in _extract_comments(source, _CAP):
            text = c.strip()
            if not text or text.lower().startswith("[if "):  # skip IE conditional comments
                continue
            if _COMMENT_KEYWORD_RE.search(text):
                yield SecurityFinding(asset_url=asset.url, finding_type="html_comment",
                                      severity="info", value=text[:200])

    @staticmethod
    def _capped(items):
        return list(items)[:_CAP]


def _form_open(source: str, body: str) -> str:
    """Return the ``<form ...>`` opening tag that precedes a captured form body."""
    idx = source.find(body)
    if idx == -1:
        return "<form>"
    start = source.rfind("<form", 0, idx)
    end = source.find(">", start)
    return source[start:end + 1] if start != -1 and end != -1 else "<form>"
