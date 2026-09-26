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
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_FORM_ATTR_RE = re.compile(r"""\b(action|method)\s*=\s*["']([^"']*)["']""", re.I)
_INPUT_RE = re.compile(r"""<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)["']""", re.I)
_SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.I | re.S)
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_COMMENT_KEYWORD_RE = re.compile(r"\b(TODO|FIXME|password|passwd|secret|api[_-]?key|token|backdoor|debug|/[A-Za-z0-9_./-]{2,})\b", re.I)

_SKIP_PREFIX = ("mailto:", "tel:", "javascript:", "data:", "#")
_CAP = 400  # per-page cap on any one finding kind, to stay bounded on huge pages


def _is_absolute(u: str) -> bool:
    return u.startswith("http://") or u.startswith("https://") or u.startswith("//")


class PageAnalyzer(Analyzer):
    id = "pages"
    description = "Extract links, forms, endpoints, and inline references from server-rendered pages"
    supported_asset_types = ("page",)

    def analyze(self, asset: Asset, source: str) -> Iterable[Finding]:
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

        # 4) Interesting HTML comments (paths, TODOs, credential-ish keywords).
        for c in self._capped(_COMMENT_RE.findall(source)):
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
