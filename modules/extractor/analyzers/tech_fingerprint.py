"""Server-side technology fingerprinting (extra layer for non-JS stacks).

Complements the JS-framework analyzer by identifying the *backend* technology of a
server-rendered page (``asset_type == "page"``) from two signals:

- the URL extension (``.php`` → PHP, ``.jsp``/``.do`` → Java, ``.aspx`` → ASP.NET,
  ``.cfm`` → ColdFusion, ``.cgi``/``.pl``/``.py``/``.rb`` → CGI/Perl/Python/Ruby), and
- body markers (Django's ``csrfmiddlewaretoken``, Laravel's ``XSRF-TOKEN``,
  WordPress's ``wp-content``, Flask/Werkzeug debugger, Rails' ``authenticity_token``,
  ASP.NET's ``__VIEWSTATE``, a ``<meta name="generator">`` tag, …).

Emits ``FrameworkFinding`` rows (technology + evidence), the same shape the JS
framework analyzer uses, so they flow into ``reports/frameworks.json`` and the DB.
"""
from __future__ import annotations

import re
from collections.abc import Iterable

from ..analyzer import Analyzer
from ..findings import Finding, FrameworkFinding
from ..models import Asset

_EXT_TECH = [
    (re.compile(r"\.(php|phtml|php[0-9])(\?|#|$)", re.I), "PHP", "URL extension"),
    (re.compile(r"\.(jsp|jspx)(\?|#|$)", re.I), "Java (JSP)", "URL extension"),
    (re.compile(r"\.(do|action)(\?|#|$)", re.I), "Java (Servlet/Struts)", "URL extension"),
    (re.compile(r"\.(aspx|ashx)(\?|#|$)", re.I), "ASP.NET", "URL extension"),
    (re.compile(r"\.asp(\?|#|$)", re.I), "Classic ASP", "URL extension"),
    (re.compile(r"\.cfm(\?|#|$)", re.I), "ColdFusion", "URL extension"),
    (re.compile(r"\.cgi(\?|#|$)", re.I), "CGI", "URL extension"),
    (re.compile(r"\.pl(\?|#|$)", re.I), "Perl (CGI)", "URL extension"),
    (re.compile(r"\.py(\?|#|$)", re.I), "Python (CGI)", "URL extension"),
    (re.compile(r"\.rb(\?|#|$)", re.I), "Ruby (CGI)", "URL extension"),
]

_BODY_TECH = [
    (re.compile(r'name=["\']csrfmiddlewaretoken["\']', re.I), "Django", "csrfmiddlewaretoken field"),
    (re.compile(r'name=["\']authenticity_token["\']', re.I), "Ruby on Rails", "authenticity_token field"),
    (re.compile(r'name=["\']__VIEWSTATE["\']', re.I), "ASP.NET WebForms", "__VIEWSTATE field"),
    (re.compile(r"\bXSRF-TOKEN\b|laravel_session", re.I), "Laravel (PHP)", "Laravel session/token marker"),
    (re.compile(r"/wp-(content|includes)/", re.I), "WordPress (PHP)", "wp-content/wp-includes path"),
    (re.compile(r"Werkzeug|__debugger__|\bflask\b", re.I), "Flask/Werkzeug (Python)", "Werkzeug/Flask marker"),
    (re.compile(r"drupal-settings-json|/sites/default/files/", re.I), "Drupal (PHP)", "Drupal marker"),
    (re.compile(r"Set-Cookie:\s*JSESSIONID|jsessionid", re.I), "Java (servlet container)", "JSESSIONID"),
]
_GENERATOR_RE = re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', re.I)


class TechFingerprintAnalyzer(Analyzer):
    id = "tech_fingerprint"
    description = "Fingerprint the server-side technology of a rendered page"
    supported_asset_types = ("page",)

    def analyze(self, asset: Asset, source: str) -> Iterable[Finding]:
        seen: set[str] = set()

        def emit(tech: str, evidence: str):
            if tech not in seen:
                seen.add(tech)
                return FrameworkFinding(asset_url=asset.url, technology=tech, evidence=evidence)
            return None

        for rx, tech, ev in _EXT_TECH:
            if rx.search(asset.url):
                f = emit(tech, ev)
                if f:
                    yield f
        for rx, tech, ev in _BODY_TECH:
            if rx.search(source):
                f = emit(tech, ev)
                if f:
                    yield f
        m = _GENERATOR_RE.search(source)
        if m:
            f = emit(m.group(1).strip()[:80], "meta generator tag")
            if f:
                yield f
