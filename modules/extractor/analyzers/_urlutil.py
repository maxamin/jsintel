"""Shared URL plausibility filter for URL-emitting analyzers."""
from __future__ import annotations
import re

# XML/SVG/Math/Atom/RDF namespace URIs used as xmlns= attribute values in HTML/SVG.
# These are specification identifiers, never live web endpoints.
_XML_NS_RE = re.compile(
    r'^https?://(?:www\.)?w3\.org/(?:1998|1999|2000|2001|2005)/', re.I
)

# JS template-literal placeholders (${expr}) or JSX/template expressions ({expr}).
# A URL containing an unencoded `{` followed by an identifier was never interpolated
# at extract time and cannot be a real URL.
_TEMPLATE_EXPR_RE = re.compile(r'\$?\{[A-Za-z_$]')


def is_plausible_url(u: str) -> bool:
    """Return False for patterns that are clearly not real web URLs.

    Keeps the filter cheap and precise — only removes categories where
    false-positive rate is ~100%: XML namespace URIs and JS template/expression
    strings that were never resolved to a real host.
    """
    if not u or len(u) < 6:
        return False
    if _XML_NS_RE.match(u):
        return False
    if _TEMPLATE_EXPR_RE.search(u):
        return False
    return True
