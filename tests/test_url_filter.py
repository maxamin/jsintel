"""Regression tests for the URL plausibility filter (_urlutil.is_plausible_url).

Guards the false-positive categories found in real lab output:
  - XML namespace URIs (w3.org/1999/, /2000/, /2005/, etc.)
  - JS template-literal placeholders (${expr})
  - JSX/template expression hosts ({this.host})
  - Real URLs that must pass through unchanged
"""
from __future__ import annotations

import pytest

from modules.extractor.analyzers._urlutil import is_plausible_url


@pytest.mark.parametrize("url", [
    # XML namespace URIs — specification identifiers, not web endpoints
    "http://www.w3.org/2000/svg",
    "http://www.w3.org/1999/xhtml",
    "http://www.w3.org/1999/xlink",
    "http://www.w3.org/1998/Math/MathML",
    "http://www.w3.org/2000/xmlns/",
    "http://www.w3.org/2005/Atom",
    "http://www.w3.org/2001/XMLSchema-instance",
    # JS template literals — unresolved ${...} interpolation
    "//img.youtube.com/vi/${r.src}/default.jpg",
    "https://player.vimeo.com/video/${r.src}",
    "https://${n}/v1/lb/${t.applicationId}",
    "https://gateway.ipfs.io/ipfs/${r}",
    "https://binaries.soliditylang.org/bin/${i}",
    "//totp/${T}:${s}?secret=${d}&issuer=${T}",
    # JSX / template expression in host position
    "//${this.windowRefService.nativeWindow.location.host}",
    "//{location.host}/api",
])
def test_rejects_false_positives(url: str) -> None:
    assert not is_plausible_url(url), f"Should have been rejected: {url}"


@pytest.mark.parametrize("url", [
    # Real absolute URLs
    "https://api.example.com/v1/users",
    "http://juice-shop.vuln.lab:3000/rest/products",
    "https://socket.io/docs/v3/migrating-from-2-x-to-3-0/",
    "https://popper.js.org/",
    "//cdn.example.com/bundle.js",
    # API paths with query strings
    "https://example.com/api?key=abc123&page=1",
    # Localhost and IP
    "http://localhost:8080/health",
    "http://127.0.0.1:4000/api",
    # IPFS with a real CID (no template placeholder)
    "https://gateway.ipfs.io/ipfs/QmYjtig7VJQ6XsnUjqqJvj7QaMcCAwtrgNdahSiFofrE7o",
])
def test_passes_real_urls(url: str) -> None:
    assert is_plausible_url(url), f"Should have been accepted: {url}"
