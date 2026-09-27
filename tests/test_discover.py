"""Feedback-discovery candidate building. The safety-critical property: candidates are
only ever built on hosts already in scope (already fetched) — never a new host — and
templated/placeholder routes are skipped."""
import json
from pathlib import Path

from modules import discover


def _setup(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir(parents=True)
    (reports / "assets.json").write_text(json.dumps([
        {"url": "http://app.test/index.html", "type": "page"},
        {"url": "https://api.test/v1/", "type": "page"},
    ]))
    (reports / "endpoints.json").write_text(json.dumps([
        {"asset_url": "http://app.test/", "endpoint": "/admin/panel.js"},   # site-relative
        {"asset_url": "http://app.test/", "endpoint": "/rest/basket/{}/x"}, # templated -> skip
        {"asset_url": "http://app.test/", "endpoint": "https://api.test/v2/keys"},  # abs in-scope
        {"asset_url": "http://app.test/", "endpoint": "https://evil.test/x"},       # abs OFF-scope
    ]))
    (reports / "urls.json").write_text(json.dumps([
        {"asset_url": "http://app.test/", "url": "https://github.com/some/repo"},   # OFF-scope
        {"asset_url": "http://app.test/", "url": "http://app.test/static/lib.js"},  # in-scope
    ]))
    return reports


def test_candidates_stay_in_scope(tmp_path):
    reports = _setup(tmp_path)
    in_scope = {"app.test": "http", "api.test": "https"}
    existing = {"http://app.test/index.html", "https://api.test/v1/"}
    cands = discover._candidates(reports, in_scope, existing, limit=100)
    hosts = {__import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(c).netloc for c in cands}
    assert hosts <= {"app.test", "api.test"}                     # NEVER a new host
    assert not any("evil.test" in c or "github.com" in c for c in cands)   # off-scope excluded
    # site-relative endpoint resolved against BOTH known hosts
    assert "http://app.test/admin/panel.js" in cands
    assert "https://api.test/admin/panel.js" in cands
    # absolute in-scope kept; templated skipped
    assert "https://api.test/v2/keys" in cands
    assert "http://app.test/static/lib.js" in cands
    assert not any("{}" in c or "basket" in c for c in cands)


def test_candidates_exclude_already_fetched(tmp_path):
    reports = _setup(tmp_path)
    in_scope = {"app.test": "http", "api.test": "https"}
    existing = {"http://app.test/index.html", "https://api.test/v1/",
                "http://app.test/static/lib.js"}                 # already have lib.js
    cands = discover._candidates(reports, in_scope, existing, limit=100)
    assert "http://app.test/static/lib.js" not in cands          # not re-fetched


def test_classify_matches_pipeline():
    assert discover._classify("http://h/a.js") == "javascript"
    assert discover._classify("http://h/a.map") == "source_map"
    assert discover._classify("http://h/x.json") == "configuration"
    assert discover._classify("http://h/login.php") == "page"
    assert discover._classify("http://h/route") == "page"


def test_limit_is_respected(tmp_path):
    reports = _setup(tmp_path)
    cands = discover._candidates(reports, {"app.test": "http", "api.test": "https"},
                                 {"http://app.test/index.html"}, limit=2)
    assert len(cands) == 2
