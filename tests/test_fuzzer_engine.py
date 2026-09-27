"""End-to-end engine runs over a synthetic JSIntel output directory (offline)."""
import json
from pathlib import Path

from modules.fuzzer.engine import build_candidates, load_origins, run
from modules.fuzzer.models import FuzzConfig
from modules.fuzzer.scope import Scope
from modules.fuzzer.transport import Response
from modules.fuzzer.wordlists import WordlistProvider


class FakeTransport:
    def __init__(self, table: dict[str, Response], default: Response | None = None):
        self.table = table
        self.default = default or Response(status=404, length=20, words=3)
        self.calls: list[str] = []

    def fetch(self, url, method, timeout, headers, follow_redirects):
        self.calls.append(url)
        for needle, response in self.table.items():
            if needle in url:
                return response
        return self.default


def _seed_reports(output: Path) -> Path:
    reports = output / "reports"
    reports.mkdir(parents=True)
    (reports / "endpoints.json").write_text(
        json.dumps(
            [
                {"asset_url": "https://app.example.test/static/main.js", "endpoint": "/api/v1/users", "kind": "api"},
                {"asset_url": "https://app.example.test/static/main.js", "endpoint": "/graphql", "kind": "api"},
                {"asset_url": "https://cdn.thirdparty.io/lib.js", "endpoint": "/api/track", "kind": "api"},
            ]
        ),
        encoding="utf-8",
    )
    (reports / "urls.json").write_text(
        json.dumps(
            [
                {"asset_url": "https://app.example.test/static/main.js", "url": "https://app.example.test/assets/app.js", "kind": "url"},
                {"asset_url": "https://app.example.test/static/main.js", "url": "https://www.google-analytics.com/ga.js", "kind": "url"},
            ]
        ),
        encoding="utf-8",
    )
    return reports


def _offline_provider(tmp_path: Path) -> WordlistProvider:
    return WordlistProvider(cache_dir=tmp_path / "cache", offline=True)


def test_load_origins_reads_endpoints_and_urls(tmp_path: Path):
    _seed_reports(tmp_path)
    origins = load_origins(tmp_path / "reports")
    endpoints = {o for o, _ in origins}
    assert "/api/v1/users" in endpoints
    assert "https://app.example.test/assets/app.js" in endpoints


def test_build_candidates_is_scope_limited_and_categorized(tmp_path: Path):
    _seed_reports(tmp_path)
    origins = load_origins(tmp_path / "reports")
    scope = Scope(["app.example.test"])
    config = FuzzConfig(max_words_per_category=5, offline=True)
    candidates, by_category, in_scope = build_candidates(origins, scope, _offline_provider(tmp_path), config)

    hosts = {c.base for c in candidates}
    assert hosts == {"https://app.example.test"}  # third-party hosts excluded
    assert "api" in by_category and "graphql" in by_category and "js" in by_category
    assert in_scope == 3  # /api/v1/users, /graphql, /assets/app.js


def test_dry_run_writes_report_without_requests(tmp_path: Path):
    _seed_reports(tmp_path)
    scope = Scope(["app.example.test"])
    config = FuzzConfig(dry_run=True, offline=True, max_words_per_category=5)
    transport = FakeTransport({})
    _results, summary = run(tmp_path, scope, config, transport=transport, provider=_offline_provider(tmp_path))

    assert transport.calls == []
    assert summary.requested == 0
    assert summary.candidates > 0
    report = json.loads((tmp_path / "reports" / "fuzz.json").read_text())
    assert all(item["note"] == "dry-run" for item in report)


def test_live_run_finds_interesting_paths_in_scope_only(tmp_path: Path):
    _seed_reports(tmp_path)
    scope = Scope(["app.example.test"])
    config = FuzzConfig(offline=True, max_words_per_category=40, concurrency=4)
    # /api/v1/users context is a hard-404 dir; /api/v1/me exists (200).
    transport = FakeTransport({"/api/v1/me": Response(status=200, length=1234, words=210)})
    results, summary = run(tmp_path, scope, config, transport=transport, provider=_offline_provider(tmp_path))

    assert all("app.example.test" in url for url in transport.calls)
    assert not any("thirdparty" in url or "google" in url for url in transport.calls)
    interesting = [r for r in results if r.interesting]
    assert any(r.url == "https://app.example.test/api/v1/me" for r in interesting)
    assert summary.interesting >= 1

    report = json.loads((tmp_path / "reports" / "fuzz.json").read_text())
    assert report[0]["interesting"] is True  # interesting sorted first


def test_no_scope_yields_no_candidates(tmp_path: Path):
    _seed_reports(tmp_path)
    config = FuzzConfig(offline=True, max_words_per_category=5)
    transport = FakeTransport({})
    _results, summary = run(tmp_path, Scope(), config, transport=transport, provider=_offline_provider(tmp_path))
    assert summary.candidates == 0
    assert transport.calls == []


def test_max_candidates_cap_is_enforced(tmp_path: Path):
    _seed_reports(tmp_path)
    scope = Scope(["app.example.test"])
    config = FuzzConfig(dry_run=True, offline=True, max_words_per_category=100, max_candidates=7)
    transport = FakeTransport({})
    _results, summary = run(tmp_path, scope, config, transport=transport, provider=_offline_provider(tmp_path))
    assert summary.candidates == 7


def test_missing_reports_dir_reads_no_origins(tmp_path: Path):
    assert load_origins(tmp_path / "reports") == []


def test_candidate_budget_is_shared_fairly_across_hosts(tmp_path: Path):
    # Regression for the gala.com run where one soft-404 SPA host consumed the
    # entire candidate cap. With many origins on host A and one on host B, the cap
    # must not be monopolised by A -- host B must still get candidates.
    provider = _offline_provider(tmp_path)
    # 50 distinct API paths on host A, 1 on host B.
    origins = [(f"https://a.example.test/api/v{i}/users", "") for i in range(50)]
    origins.append(("https://b.example.test/api/v1/users", ""))
    scope = Scope(["example.test"])
    config = FuzzConfig(max_candidates=400, max_words_per_category=200, context_depth=1)

    candidates, by_category, in_scope = build_candidates(origins, scope, provider, config)

    assert len(candidates) == 400  # cap reached
    hosts = {c.url.split("/")[2] for c in candidates}
    assert "b.example.test" in hosts, "the lone host B was starved by host A"
    a_count = sum(1 for c in candidates if c.url.split("/")[2] == "a.example.test")
    b_count = sum(1 for c in candidates if c.url.split("/")[2] == "b.example.test")
    # Host B (one origin) should get a meaningful share, not a token 1-2 URLs.
    assert b_count >= 50
    assert a_count >= b_count  # A has far more origins, so it still leads
