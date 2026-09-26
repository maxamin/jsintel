"""Run-to-run diff between two JSIntel output directories."""
import json

from modules import diff


def _write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


def _make_run(base, *, assets=None, endpoints=None, findings=None, ports=None):
    r = base / "reports"
    r.mkdir(parents=True, exist_ok=True)
    _write(r / "assets.json", assets or [])
    _write(r / "endpoints.json", endpoints or [])
    _write(r / "findings.json", findings or [])
    _write(r / "ports.json", ports or [])
    return base


def test_diff_detects_added_and_removed(tmp_path):
    old = _make_run(
        tmp_path / "old",
        assets=[{"url": "http://a.test/app.js"}],
        endpoints=[{"asset_url": "http://a.test/app.js", "endpoint": "/api/old", "kind": "api"}],
        findings=[{"asset_url": "http://a.test/app.js", "finding_type": "secret", "severity": "high", "value": "k1"}],
        ports=[{"host": "a.test", "port": 80, "status": 200, "title": ""}],
    )
    new = _make_run(
        tmp_path / "new",
        assets=[{"url": "http://a.test/app.js"}, {"url": "http://b.test/x.js"}],
        endpoints=[{"asset_url": "http://a.test/app.js", "endpoint": "/api/new", "kind": "api"}],
        findings=[{"asset_url": "http://a.test/app.js", "finding_type": "secret", "severity": "high", "value": "k1"},
                  {"asset_url": "http://b.test/x.js", "finding_type": "eval", "severity": "critical", "value": "e1"}],
        ports=[{"host": "a.test", "port": 80, "status": 200, "title": ""},
               {"host": "b.test", "port": 8080, "status": 200, "title": "X"}],
    )

    d = diff.build_diff(old, new)

    assert d["hosts"]["added"] == ["b.test"]
    assert d["hosts"]["removed"] == []
    assert any(s["host"] == "b.test" and s["port"] == 8080 for s in d["services"]["added"])
    added_eps = {e["endpoint"] for e in d["endpoints"]["added"]}
    removed_eps = {e["endpoint"] for e in d["endpoints"]["removed"]}
    assert "/api/new" in added_eps and "/api/old" in removed_eps
    # The new critical finding is added; the unchanged high finding is neither.
    assert [f["finding_type"] for f in d["findings"]["added"]] == ["eval"]
    assert d["findings"]["removed"] == []


def test_diff_identical_runs_have_no_delta(tmp_path):
    payload = dict(
        assets=[{"url": "http://a.test/app.js"}],
        endpoints=[{"asset_url": "http://a.test/app.js", "endpoint": "/api", "kind": "api"}],
        findings=[{"asset_url": "http://a.test/app.js", "finding_type": "secret", "severity": "low", "value": "v"}],
        ports=[{"host": "a.test", "port": 443, "status": 200, "title": "t"}],
    )
    a = _make_run(tmp_path / "a", **payload)
    b = _make_run(tmp_path / "b", **payload)
    d = diff.build_diff(a, b)
    for section in ("hosts", "services", "endpoints", "findings"):
        assert d[section]["added"] == [] and d[section]["removed"] == [], section


def test_diff_tolerates_missing_reports_and_writes_files(tmp_path):
    old = tmp_path / "old"       # no reports dir at all
    new = _make_run(tmp_path / "new", assets=[{"url": "http://a.test/app.js"}],
                    ports=[{"host": "a.test", "port": 80, "status": 200}])
    d = diff.write_diff(old, new, new)
    assert "a.test" in d["hosts"]["added"]
    assert (new / "reports" / "diff.json").exists()
    assert (new / "reports" / "diff.md").exists()
