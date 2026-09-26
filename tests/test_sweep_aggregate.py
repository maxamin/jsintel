"""Mass-sweep aggregation: rolling per-target reports into one summary."""
import json

from modules import sweep_aggregate


def _write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


def _make_target(base, name, *, status="ok", subs=None, ports=None, summary=None, fuzz=None):
    tdir = base / "targets" / sweep_aggregate.sanitize(name)
    (tdir / "assets").mkdir(parents=True, exist_ok=True)
    (tdir / "reports").mkdir(parents=True, exist_ok=True)
    (tdir / ".sweep_status").write_text(status + "\n", encoding="utf-8")
    if subs is not None:
        (tdir / "assets" / "subdomains.txt").write_text("\n".join(subs) + "\n", encoding="utf-8")
    if ports is not None:
        _write(tdir / "reports" / "ports.json", ports)
    if summary is not None:
        _write(tdir / "reports" / "summary.json", summary)
    if fuzz is not None:
        _write(tdir / "reports" / "fuzz_summary.json", fuzz)


def test_aggregate_totals_and_ordering(tmp_path):
    _make_target(
        tmp_path, "alpha.test",
        subs=["https://a.alpha.test", "https://b.alpha.test"],
        ports=[
            {"host": "a.alpha.test", "port": 443},
            {"host": "a.alpha.test", "port": 8443},
            {"host": "a.alpha.test", "port": 3000},
        ],
        summary={"total_assets": 10, "endpoint_count": 4, "security_finding_count": 2},
        fuzz={"requested": 100, "interesting": 5},
    )
    _make_target(
        tmp_path, "beta.test",
        subs=["https://beta.test"],
        ports=[{"host": "beta.test", "port": 80}],
        summary={"total_assets": 3, "endpoint_count": 1, "security_finding_count": 9},
        fuzz={"requested": 50, "interesting": 1},
    )
    _make_target(tmp_path, "gamma.test", status="failed rc=1")

    agg = sweep_aggregate.aggregate(tmp_path, ["alpha.test", "beta.test", "gamma.test"])

    totals = agg["totals"]
    assert totals["targets"] == 3
    assert totals["ok"] == 2
    assert totals["failed"] == 1
    assert totals["live_subdomains"] == 3
    assert totals["web_services"] == 4  # 3 + 1
    assert totals["extra_port_services"] == 2  # 8443 + 3000 (80/443 excluded)
    assert totals["assets"] == 13
    assert totals["security_findings"] == 11
    assert totals["fuzz_interesting"] == 6

    # Ordered by most security findings first: beta (9) before alpha (2).
    assert [r["target"] for r in agg["targets"]] == ["beta.test", "alpha.test", "gamma.test"]

    # Files were written.
    disk = json.loads((tmp_path / "reports" / "sweep_summary.json").read_text())
    assert disk["totals"]["targets"] == 3
    md = (tmp_path / "reports" / "sweep_summary.md").read_text()
    assert "JSIntel Mass Sweep Summary" in md
    assert "beta.test" in md


def test_aggregate_handles_missing_and_malformed(tmp_path):
    # A target dir that never produced reports must not crash aggregation.
    (tmp_path / "targets" / "empty.test").mkdir(parents=True)
    # A target with malformed JSON should be treated as empty, not fatal.
    bad = tmp_path / "targets" / "bad.test" / "reports"
    bad.mkdir(parents=True)
    (bad / "ports.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "targets" / "bad.test" / ".sweep_status").write_text("ok\n")

    agg = sweep_aggregate.aggregate(tmp_path, ["empty.test", "bad.test"])
    assert agg["totals"]["targets"] == 2
    assert agg["totals"]["web_services"] == 0
    statuses = {r["target"]: r["status"] for r in agg["targets"]}
    assert statuses["empty.test"] == "missing"
    assert statuses["bad.test"] == "ok"
