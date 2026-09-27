"""triage — per-host risk ranking. Verifies severity weighting, that info-only
inventory does not score, sensitive-endpoint detection, non-standard-port exposure,
and ranking order."""
import json
import sqlite3
from pathlib import Path

from modules import triage
from modules.triage import build_triage, is_sensitive_endpoint

ROOT = Path(__file__).resolve().parents[1]


def _db(output: Path) -> sqlite3.Connection:
    (output / "database").mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(output / "database" / "recon.db")
    con.executescript((ROOT / "database" / "schema.sql").read_text())
    return con


def _asset(con, url, t="javascript"):
    return con.execute("INSERT INTO assets(url,asset_type,status) VALUES(?,?,?)",
                       (url, t, "downloaded")).lastrowid


def test_is_sensitive_endpoint():
    assert is_sensitive_endpoint("/api/Users") and is_sensitive_endpoint("/admin/config")
    assert is_sensitive_endpoint("/.git/config") and is_sensitive_endpoint("/login")
    assert not is_sensitive_endpoint("/styles.css") and not is_sensitive_endpoint("")


def test_build_triage_ranks_by_risk_and_ignores_info(tmp_path):
    con = _db(tmp_path)
    a = _asset(con, "http://high.test/app.js")       # high-severity finding + sensitive ep
    b = _asset(con, "http://low.test/app.js")        # only an info finding -> no score
    con.execute("INSERT INTO findings(asset_id,finding_type,severity,value) VALUES(?,?,?,?)",
                (a, "hardcoded_secret", "high", "AKIA…"))
    con.execute("INSERT INTO findings(asset_id,finding_type,severity,value) VALUES(?,?,?,?)",
                (b, "call_graph", "info", "x -> y"))
    con.execute("INSERT INTO endpoints(asset_id,endpoint,kind) VALUES(?,?,?)", (a, "/admin/reset", "api"))
    con.execute("INSERT INTO endpoints(asset_id,endpoint,kind) VALUES(?,?,?)", (a, "/style.css", "url"))
    con.execute("INSERT INTO services(host,port,scheme,url,status) VALUES(?,?,?,?,?)",
                ("high.test", 8443, "https", "https://high.test:8443/", 200))
    con.commit()
    result = build_triage(con)
    con.close()
    hosts = {h["host"]: h for h in result}
    assert result[0]["host"] == "high.test"                     # highest risk first
    hi = hosts["high.test"]
    assert hi["max_severity"] == "high" and hi["risk_score"] > 0
    assert hi["score_breakdown"]["findings"] > 0
    assert hi["score_breakdown"]["endpoints"] > 0               # sensitive /admin scored
    assert hi["score_breakdown"]["exposure"] > 0               # non-standard port + open 200
    assert "/admin/reset" in hi["sensitive_endpoints"] and "/style.css" not in hi["sensitive_endpoints"]
    # low.test had only an info finding -> not ranked at all (no score, no endpoints/services)
    assert "low.test" not in hosts


def test_triage_main_writes_reports(tmp_path):
    con = _db(tmp_path)
    a = _asset(con, "http://h.test/app.js")
    con.execute("INSERT INTO findings(asset_id,finding_type,severity,value) VALUES(?,?,?,?)",
                (a, "dangerous_eval", "medium", "eval(x)"))
    con.commit(); con.close()
    out = triage.main(tmp_path)
    assert out["hosts_ranked"] >= 1
    data = json.loads((tmp_path / "reports/triage.json").read_text())
    hosts = data if isinstance(data, list) else data.get("hosts", [])
    assert any(h["host"] == "h.test" for h in hosts)
    assert (tmp_path / "reports/triage.md").is_file()
