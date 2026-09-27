"""reporter.main — derives summary.json / summary.md / assets.csv from the DB.
Verifies 'service' assets are excluded from asset counts and that info-severity
inventory findings are split out from real security findings."""
import csv
import json
import sqlite3
from pathlib import Path

from modules import reporter

ROOT = Path(__file__).resolve().parents[1]


def _build_db(output: Path):
    (output / "database").mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(output / "database" / "recon.db")
    con.executescript((ROOT / "database" / "schema.sql").read_text())
    ins = lambda url, t: con.execute(
        "INSERT INTO assets(url,asset_type,local_path,status) VALUES(?,?,?,?)",
        (url, t, f"/x/{url[-8:]}", "downloaded")).lastrowid
    js = ins("http://h/app.js", "javascript")
    ins("http://h/index.html", "page")
    ins("http://h/svc", "service")                       # excluded from asset counts
    con.execute("INSERT INTO endpoints(asset_id,endpoint,kind) VALUES(?,?,?)", (js, "/api/v1/users", "api"))
    con.execute("INSERT INTO technologies(asset_id,name) VALUES(?,?)", (js, "Angular"))
    con.execute("INSERT INTO findings(asset_id,finding_type,severity,value) VALUES(?,?,?,?)",
                (js, "hardcoded_secret", "high", "AKIA…"))
    con.execute("INSERT INTO findings(asset_id,finding_type,severity,value) VALUES(?,?,?,?)",
                (js, "call_graph", "info", "a -> b"))     # inventory, not a security finding
    con.commit(); con.close()


def test_reporter_summary_counts_and_severity_split(tmp_path):
    _build_db(tmp_path)
    reporter.main(tmp_path)
    s = json.loads((tmp_path / "reports/summary.json").read_text())
    assert s["total_assets"] == 2               # 'service' asset excluded
    assert s["javascript_count"] == 1
    assert s["endpoint_count"] == 1 and s["technology_count"] == 1
    assert s["finding_count"] == 2              # all findings
    assert s["security_finding_count"] == 1     # 'info' call_graph excluded
    assert s["findings_by_severity"] == {"high": 1, "info": 1}
    assert s["file_statistics"].get("service") == 1


def test_reporter_writes_markdown_and_csv(tmp_path):
    _build_db(tmp_path)
    reporter.main(tmp_path)
    md = (tmp_path / "reports/summary.md").read_text()
    assert "Total assets: 2" in md and "Security findings (low+): 1" in md
    rows = list(csv.DictReader((tmp_path / "reports/assets.csv").open()))
    urls = {r["url"] for r in rows}
    assert "http://h/app.js" in urls and len(rows) == 3   # CSV lists every asset row
