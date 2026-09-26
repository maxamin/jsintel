"""modules/database.py ingest must be idempotent: re-running rebuilds, not doubles."""
import json
import sqlite3
from pathlib import Path

from modules import database


def _seed(output: Path, *, secret_value: str, fuzz_url: str) -> None:
    reports = output / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "assets.json").write_text(json.dumps([
        {"url": "https://app.example.test/main.js", "type": "javascript",
         "local_path": "x", "sha256": "a", "size_bytes": 1, "mime_type": "application/javascript"},
    ]))
    (reports / "endpoints.json").write_text(json.dumps([
        {"asset_url": "https://app.example.test/main.js", "endpoint": "/api/v1/users", "kind": "api"},
    ]))
    (reports / "findings.json").write_text(json.dumps([
        {"asset_url": "https://app.example.test/main.js", "finding_type": "hardcoded_secret",
         "severity": "high", "value": secret_value},
    ]))
    (reports / "fuzz.json").write_text(json.dumps([
        {"url": fuzz_url, "category": "api", "origin": "/api", "word": "users",
         "status": 200, "length": 10, "interesting": True, "note": "match"},
    ]))


def _counts(output: Path, config: Path) -> dict:
    con = sqlite3.connect(database.db_path(output, config))
    try:
        return {t: con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                for t in ("assets", "endpoints", "findings", "fuzz_results")}
    finally:
        con.close()


def test_ingest_is_idempotent_not_accumulating(tmp_path: Path):
    config = Path("config/config.yaml")
    _seed(tmp_path, secret_value="AKIA111", fuzz_url="https://app.example.test/api/users")

    database.ingest(tmp_path, config)
    first = _counts(tmp_path, config)
    assert first == {"assets": 1, "endpoints": 1, "findings": 1, "fuzz_results": 1}

    # Re-run into the same output dir (as a real re-scan does): counts must not double.
    database.ingest(tmp_path, config)
    assert _counts(tmp_path, config) == first


def test_ingest_rebuild_drops_stale_rows_from_prior_run(tmp_path: Path):
    config = Path("config/config.yaml")
    # First run: one finding + a fuzz URL on an old host.
    _seed(tmp_path, secret_value="OLD_SECRET", fuzz_url="https://old.example.test/api/x")
    database.ingest(tmp_path, config)

    # Second run overwrites the reports with different content (new host, new secret).
    _seed(tmp_path, secret_value="NEW_SECRET", fuzz_url="https://new.example.test/api/y")
    database.ingest(tmp_path, config)

    con = sqlite3.connect(database.db_path(tmp_path, config))
    try:
        findings = [r[0] for r in con.execute("SELECT value FROM findings")]
        fuzz = [r[0] for r in con.execute("SELECT url FROM fuzz_results")]
    finally:
        con.close()
    assert findings == ["NEW_SECRET"]  # stale OLD_SECRET gone
    assert fuzz == ["https://new.example.test/api/y"]  # stale old-host fuzz row gone
