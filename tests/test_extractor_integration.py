import json
from pathlib import Path

from modules.extractor.main import run


def test_extractor_preserves_phase_one_reports_and_writes_errors(tmp_path: Path) -> None:
    source = tmp_path / "app.js"
    source.write_text(
        'import React from "react"; const client=require("axios"); '
        'const path="/api/users"; const socket="wss://socket.example.test"; '
        'const remote="https://api.example.test/v1"; React.useState();',
        encoding="utf-8",
    )
    manifest = tmp_path / "assets.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "url": "https://app.example.test/app.js",
                    "type": "javascript",
                    "status": "downloaded",
                    "local_path": str(source),
                }
            ]
        ),
        encoding="utf-8",
    )

    assert run(manifest, tmp_path / "reports") == 0
    reports = tmp_path / "reports"
    assert json.loads((reports / "endpoints.json").read_text()) == [
        {"asset_url": "https://app.example.test/app.js", "endpoint": "/api/users", "kind": "api"}
    ]
    assert json.loads((reports / "websocket.json").read_text()) == [
        {"asset_url": "https://app.example.test/app.js", "url": "wss://socket.example.test", "kind": "websocket"}
    ]
    assert {item["module"] for item in json.loads((reports / "imports.json").read_text())} == {"react", "axios"}
    assert json.loads((reports / "frameworks.json").read_text()) == [
        {"asset_url": "https://app.example.test/app.js", "technology": "React", "evidence": "signature match"}
    ]
    assert json.loads((reports / "errors.json").read_text()) == []


def test_extractor_records_missing_asset_as_recoverable_error(tmp_path: Path) -> None:
    manifest = tmp_path / "assets.json"
    manifest.write_text(
        json.dumps(
            [{"url": "https://app.example.test/missing.js", "type": "javascript", "status": "downloaded", "local_path": str(tmp_path / "missing.js")}]
        ),
        encoding="utf-8",
    )

    assert run(manifest, tmp_path / "reports") == 1
    errors = json.loads((tmp_path / "reports" / "errors.json").read_text())
    assert errors[0]["analyzer"] == "reader"
