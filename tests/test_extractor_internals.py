"""Extractor internals: typed findings, the streaming JSONWriter, defensive asset
reading, and the shared AST helpers."""
import json

from modules.extractor.findings import (
    EndpointFinding, ExtractionError, FrameworkFinding, ImportFinding,
    SecurityFinding, URLFinding, WebSocketFinding,
)
from modules.extractor.writer import JSONWriter
from modules.extractor.utils import read_asset
from modules.extractor import ast_utils
from modules.extractor.parser import parse_js


# --- findings ---------------------------------------------------------------
def test_finding_records_and_report_targets():
    assert URLFinding("a", "http://x").report == "urls"
    assert URLFinding("a", "http://x").to_record() == {"asset_url": "a", "url": "http://x", "kind": "url"}
    assert EndpointFinding("a", "/api").to_record() == {"asset_url": "a", "endpoint": "/api", "kind": "api"}
    assert WebSocketFinding("a", "wss://x").report == "websocket"
    assert ImportFinding("a", "react").to_record() == {"asset_url": "a", "module": "react"}
    assert FrameworkFinding("a", "Vue", "ev").to_record()["technology"] == "Vue"
    sf = SecurityFinding("a", "hardcoded_secret", "high", "AKIA…", source="s", sink="k")
    assert sf.report == "findings"
    rec = sf.to_record()
    assert rec["finding_type"] == "hardcoded_secret" and rec["severity"] == "high" and rec["sink"] == "k"
    assert ExtractionError("a", "secrets", "boom").to_record() == {
        "asset_url": "a", "analyzer": "secrets", "message": "boom"}


# --- JSONWriter -------------------------------------------------------------
def test_jsonwriter_emits_valid_arrays_and_routes_by_report(tmp_path):
    w = JSONWriter(tmp_path)
    w.write(URLFinding("a", "http://x"))
    w.write(EndpointFinding("a", "/api/v1"))
    w.write(SecurityFinding("a", "dangerous_eval", "medium", "eval(x)"))
    w.write_error(ExtractionError("a", "parser", "syntax"))
    w.close()
    urls = json.loads((tmp_path / "urls.json").read_text())
    assert urls == [{"asset_url": "a", "url": "http://x", "kind": "url"}]
    assert json.loads((tmp_path / "endpoints.json").read_text())[0]["endpoint"] == "/api/v1"
    assert json.loads((tmp_path / "findings.json").read_text())[0]["finding_type"] == "dangerous_eval"
    assert json.loads((tmp_path / "errors.json").read_text())[0]["message"] == "syntax"
    # a report that received nothing is still a valid empty array
    assert json.loads((tmp_path / "frameworks.json").read_text()) == []


def test_jsonwriter_empty_scan_closes_cleanly(tmp_path):
    JSONWriter(tmp_path).close()
    for name in JSONWriter.reports:
        assert json.loads((tmp_path / f"{name}.json").read_text()) == []


# --- read_asset -------------------------------------------------------------
def test_read_asset_tolerates_bad_bytes(tmp_path):
    p = tmp_path / "x.js"
    p.write_bytes(b"var a=1;\xff\xfe garbage")
    text = read_asset(p)                          # must not raise on invalid utf-8
    assert "var a=1;" in text


# --- ast_utils --------------------------------------------------------------
def test_ast_helpers_index_find_and_walk():
    tree = parse_js("var a='hello'; foo('world');")
    root = tree.root_node
    buckets = ast_utils._build_index(root)
    assert "string" in buckets and len(buckets["string"]) == 2   # 'hello' and 'world'
    strings = ast_utils._extract_string_literals(tree)
    assert any("hello" in s for s in strings) and any("world" in s for s in strings)
    # _find_nodes returns only requested types, in source order (by start_byte)
    found = list(ast_utils._find_nodes(root, ("string",)))
    assert [n.start_byte for n in found] == sorted(n.start_byte for n in found)
    # _walk over the whole tree yields nodes in source order and includes the strings
    walked = list(ast_utils._walk(root))
    assert len(walked) >= len(found)
