"""Unit tests for the mitmproxy capture-streamer addon. The addon does not import
mitmproxy, so its serialization helpers are testable with plain Python; we also verify
its output is accepted by the listener's CaptureStore (addon -> listener contract)."""
import base64
import importlib.util
from pathlib import Path

from modules.listener import CaptureStore

CFG = Path("config/config.yaml")
_MOD = Path(__file__).resolve().parent.parent / "integrations/mitmproxy/jsintel_mitm.py"
_spec = importlib.util.spec_from_file_location("jsintel_mitm", _MOD)
mitm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mitm)


def test_encode_body_text_vs_binary():
    assert mitm._encode_body(b"var x=1;", "application/javascript") == ("var x=1;", False)
    png = b"\x89PNG\r\n\x1a\n\x00\xff"
    body, b64 = mitm._encode_body(png, "image/png")
    assert b64 and base64.b64decode(body) == png
    # texty content-type but undecodable bytes -> falls back to base64
    body2, b64_2 = mitm._encode_body(b"\xff\xfe\x00", "text/html")
    assert b64_2 and base64.b64decode(body2) == b"\xff\xfe\x00"
    assert mitm._encode_body(None, "text/html") == ("", False)


def test_is_texty():
    assert mitm._is_texty("text/html; charset=utf-8")
    assert mitm._is_texty("application/vnd.api+json")
    assert not mitm._is_texty("application/octet-stream")
    assert not mitm._is_texty("image/png")


def test_in_scope():
    assert mitm.in_scope("app.example.com", [])                    # empty scope = all
    assert mitm.in_scope("api.example.com", ["example.com"])       # substring match
    assert not mitm.in_scope("evil.test", ["example.com"])


def test_build_ws_capture():
    t = mitm.build_ws_capture("wss://h/s", from_client=True, content=b"hello /api/x")
    assert t == {"type": "ws", "url": "wss://h/s", "direction": "send",
                 "opcode": "text", "payload": "hello /api/x"}
    b = mitm.build_ws_capture("wss://h/s", from_client=False, content=b"\xff\x00")
    assert b["opcode"] == "binary" and base64.b64decode(b["payload"]) == b"\xff\x00"


def test_build_http_capture_shape():
    cap = mitm.build_http_capture(
        "http://h/a.js", "get", {"content-type": "application/javascript"}, None,
        200, {"content-type": "application/javascript", "server": "nginx"}, b"fetch('/api/v1/z')")
    assert cap["type"] == "http" and cap["method"] == "GET" and cap["status"] == 200
    assert cap["response_body"] == "fetch('/api/v1/z')" and cap["response_body_b64"] is False
    assert "request_body" not in cap                                # empty request body omitted


def test_addon_output_is_accepted_by_listener(tmp_path):
    # The contract that matters: what the addon emits, the listener ingests + analyzes.
    s = CaptureStore(tmp_path, CFG)
    # a binary-encoded JS body (as the addon would send for an odd content-type)
    js = b"const K='AKIAIOSFODNN7EXAMPLE'; fetch('/api/v1/users');"
    cap = mitm.build_http_capture("http://cap.test/app.js", "GET", {}, None, 200,
                                  {"content-type": "application/octet-stream"}, js)
    assert cap["response_body_b64"] is True                          # binary -> base64
    assert s.add_http(cap)                                           # listener accepts + decodes
    s.process()
    import json
    findings = {f["finding_type"] for f in json.loads((tmp_path / "reports/findings.json").read_text())}
    eps = {e["endpoint"] for e in json.loads((tmp_path / "reports/endpoints.json").read_text())}
    assert "hardcoded_secret" in findings and "/api/v1/users" in eps  # decoded + mined
