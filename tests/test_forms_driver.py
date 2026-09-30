"""Headless-Chromium (CDP) driver: unit tests for the pure pieces plus a
Chromium-gated integration test that a form's JavaScript XHR/fetch is captured.
"""
from __future__ import annotations

import socketserver
import threading
from http.server import BaseHTTPRequestHandler

import pytest

from modules.forms.driver import (build_fill_and_trigger_js,
                                   build_instrumentation_js, drive_page,
                                   find_chromium, parse_captured)


# -- pure builders / parsers (no browser) -------------------------------------
def test_instrumentation_hooks_all_network_apis():
    js = build_instrumentation_js()
    for api in ("XMLHttpRequest", "fetch", "WebSocket", "sendBeacon", "__jsintel"):
        assert api in js


def test_fill_js_embeds_values_and_denylist_and_submit_flag():
    js = build_fill_and_trigger_js({"email": "a@b.com"}, submit=True, deny_source="checkout|swap")
    assert '"email"' in js and "a@b.com" in js
    assert "checkout|swap" in js
    assert "doSubmit = true" in js
    js2 = build_fill_and_trigger_js({}, submit=False, deny_source="x")
    assert "doSubmit = false" in js2


def test_parse_captured_dedupes_and_drops_pseudo_schemes():
    raw = [
        {"method": "get", "url": "https://t/api"},
        {"method": "GET", "url": "https://t/api"},          # dup (case-normalized)
        {"method": "GET", "url": "https://t/api#frag"},      # dup (fragment stripped)
        {"method": "POST", "url": "https://t/save", "body": "a=1"},
        {"url": "data:text/plain,x"},                        # dropped
        {"url": "blob:abc"},                                 # dropped
        {"url": ""},                                          # dropped
        "not-a-dict",
    ]
    out = parse_captured(raw)
    urls = [(e["method"], e["url"]) for e in out]
    assert ("GET", "https://t/api") in urls
    assert ("POST", "https://t/save") in urls
    assert all(not e["url"].startswith(("data:", "blob:")) for e in out)
    assert len(out) == 2  # /api (3 rows collapse by method+url-without-fragment) + /save


def test_parse_captured_handles_none_and_empty():
    assert parse_captured(None) == []
    assert parse_captured([]) == []


def test_drive_page_without_chromium_is_graceful(monkeypatch):
    monkeypatch.setattr("modules.forms.driver.find_chromium", lambda explicit="": "")
    res = drive_page("https://t.test/", {}, chromium="")
    assert res.ok is False and "chromium" in res.reason.lower()


def test_drive_page_non_http_scheme_rejected():
    # Pass an explicit (fake) chromium so the no-chromium branch is skipped.
    res = drive_page("file:///etc/passwd", {}, chromium="/bin/true")
    assert res.ok is False and "non-http" in res.reason


# -- Chromium-gated end-to-end -------------------------------------------------
_HTML = b"""<!doctype html><html><body>
<form id="f" action="javascript:void(0)">
  <input type="email" name="email" id="email">
  <input type="text" name="city" id="city">
  <button type="submit" id="go">Send</button>
</form>
<script>
document.getElementById('f').addEventListener('submit', function(e){ e.preventDefault();
  var x=new XMLHttpRequest(); x.open('POST','/api/contact'); x.send('e='+document.getElementById('email').value);
  fetch('/api/track?city='+encodeURIComponent(document.getElementById('city').value)); });
fetch('/api/bootstrap');
</script></body></html>"""


class _PageHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(_HTML if self.path == "/" else b"ok")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


@pytest.fixture()
def page_server():
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _PageHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        srv.shutdown()


@pytest.mark.skipif(not find_chromium(), reason="Chromium not installed")
def test_driver_triggers_js_and_captures_xhr(page_server):
    res = drive_page(page_server, {"email": "a@b.com", "city": "Aurora"},
                     submit=True, timeout=30, settle=2.0)
    assert res.ok, res.reason
    assert res.filled >= 2 and res.submitted >= 1
    urls = [e["url"] for e in res.endpoints]
    assert any("/api/bootstrap" in u for u in urls)   # load-time fetch
    assert any("/api/contact" in u for u in urls)      # submit-triggered XHR
    assert any("/api/track?city=Aurora" in u for u in urls)  # fetch using the filled value
