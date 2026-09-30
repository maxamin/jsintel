"""End-to-end tests for the form stage CLI (modules.forms.main) and the listener
integration (CaptureStore._run_forms).
"""
from __future__ import annotations

import json
import socketserver
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs

import pytest

from modules.forms import main as forms_main
from modules.forms.driver import find_chromium


class _Handler(BaseHTTPRequestHandler):
    seen: list = []
    page_html = b""

    def log_message(self, *a):
        pass

    def do_GET(self):
        type(self).seen.append(("GET", self.path, dict(self.headers)))
        if self.path == "/" or self.path.endswith(".html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(type(self).page_html)
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode()
        type(self).seen.append(("POST", self.path, body, dict(self.headers)))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"created")


@pytest.fixture()
def server():
    _Handler.seen = []
    _Handler.page_html = (b'<html><body><form action="/register" method="post">'
                          b'<input type="email" name="email" required>'
                          b'<input type="password" name="pwd" minlength="12"></form></body></html>')
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}", _Handler
    finally:
        srv.shutdown()


def test_main_url_path_submits_and_writes_report(tmp_path, server, monkeypatch):
    base, handler = server
    monkeypatch.delenv("JSINTEL_AUTH_COOKIE", raising=False)
    monkeypatch.delenv("JSINTEL_AUTH_BEARER", raising=False)
    rc = forms_main.main(["--url", f"{base}/", "--output", str(tmp_path)])
    assert rc == 0
    report = json.loads((tmp_path / "reports" / "forms.json").read_text())
    assert report["forms_found"] == 1 and report["forms_submitted"] == 1
    assert any(m == "POST" and p == "/register" for (m, p, *_rest) in handler.seen)


def test_main_no_submit_fills_only(tmp_path, server):
    base, handler = server
    forms_main.main(["--url", f"{base}/", "--output", str(tmp_path), "--no-submit"])
    report = json.loads((tmp_path / "reports" / "forms.json").read_text())
    assert report["forms_found"] == 1 and report["forms_submitted"] == 0
    assert not any(m == "POST" for (m, *_rest) in handler.seen)  # nothing submitted


def test_main_honours_auth_env(tmp_path, server, monkeypatch):
    base, handler = server
    monkeypatch.setenv("JSINTEL_AUTH_COOKIE", "sid=secret")
    monkeypatch.setenv("JSINTEL_AUTH_BEARER", "JWTV")
    forms_main.main(["--url", f"{base}/", "--output", str(tmp_path)])
    post = [s for s in handler.seen if s[0] == "POST"][0]
    hdrs = post[3]
    assert hdrs.get("Cookie") == "sid=secret" and hdrs.get("Authorization") == "Bearer JWTV"


def test_main_scope_filter_skips_out_of_scope(tmp_path, server, capsys):
    base, handler = server
    forms_main.main(["--url", f"{base}/", "--output", str(tmp_path), "--scope", "not-my-host.example"])
    # Out-of-scope: the page is never even fetched.
    assert not any(p == "/" for (_m, p, *_rest) in handler.seen)
    report = json.loads((tmp_path / "reports" / "forms.json").read_text())
    assert report["pages_probed"] == 0


def test_main_reuses_downloaded_pages_from_output(tmp_path, server):
    base, handler = server
    # Simulate a prior pipeline run: a downloaded page asset + manifest.
    assets = tmp_path / "assets"
    assets.mkdir()
    page = assets / "000000_index.html"
    page.write_bytes(handler.page_html.replace(b'action="/register"',
                                               f'action="{base}/register"'.encode()))
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "assets.json").write_text(json.dumps([
        {"url": f"{base}/", "type": "page", "local_path": str(page), "status": "downloaded"}
    ]))
    rc = forms_main.main(["--output", str(tmp_path)])  # no --url -> reuse output
    assert rc == 0
    report = json.loads((reports / "forms.json").read_text())
    assert report["forms_found"] == 1 and report["forms_submitted"] == 1


@pytest.mark.skipif(not find_chromium(), reason="Chromium not installed")
def test_main_browser_feeds_discovered_endpoints_back(tmp_path):
    # A JS page that fetches an endpoint on load; --browser should capture it
    # (resolved to an absolute, in-scope URL) and append it to crawled_urls.txt.
    # action=javascript:void(0) so submitting does not navigate away mid-capture.
    html = (b'<html><body><form id="f" action="javascript:void(0)">'
            b'<input name="q" id="q"><button type="submit">go</button></form>'
            b'<script>fetch("/api/discovered?x=1");</script></body></html>')

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html if self.path == "/" else b"ok")

    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{port}"
        forms_main.main(["--url", f"{base}/", "--output", str(tmp_path), "--browser",
                         "--scope", "127.0.0.1"])
    finally:
        srv.shutdown()
    report = json.loads((tmp_path / "reports" / "forms.json").read_text())
    assert any("/api/discovered" in e["url"] for e in report["discovered_endpoints"])
    crawled = (tmp_path / "assets" / "crawled_urls.txt").read_text()
    assert "/api/discovered" in crawled


def test_browser_path_runs_on_pages_without_static_forms(monkeypatch):
    # Regression: an SPA page has no static <form>, but the browser (AJAX-spider)
    # path must still run — that is exactly where it discovers client-rendered
    # forms and their XHR. run() must not `continue` past a form-less page.
    called = {}

    class _Drv:
        ok = True
        reason = ""
        filled = 0
        submitted = 0
        endpoints = [{"method": "GET", "url": "https://spa.test/api/data"}]

        def to_record(self):
            return {"ok": True, "endpoints": self.endpoints}

    def fake_drive(url, fill_map, **kw):
        called["url"] = url
        return _Drv()

    monkeypatch.setattr(forms_main, "drive_page", fake_drive)
    report = forms_main.run([("https://spa.test/", "<html><body><div id=app></div></body></html>")],
                            submit=False, use_browser=True, headers={}, chromium="/bin/true",
                            seed=1, extra_denylist=[], timeout=5)
    assert called.get("url") == "https://spa.test/"           # browser path executed
    assert any(e["url"].endswith("/api/data") for e in report["discovered_endpoints"])


# -- listener integration ------------------------------------------------------
def test_listener_run_forms_over_captured_pages(tmp_path, server):
    base, handler = server
    from modules.listener import CaptureStore
    store = CaptureStore(tmp_path, Path("config/config.yaml"))
    store.forms = True
    # A captured HTML page (as the listener would have stored it), action -> live server.
    page = tmp_path / "assets" / "cap_page.html"
    page.write_bytes(handler.page_html.replace(b'action="/register"',
                                               f'action="{base}/register"'.encode()))
    assets = [{"url": f"{base}/", "type": "page", "local_path": str(page), "status": "downloaded"}]
    summary = store._run_forms(assets)
    assert summary["ran"] is True
    assert summary["forms_found"] == 1 and summary["forms_submitted"] == 1
    assert (tmp_path / "reports" / "forms.json").is_file()


def test_listener_run_forms_no_pages_is_reported(tmp_path):
    from modules.listener import CaptureStore
    store = CaptureStore(tmp_path, Path("config/config.yaml"))
    store.forms = True
    summary = store._run_forms([{"url": "https://t/x.js", "type": "javascript"}])
    assert summary["ran"] is False and "no HTML" in summary["reason"]
