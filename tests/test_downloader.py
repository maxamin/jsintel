"""Integration guard for the download stage's per-asset ceilings.

The downloader once used `iter_content(65536)`, whose per-read-chunk timeout is
never tripped by an endpoint that trickles bytes forever (SSE / long-poll /
chunked keep-alive). Because `as_completed` waits on every worker, a single such
endpoint wedged the whole pipeline indefinitely. These tests assert the stage
now always terminates and records the outcome per asset.
"""
import gzip
import json
import socketserver
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DOWNLOADER = REPO / "modules" / "downloader.sh"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        if self.path == "/normal.js":
            body = gzip.compress(b"console.log('ok');\n" * 50)
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/stream":  # never-ending trickle
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            try:
                while True:
                    self.wfile.write(b".")
                    self.wfile.flush()
                    time.sleep(0.05)
            except Exception:
                pass
        elif self.path == "/big":  # exceeds max_bytes quickly
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            block = b"A" * 65536
            try:
                for _ in range(4000):  # ~256 MiB if unbounded
                    self.wfile.write(block)
            except Exception:
                pass
        elif self.path.startswith("/walled/"):  # WAF wall: every request is 403
            self.server.walled_hits += 1
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture()
def server():
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    srv.walled_hits = 0
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()


def _run(tmp_path: Path, base: str, config: str) -> list[dict]:
    out = tmp_path / "out"
    (out / "assets").mkdir(parents=True)
    manifest = out / "assets.json"
    manifest.write_text(
        json.dumps(
            [
                {"url": f"{base}/normal.js", "type": "javascript"},
                {"url": f"{base}/stream", "type": "page"},
                {"url": f"{base}/big", "type": "other"},
                {"url": f"{base}/missing", "type": "javascript"},
            ]
        )
    )
    cfg = tmp_path / "config.yaml"
    cfg.write_text(config)
    env = {
        "PATH": "/usr/bin:/bin",
        "OUTPUT_DIR": str(out),
        "CONFIG": str(cfg),
        "THREADS": "5",
        "LOG_FILE": "/dev/null",
    }
    # A generous outer timeout: the fix must make this finish in a few seconds.
    subprocess.run(
        ["bash", str(DOWNLOADER), str(manifest)],
        env=env,
        timeout=45,
        check=True,
        capture_output=True,
    )
    return json.loads(manifest.read_text())


def test_download_stage_terminates_and_bounds_each_asset(tmp_path, server):
    config = (
        "download:\n"
        "  timeout: 4\n"
        "  retries: 0\n"
        "  max_seconds: 3\n"
        "  max_bytes: 1048576\n"
    )
    start = time.monotonic()
    items = _run(tmp_path, server, config)
    elapsed = time.monotonic() - start

    # The whole stage must finish quickly rather than hang on the trickle endpoint.
    assert elapsed < 30, f"download stage took {elapsed:.1f}s — streaming ceiling not enforced"

    by_url = {i["url"].rsplit("/", 1)[-1]: i for i in items}

    # A real gzip-encoded JS asset downloads and is decoded correctly.
    normal = by_url["normal.js"]
    assert normal["status"] == "downloaded"
    assert normal["size_bytes"] == len(b"console.log('ok');\n" * 50)

    # The endless stream is aborted by the wall-clock ceiling, not hung on.
    stream = by_url["stream"]
    assert stream["status"] == "failed"
    assert "max_seconds" in stream["error"]

    # An oversized body is aborted by the size ceiling.
    big = by_url["big"]
    assert big["status"] == "failed"
    assert "max_bytes" in big["error"]

    # A 404 is recorded as a failure but does not abort the stage.
    assert by_url["missing"]["status"] == "failed"

    # No partial files are left behind for aborted downloads.
    leftover = list((tmp_path / "out" / "assets").glob("*.part"))
    assert not leftover, f"leftover partial files: {leftover}"


def _run_items(tmp_path: Path, items: list[dict], env_extra: dict | None = None) -> list[dict]:
    out = tmp_path / "out"
    (out / "assets").mkdir(parents=True, exist_ok=True)
    manifest = out / "assets.json"
    manifest.write_text(json.dumps(items))
    cfg = tmp_path / "config.yaml"
    cfg.write_text("download:\n  timeout: 4\n  retries: 0\n")
    env = {"PATH": "/usr/bin:/bin", "OUTPUT_DIR": str(out), "CONFIG": str(cfg),
           "THREADS": "1", "LOG_FILE": "/dev/null", **(env_extra or {})}
    subprocess.run(["bash", str(DOWNLOADER), str(manifest)], env=env, timeout=60,
                   check=True, capture_output=True)
    return json.loads(manifest.read_text())


def _walled(base: str, n: int) -> list[dict]:
    return [{"url": f"{base}/walled/{i}.js", "type": "javascript"} for i in range(n)]


def test_host_behind_a_403_wall_is_cut_off(tmp_path):
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    srv.walled_hits = 0
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        items = _run_items(tmp_path, _walled(base, 40) + [{"url": f"{base}/normal.js",
                                                           "type": "javascript"}],
                           {"JSINTEL_DOWNLOAD_BLOCK_AFTER": "5"})
        # Single worker: exactly 5 requests reach the wall, the other 35 are skipped.
        assert srv.walled_hits == 5
        statuses = [i["status"] for i in items[:40]]
        assert statuses.count("failed") == 5 and statuses.count("blocked") == 35
        assert "not requested" in items[39]["error"]
        assert items[40]["status"] == "blocked"     # same host: the breaker is per host
    finally:
        srv.shutdown()


def test_breaker_resets_on_success_and_can_be_disabled(tmp_path):
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    srv.walled_hits = 0
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    ok = {"url": f"{base}/normal.js", "type": "javascript"}
    try:
        # 4 walls, a success, 4 walls: never 5 in a row, so nothing is blocked.
        items = _run_items(tmp_path, _walled(base, 4) + [ok] + _walled(base, 4),
                           {"JSINTEL_DOWNLOAD_BLOCK_AFTER": "5"})
        assert "blocked" not in {i["status"] for i in items}
        srv.walled_hits = 0
        items = _run_items(tmp_path / "b", _walled(base, 30), {"JSINTEL_DOWNLOAD_BLOCK_AFTER": "0"})
        assert srv.walled_hits == 30 and {i["status"] for i in items} == {"failed"}
    finally:
        srv.shutdown()
