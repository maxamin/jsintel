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
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture()
def server():
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
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
