"""Webshot stage: perceptual hashing, visual clustering, gallery, and run wiring."""
import json
import shutil
from pathlib import Path

import pytest

from modules import webshot


def test_hamming_distance():
    assert webshot.hamming("0000000000000000", "0000000000000000") == 0
    assert webshot.hamming("0000000000000000", "0000000000000001") == 1
    assert webshot.hamming("ffffffffffffffff", "0000000000000000") == 64
    assert webshot.hamming("", "abc") == 64  # missing hash -> far


def test_cluster_by_phash_groups_similar_and_separates_different():
    records = [
        {"url": "a", "phash": "0000000000000000"},
        {"url": "b", "phash": "0000000000000001"},   # 1 bit from a -> same cluster
        {"url": "c", "phash": "ffffffffffffffff"},   # far -> own cluster
        {"url": "d", "phash": ""},                    # no hash -> own cluster
    ]
    clusters = webshot.cluster_by_phash(records, threshold=10)
    assert records[0]["cluster"] == records[1]["cluster"]
    assert records[2]["cluster"] != records[0]["cluster"]
    assert records[3]["cluster"] not in (records[0]["cluster"], records[2]["cluster"])
    assert clusters == 3


def _make_png(path: Path, color) -> None:
    from PIL import Image
    Image.new("RGB", (64, 48), color).save(path)


def _pattern(path: Path, kind: str) -> None:
    # Structured (high-frequency) images so dHash has signal, like a real page.
    from PIL import Image
    w, h = 90, 80
    if kind == "checker":
        data = [255 if ((x // 6) + (y // 6)) % 2 else 0 for y in range(h) for x in range(w)]
    else:  # vertical stripes -> a clearly different dHash
        data = [255 if (x // 4) % 2 else 0 for y in range(h) for x in range(w)]
    img = Image.new("L", (w, h)); img.putdata(data); img.save(path)


def test_perceptual_hash_stable_and_discriminating(tmp_path: Path):
    a = tmp_path / "a.png"; b = tmp_path / "b.png"; c = tmp_path / "c.png"
    _pattern(a, "checker"); _pattern(b, "checker"); _pattern(c, "stripes")
    ha, hb, hc = webshot.perceptual_hash(a), webshot.perceptual_hash(b), webshot.perceptual_hash(c)
    assert ha and hc
    assert webshot.hamming(ha, hb) == 0       # identical look -> identical hash
    assert webshot.hamming(ha, hc) >= 8       # different look


def test_run_with_fake_renderer_builds_gallery_and_clusters(tmp_path: Path):
    # Two services share one look; a third differs -> 2 clusters. No real browser.
    (tmp_path / "assets").mkdir()
    (tmp_path / "reports").mkdir()
    services = tmp_path / "assets" / "services.txt"
    services.write_text("https://a.test/\nhttps://b.test/\nhttps://c.test:8443/\n")
    # ports.json metadata + a high finding on a.test for the flag.
    (tmp_path / "reports" / "ports.json").write_text(json.dumps([
        {"url": "https://a.test/", "status": 200, "title": "Login", "server": "nginx"},
        {"url": "https://c.test:8443/", "status": 200, "title": "Admin", "server": "kestrel"},
    ]))
    (tmp_path / "reports" / "findings.json").write_text(json.dumps([
        {"asset_url": "https://a.test/app.js", "severity": "critical", "finding_type": "x", "value": "y"},
    ]))

    from PIL import Image
    def fake_render(url, out_path):
        # a.test and b.test share a checkerboard look; c.test gets stripes.
        w, h = 90, 80
        if "c.test" in url:
            data = [255 if (x // 4) % 2 else 0 for y in range(h) for x in range(w)]
        else:
            data = [255 if ((x // 6) + (y // 6)) % 2 else 0 for y in range(h) for x in range(w)]
        img = Image.new("L", (w, h)); img.putdata(data); img.convert("RGB").save(out_path)
        return True

    summary = webshot.run(tmp_path, services, renderer=fake_render)
    assert summary["captured"] == 3
    assert summary["clusters"] == 2
    assert summary["engine"] == "injected"

    recs = json.loads((tmp_path / "reports" / "screenshots.json").read_text())
    by_url = {r["url"]: r for r in recs}
    assert by_url["https://a.test/"]["cluster"] == by_url["https://b.test/"]["cluster"]
    assert by_url["https://c.test:8443/"]["cluster"] != by_url["https://a.test/"]["cluster"]
    # metadata + finding cross-reference carried through
    assert by_url["https://a.test/"]["title"] == "Login"
    assert by_url["https://a.test/"]["flagged"] is True
    assert by_url["https://c.test:8443/"]["flagged"] is False
    # gallery written and references the screenshots
    html = (tmp_path / "reports" / "screenshots.html").read_text()
    assert "JSIntel Screenshots" in html
    assert "a.test" in html and "high-severity finding" in html


def test_run_no_services_is_noop(tmp_path: Path):
    (tmp_path / "assets").mkdir(); (tmp_path / "reports").mkdir()
    services = tmp_path / "assets" / "services.txt"
    services.write_text("")
    summary = webshot.run(tmp_path, services)
    assert summary == {"services": 0, "captured": 0, "clusters": 0, "engine": "none"}


@pytest.mark.skipif(not webshot.find_chromium(), reason="no chromium/chrome installed")
def test_real_chromium_renders_a_local_page(tmp_path: Path):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            b = b"<html><head><title>Real</title></head><body>hello</body></html>"
            self.send_response(200); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
        def log_message(self, *a): pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        host, port = srv.server_address
        out = tmp_path / "shot.png"
        ok = webshot.render_screenshot(f"http://{host}:{port}/", out,
                                       chromium=webshot.find_chromium(), timeout=40)
    finally:
        srv.shutdown()
    assert ok and out.is_file() and out.stat().st_size > 0
    assert webshot.perceptual_hash(out)  # a real PNG that hashes
