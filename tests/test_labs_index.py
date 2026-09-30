"""Tests for the labs-index discovery target (tests/lab/labs_index.py) and the
port-scanner robustness the wide-range scan depends on.
"""
from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

# labs_index lives under tests/lab; import it by path.
import importlib.util
import sys

_SPEC = importlib.util.spec_from_file_location(
    "labs_index", Path(__file__).resolve().parent / "lab" / "labs_index.py")
labs_index = importlib.util.module_from_spec(_SPEC)
sys.modules["labs_index"] = labs_index  # dataclass needs the module registered
_SPEC.loader.exec_module(labs_index)  # type: ignore[union-attr]

Lab = labs_index.Lab


# -- lab discovery / index building -------------------------------------------
def test_web_defaults_cover_the_web_labs():
    names = {l.name for l in labs_index.web_default_labs()}
    assert {"juice-shop", "dvwa", "webgoat", "wordpress", "django"} <= names


def test_registry_labs_parsed(tmp_path):
    reg = tmp_path / "ports.json"
    reg.write_text(json.dumps({"apps": {
        "anvil": {"port": 31000, "kind": "chain"},
        "dvdefi": {"port": None, "kind": "foundry-cli"},
    }}))
    labs = labs_index.registry_labs(reg)
    by = {l.name: l for l in labs}
    assert by["anvil"].url == "http://127.0.0.1:31000/"
    assert by["dvdefi"].url == ""  # CLI lab has no HTTP url


def test_registry_labs_missing_file_is_empty(tmp_path):
    assert labs_index.registry_labs(tmp_path / "nope.json") == []


def test_discover_merges_and_dedupes(tmp_path):
    reg = tmp_path / "ports.json"
    reg.write_text(json.dumps({"apps": {"anvil": {"port": 31000},
                                        "juice-shop": {"port": 3000}}}))  # dup name
    labs = labs_index.discover_labs(registry_path=reg, include_web=True)
    names = [l.name for l in labs]
    assert names.count("juice-shop") == 1  # web default wins, registry dup dropped
    assert "anvil" in names


def test_index_html_links_every_lab():
    labs = [Lab("a", "Alpha", "http://h/a", "web"),
            Lab("b", "Bravo", "", "foundry-cli"),
            Lab("c", "Charlie", "http://h/c", "chain")]
    html = labs_index.build_index_html(labs, "http://127.0.0.1:9999")
    for lab in labs:
        assert f"/lab/{lab.name}" in html          # every lab is linked at least once
        assert lab.title in html
    # the CLI lab (no url) is still present and flagged
    assert "no HTTP service" in html


def test_lab_stub_html_has_back_link_and_url():
    lab = Lab("x", "X lab", "http://127.0.0.1:1/x", "web")
    stub = labs_index.build_lab_stub_html(lab, "http://127.0.0.1:9999")
    assert "http://127.0.0.1:1/x" in stub and "back to index" in stub


# -- free-port picking --------------------------------------------------------
def test_pick_free_port_in_range_and_bindable():
    import random
    port = labs_index.pick_free_port(20000, 20500, "127.0.0.1", random.Random(1))
    assert 20000 <= port <= 20500
    # It must actually be bindable (i.e. was free).
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))


def test_pick_free_port_avoids_a_used_port():
    import random
    # Occupy a port, then ask for exactly that 1-wide range -> must fail to find one.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as busy:
        busy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        p = busy.getsockname()[1]
        with pytest.raises(RuntimeError):
            labs_index.pick_free_port(p, p, "127.0.0.1", random.Random(1), attempts=5)


# -- served index integration -------------------------------------------------
@pytest.fixture()
def index_server():
    labs = [Lab("juice-shop", "Juice Shop", "http://127.0.0.1:3000/", "web"),
            Lab("dvdefi", "DV DeFi", "", "foundry-cli"),
            Lab("anvil", "anvil", "http://127.0.0.1:31000/", "chain")]
    srv = labs_index.make_server("127.0.0.1", 0, labs)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}", labs
    finally:
        srv.shutdown()


def test_served_index_lists_every_lab_and_stubs_resolve(index_server):
    base, labs = index_server
    index = urllib.request.urlopen(base + "/", timeout=5).read().decode()
    for lab in labs:
        assert f"/lab/{lab.name}" in index
    # each stub resolves
    for lab in labs:
        body = urllib.request.urlopen(f"{base}/lab/{lab.name}", timeout=5).read().decode()
        assert lab.title in body
    # unknown lab -> 404
    with pytest.raises(urllib.error.HTTPError) as ei:
        urllib.request.urlopen(f"{base}/lab/does-not-exist", timeout=5)
    assert ei.value.code == 404


# -- port scanner robustness (the wide 80-10443 sweep depends on this) --------
def test_http_probe_survives_non_http_service():
    """A non-HTTP service (VNC answering 'RFB 003.008') must yield None, not crash.

    Regression: scanning 80-10443 hit the VNC server on 5901 and http.client raised
    BadStatusLine, which was uncaught and aborted the whole scan.
    """
    from modules import portscan

    class _RFBHandler:
        pass

    # A tiny raw TCP server that sends a VNC banner and closes.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        try:
            conn, _ = srv.accept()
            conn.recv(1024)
            conn.sendall(b"RFB 003.008\n")
            conn.close()
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    try:
        # Must return None (unrecognized), not raise.
        assert portscan._http_probe("127.0.0.1", port, timeout=3) is None
    finally:
        srv.close()


def test_http_probe_detects_a_real_http_service(index_server):
    from modules import portscan
    base, _ = index_server
    port = int(base.rsplit(":", 1)[1])
    rec = portscan._http_probe("127.0.0.1", port, timeout=5)
    assert rec and rec["port"] == port and rec["status"] == 200
