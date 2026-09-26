"""Port scanner: parsing, host normalisation, and live web-service confirmation.

The live parts use an in-process HTTP server bound to loopback on an ephemeral
port -- no third party is ever contacted -- so the confirm/probe path is exercised
end to end while staying entirely local.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from modules import portscan


def test_parse_ports_ranges_and_dedup():
    assert portscan.parse_ports("80,443,8000-8002,443") == (80, 443, 8000, 8001, 8002)
    assert portscan.parse_ports("bad, 8080 , 90-88") == (88, 89, 90, 8080)
    assert portscan.parse_ports("70000,0,-5") == ()


def test_read_hosts_strips_scheme_port_and_dupes(tmp_path):
    p = tmp_path / "hosts.txt"
    p.write_text(
        "\n".join(
            [
                "https://a.example.test:8443/path",
                "a.example.test",  # dupe of the above after normalisation
                "# comment",
                "",
                "user@b.example.test:80",
                "C.EXAMPLE.TEST",
            ]
        )
    )
    assert portscan._read_hosts(p) == ["a.example.test", "b.example.test", "c.example.test"]


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib signature
        body = b"<html><head><title>  Admin  Panel  </title></head><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Server", "unittest/1.0")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        pass


@pytest.fixture()
def local_http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address  # (host, port)
    finally:
        server.shutdown()
        server.server_close()


def test_http_probe_confirms_service_and_extracts_title(local_http_server):
    host, port = local_http_server
    record = portscan._http_probe(host, port, timeout=5.0)
    assert record is not None
    assert record["status"] == 200
    assert record["scheme"] == "http"
    assert record["port"] == port
    assert record["server"]  # a Server header was captured
    assert record["title"] == "Admin Panel"  # whitespace collapsed


def test_http_probe_on_closed_port_returns_none():
    # Port 1 on loopback is not listening; confirm we get no false positive.
    assert portscan._http_probe("127.0.0.1", 1, timeout=1.0) is None


def test_confirm_web_services_orders_and_filters(local_http_server):
    host, port = local_http_server
    services = portscan.confirm_web_services(
        {host: {port, 1}}, timeout=3.0, workers=4
    )
    # Only the listening port is confirmed; the dead one is dropped.
    assert [s["port"] for s in services] == [port]


def test_python_scan_detects_open_port(local_http_server):
    host, port = local_http_server
    result = portscan._scan_python([host], (port, 1), timeout=1.0, workers=4)
    assert port in result[host]
    assert 1 not in result[host]


def test_run_writes_services_and_ports_json(tmp_path, local_http_server):
    host, port = local_http_server
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text(f"{host}\n")
    out = tmp_path / "out"
    (out / "assets").mkdir(parents=True)
    (out / "reports").mkdir(parents=True)
    summary = portscan.run(
        out, hosts_file, ports=(port,),
        connect_timeout=1.0, http_timeout=3.0, workers=4, prefer_tools=False,
    )
    assert summary["services"] == 1
    services_txt = (out / "assets" / "services.txt").read_text().strip()
    assert services_txt == f"http://{host}:{port}/"
    ports_json = json.loads((out / "reports" / "ports.json").read_text())
    assert ports_json[0]["port"] == port
    assert ports_json[0]["title"] == "Admin Panel"


def test_run_with_no_hosts_writes_empty_outputs(tmp_path):
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text("# only comments\n\n")
    out = tmp_path / "out"
    summary = portscan.run(out, hosts_file, ports=(80,), prefer_tools=False)
    assert summary["services"] == 0
    assert (out / "assets" / "services.txt").read_text() == ""
    assert json.loads((out / "reports" / "ports.json").read_text()) == []


def test_parse_nmap_grepable_by_ip():
    text = (
        "# Nmap done\n"
        "Host: 104.18.5.7 (104-18-5-7.cloudflare.com)\tStatus: Up\n"
        "Host: 104.18.5.7 (104-18-5-7.cloudflare.com)\tPorts: 443/open/tcp//https///, 8443/open/tcp//https-alt///\n"
        "Host: 10.0.0.9 ()\tPorts: 80/open/tcp//http///\n"
    )
    by_ip = portscan._parse_nmap_grepable(text)
    assert by_ip == {"104.18.5.7": {443, 8443}, "10.0.0.9": {80}}


def test_nmap_scan_fans_shared_ip_out_to_all_hostnames(monkeypatch):
    # Regression for the gala.com run: many hostnames share one CDN IP whose PTR
    # is a cloudflare name; results must fan back out to EVERY queried hostname.
    hosts = ["a.example.test", "b.example.test", "dead.example.test"]

    def fake_resolve(_hosts):
        ip_to_hosts = {"1.2.3.4": {"a.example.test", "b.example.test"}}
        host_to_ips = {"a.example.test": {"1.2.3.4"}, "b.example.test": {"1.2.3.4"}}
        return ip_to_hosts, host_to_ips  # dead.example.test did not resolve

    class FakeProc:
        stdout = "Host: 1.2.3.4 (cdn.example.net)\tPorts: 443/open/tcp//https///\n"

    monkeypatch.setattr(portscan, "_resolve_hosts", fake_resolve)
    monkeypatch.setattr(portscan.subprocess, "run", lambda *a, **k: FakeProc())

    result = portscan._scan_nmap(hosts, (443,), timeout=5, hosts_file=None)
    assert result["a.example.test"] == {443}
    assert result["b.example.test"] == {443}  # fanned out despite shared IP
    assert result["dead.example.test"] == set()  # unresolved -> no ports


def test_mark_port_mirrors_collapses_cdn_echoes():
    # A host answers :443 with a page, and echoes the identical page on Cloudflare's
    # alternate ports; those must be flagged as mirrors, not counted as new services.
    services = [
        {"host": "a.test", "port": 443, "status": 200, "sig": "abc", "url": "https://a.test:443/", "mirror_of": ""},
        {"host": "a.test", "port": 8443, "status": 200, "sig": "abc", "url": "https://a.test:8443/", "mirror_of": ""},
        {"host": "a.test", "port": 2083, "status": 200, "sig": "abc", "url": "https://a.test:2083/", "mirror_of": ""},
        {"host": "a.test", "port": 9000, "status": 200, "sig": "DIFF", "url": "http://a.test:9000/", "mirror_of": ""},
    ]
    marked = portscan.mark_port_mirrors(services)
    assert marked == 2  # 8443 and 2083 mirror :443
    mirrored = {s["port"] for s in services if s["mirror_of"]}
    assert mirrored == {8443, 2083}
    # The genuinely different service on :9000 is NOT a mirror.
    assert next(s for s in services if s["port"] == 9000)["mirror_of"] == ""


def test_mark_port_mirrors_no_canonical_keeps_all():
    # No :80/:443 response -> nothing to compare against -> nothing collapsed.
    services = [
        {"host": "b.test", "port": 8080, "status": 200, "sig": "x", "url": "http://b.test:8080/", "mirror_of": ""},
        {"host": "b.test", "port": 8443, "status": 200, "sig": "x", "url": "https://b.test:8443/", "mirror_of": ""},
    ]
    assert portscan.mark_port_mirrors(services) == 0
    assert all(not s["mirror_of"] for s in services)


def test_detect_cdn_from_markers():
    assert portscan._detect_cdn({"CF-RAY": "abc"}, "", "") == "cloudflare"
    assert portscan._detect_cdn({}, "cloudflare", "") == "cloudflare"
    assert portscan._detect_cdn({}, "", "Attention Required! | Cloudflare") == "cloudflare"
    assert portscan._detect_cdn({"X-Amz-Cf-Id": "z"}, "", "") == "cloudfront"
    assert portscan._detect_cdn({}, "nginx", "Real App") == ""


def test_cdn_host_altports_collapsed_even_when_body_differs():
    # A Cloudflare-fronted host serves the site on :443 but a CF *block page* (403,
    # different body) on its alt-ports. Those alt-ports are still not new services.
    services = [
        {"host": "n.test", "port": 443, "status": 200, "sig": "site", "cdn": "cloudflare", "url": "https://n.test:443/", "mirror_of": ""},
        {"host": "n.test", "port": 8443, "status": 403, "sig": "block", "cdn": "cloudflare", "url": "https://n.test:8443/", "mirror_of": ""},
        {"host": "n.test", "port": 2083, "status": 403, "sig": "block", "cdn": "cloudflare", "url": "https://n.test:2083/", "mirror_of": ""},
    ]
    marked = portscan.mark_port_mirrors(services)
    assert marked == 2
    assert all(s["mirror_of"] for s in services if s["port"] not in (80, 443))
