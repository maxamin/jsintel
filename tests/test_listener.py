"""Capture listener daemon: classification, ingest (native/HAR/WS), full-pipeline
processing of captured traffic, and a live HTTP round-trip."""
import json
import socket
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from modules import listener
from modules.listener import classify, CaptureStore, SiteRegistry, site_key, flow_key

CFG = Path("config/config.yaml")


def _http(url, ct="application/javascript", body="var x=1;"):
    return {"type": "http", "url": url, "status": 200,
            "response_headers": {"content-type": ct}, "response_body": body}


def test_classify_mime_then_url():
    assert classify("http://h/x", "application/javascript") == "javascript"
    assert classify("http://h/route", "text/html") == "page"
    assert classify("http://h/spec", "application/json") == "configuration"
    assert classify("http://h/a.js", None) == "javascript"
    assert classify("http://h/a.map", None) == "source_map"
    assert classify("http://h/login.php", None) == "page"
    assert classify("http://h/vulns/", None) == "page"          # extensionless route
    assert classify("http://h/x.bin", "application/octet-stream") == "other"


@pytest.mark.parametrize("url,mime,expected", [
    # --- strong code extensions WIN over a mislabeled / generic content-type ---
    ("http://h/app.js", "text/html", "javascript"),            # JS mislabeled as HTML
    ("http://h/app.js", "text/plain", "javascript"),
    ("http://h/app.js", "application/octet-stream", "javascript"),
    ("http://h/app.js", "", "javascript"),
    ("http://h/app.js", None, "javascript"),
    ("http://h/chunk.mjs", "application/octet-stream", "javascript"),
    ("http://h/app.min.js", "text/html", "javascript"),
    ("http://h/bundle.js.map", "application/json", "source_map"),  # maps are JSON but want source_map
    ("http://h/app.map", "text/html", "source_map"),
    ("http://h/mod.wasm", "text/html", "webassembly"),
    # --- versioned / cache-busted URLs: query & fragment are stripped first ---
    ("http://h/app.js?v=1.2.3", None, "javascript"),
    ("http://h/app.js#frag", None, "javascript"),
    ("http://h/a.js?cb=1#x", "text/html", "javascript"),
    # --- content-type is authoritative when the URL has no telling extension ---
    ("http://h/route", "text/html", "page"),
    ("http://h/gql", "application/json", "configuration"),
    ("http://h/x", "application/javascript; charset=utf-8", "javascript"),   # charset param
    ("http://h/x", "Application/JavaScript", "javascript"),                  # case-insensitive
    ("http://h/x", "text/javascript;charset=UTF-8", "javascript"),
    ("http://h/api/v1/users", "application/vnd.api+json", "configuration"),  # +json suffix
    ("http://h/data", "application/ld+json", "configuration"),
    ("http://h/spec", "text/json", "configuration"),
    ("http://h/mod", "application/wasm", "webassembly"),
    # --- web-app manifest stays 'manifest' even when served as JSON ---
    ("http://h/manifest.json", "application/json", "manifest"),
    ("http://h/site.webmanifest", "application/manifest+json", "manifest"),
    ("http://h/manifest.webmanifest", None, "manifest"),
    # --- workers, page extensions, extensionless routes via URL fallback ---
    ("http://h/service-worker.js", None, "javascript"),   # .js wins first (still analyzed as JS)
    ("http://h/sw.worker", "application/octet-stream", "worker"),
    ("http://h/login.php", None, "page"),
    ("http://h/admin.aspx", "text/plain", "page"),         # generic MIME -> URL fallback
    ("http://h/vulns/", None, "page"),                     # trailing-slash route
    ("http://h/dashboard", None, "page"),                  # extensionless route
    ("http://h/config.json", None, "configuration"),
    # --- misleading paths must NOT be mistaken for code files ---
    ("http://h/track.js/pixel", "text/html", "page"),      # '.js' is a directory, not the file
    ("http://h/redirect?to=/app.js", "text/html", "page"), # '.js' only in the query
    ("http://h/image.png", "application/octet-stream", "other"),
    ("http://h/x.bin", "application/octet-stream", "other"),
])
def test_classify_aggressive(url, mime, expected):
    assert classify(url, mime) == expected


def test_add_http_writes_asset_and_manifest(tmp_path):
    s = CaptureStore(tmp_path, CFG)
    assert s.add_http({"url": "http://h/app.js", "status": 200,
                       "response_headers": {"content-type": "application/javascript"},
                       "response_body": "var x=1;"})
    e = s._assets["http://h/app.js"]
    assert e["type"] == "javascript" and Path(e["local_path"]).read_text() == "var x=1;"
    # re-capture same url updates in place (no duplicate asset)
    s.add_http({"url": "http://h/app.js", "status": 200,
                "response_headers": {"content-type": "application/javascript"}, "response_body": "var y=2;"})
    assert len(s._assets) == 1 and Path(e["local_path"]).read_text() == "var y=2;"


def test_har_and_list_and_ws_dispatch(tmp_path):
    s = CaptureStore(tmp_path, CFG)
    har = {"log": {"entries": [{"request": {"url": "http://h/a.js", "method": "GET"},
                                "response": {"status": 200, "headers": [{"name": "Content-Type", "value": "application/javascript"}],
                                             "content": {"text": "fetch('/api/v1/x')", "mimeType": "application/javascript"}}}]}}
    assert s.ingest_any(har) == 1
    assert s.ingest_any([{"type": "http", "url": "http://h/b.js", "status": 200,
                          "response_headers": {"content-type": "application/javascript"}, "response_body": "1"}]) == 1
    assert s.ingest_any({"type": "ws", "url": "wss://h/s", "opcode": "text", "payload": "hi /api/v2/y"}) == 1
    assert len(s._assets) == 2 and len(s._ws) == 1


def test_process_full_pipeline_on_captures(tmp_path):
    s = CaptureStore(tmp_path, CFG)
    s.add_http({"url": "http://cap.test/main.js", "status": 200,
                "response_headers": {"content-type": "application/javascript", "server": "nginx/1.2.3"},
                "response_body": 'const AWS="AKIAIOSFODNN7EXAMPLE"; fetch("/api/v1/users"); eval(z);'})
    s.add_http({"url": "http://cap.test/login.php", "status": 200,
                "response_headers": {"content-type": "text/html"},
                "response_body": '<a href="/admin/">a</a><form action="/login" method="post"><input name="u"></form>'})
    s.add_ws({"url": "wss://cap.test/s", "opcode": "text", "payload": "path=/api/v2/secret"})
    out = s.process()
    findings = json.loads((tmp_path / "reports/findings.json").read_text())
    types = {f["finding_type"] for f in findings}
    assert "hardcoded_secret" in types and "dangerous_eval" in types
    eps = {e["endpoint"] for e in json.loads((tmp_path / "reports/endpoints.json").read_text())}
    assert "/api/v1/users" in eps and "/api/v2/secret" in eps   # JS + WS-frame mining
    assert out["triage"]["hosts_ranked"] >= 1
    assert (tmp_path / "reports/security.json").exists()         # passive header analysis ran


def test_mines_urls_and_secrets_from_headers_and_url(tmp_path):
    s = CaptureStore(tmp_path, CFG)
    # A capture whose SECRETS/URLS live in the request URL + headers, NOT the body:
    #  - an AWS key in a request header
    #  - a URL-encoded redirect target in a query param (?next=https%3A%2F%2F…/admin)
    #  - an API path in another query param
    #  - a redirect URL in the response Location header
    s.add_http({
        "type": "http",
        "url": "http://cap.test/callback?next=https%3A%2F%2Fapp.internal%2Fadmin%2Fconfig&path=%2Fapi%2Fv1%2Fkeys",
        "method": "GET", "status": 302,
        "request_headers": {"Authorization": "Bearer AKIAIOSFODNN7EXAMPLE",
                            "X-Api-Key": "AKIAIOSFODNN7EXAMPLE"},
        "response_headers": {"content-type": "text/html",
                             "Location": "https://oauth.provider.test/authorize?client_id=abc"},
        "response_body": "<html>redirecting</html>",   # body has nothing useful
    })
    s.process()
    eps = {e["endpoint"] for e in json.loads((tmp_path / "reports/endpoints.json").read_text())}
    urls = {u["url"] for u in json.loads((tmp_path / "reports/urls.json").read_text())}
    findings = {f["finding_type"] for f in json.loads((tmp_path / "reports/findings.json").read_text())}
    # URL-encoded values from the URL were decoded and mined:
    assert any("/admin/config" in e for e in eps) or any("app.internal" in u for u in urls)
    assert any("/api/v1/keys" in e for e in eps)
    # the redirect URL from the response header was mined:
    assert any("oauth.provider.test" in u for u in urls)
    # the AWS key sitting in request headers was flagged as a secret:
    assert "hardcoded_secret" in findings


def test_process_harvests_openapi_spec_endpoints(tmp_path):
    s = CaptureStore(tmp_path, CFG)
    spec = json.dumps({"openapi": "3.0.0", "paths": {"/users/v1": {}, "/users/v1/_debug": {}}})
    s.add_http({"url": "http://api.test/openapi.json", "status": 200,
                "response_headers": {"content-type": "application/json"}, "response_body": spec})
    s.process()
    # Harvested spec paths land in api_spec_endpoints.json and are ingested into the
    # DB endpoints table (not the extractor's endpoints.json).
    harvested = {e["endpoint"] for e in json.loads((tmp_path / "reports/api_spec_endpoints.json").read_text())}
    assert "/users/v1" in harvested and "/users/v1/_debug" in harvested
    import sqlite3
    con = sqlite3.connect(tmp_path / "database/recon.db")
    db_eps = {r[0] for r in con.execute("SELECT endpoint FROM endpoints")}
    con.close()
    assert "/users/v1/_debug" in db_eps                          # queryable in the DB


def test_site_key_groups_uris_and_subdomains():
    # Every URI/subdomain of one target collapses to its registered domain…
    assert site_key("https://a.shop.example.com/x.js") == "example.com"
    assert site_key("http://api.example.com/v1/users?q=1") == "example.com"
    assert site_key("https://example.com/") == "example.com"
    # …multi-label public suffixes group by the real registered domain…
    assert site_key("https://www.foo.co.uk/a") == "foo.co.uk"
    # …and IPs / single-label hosts pass through untouched.
    assert site_key("http://127.0.0.1:8080/x") == "127.0.0.1"
    assert site_key("http://localhost/x") == "localhost"


def test_registry_one_store_and_dir_per_site(tmp_path):
    reg = SiteRegistry(tmp_path, CFG, debounce=99)  # debounce high: no auto-scan during test
    try:
        # Many URIs across subdomains of ONE site + a repeated XHR to the same endpoint.
        assert reg.ingest_any([
            _http("http://app.acme.test/a.js"),
            _http("http://cdn.acme.test/b.js"),
            _http("http://acme.test/api/users", ct="application/json", body='{"a":1}'),
            _http("http://acme.test/api/users", ct="application/json", body='{"a":2}'),  # dup URI
            _http("http://other.test/c.js"),
        ]) == 5
        # -> exactly TWO sites, one CaptureStore each (not one per URI, not per XHR).
        assert set(reg._stores) == {"acme.test", "other.test"}
        assert len(reg._stores["acme.test"]._assets) == 3   # a.js, b.js, api/users (deduped)
        # -> one directory per site under <output>/sites/, nothing per-URL.
        site_dirs = {p.name for p in (tmp_path / "sites").iterdir()}
        assert site_dirs == {"acme.test", "other.test"}
    finally:
        reg.shutdown()


def test_registry_host_grouping_separates_subdomains(tmp_path):
    reg = SiteRegistry(tmp_path, CFG, group="host", debounce=99)
    try:
        reg.ingest_any([_http("http://a.acme.test/x.js"), _http("http://b.acme.test/y.js")])
        assert set(reg._stores) == {"a.acme.test", "b.acme.test"}  # per-host, not collapsed
    finally:
        reg.shutdown()


def test_registry_debounced_background_scan_is_coalesced(tmp_path):
    reg = SiteRegistry(tmp_path, CFG, debounce=0.3, max_concurrent=2)
    try:
        # A burst of captures to one site while it stays "hot" must NOT spawn many scans.
        for i in range(8):
            reg.ingest_any(_http(f"http://burst.test/f{i}.js", body=f"var x={i};"))
            time.sleep(0.05)
        st = reg._stores["burst.test"]
        assert st.dirty and st.last_result is None       # nothing scanned yet (still hot)
        # Go quiet; the debounce loop should fire exactly one scan for the whole burst.
        deadline = time.time() + 10
        while time.time() < deadline and st.last_result is None:
            time.sleep(0.1)
        assert st.last_result is not None                # one coalesced scan produced a result
        assert st.last_result["assets"] == 8 and not st.dirty
        assert (st.output / "reports/triage.json").exists()
    finally:
        reg.shutdown()


def test_registry_flush_all_and_report_routing(tmp_path):
    reg = SiteRegistry(tmp_path, CFG, debounce=99)
    try:
        reg.ingest_any(_http("http://x.test/m.js", body='fetch("/api/v1/z");eval(q);'))
        reg.ingest_any(_http("http://y.test/n.js"))
        out = reg.flush_all()
        assert out["sites"] == 2 and out["results"]["x.test"]["assets"] == 1
        # per-site status + per-site report routing
        stt = reg.status()
        assert stt["sites"] == 2 and stt["per_site"]["x.test"]["site"] == "x.test"
        assert reg.report_path("x.test", "triage.json") is not None
        assert reg.report_path("x.test", "../../../etc/passwd") is None  # name-only, no traversal
        assert reg.report_path("nope.test", "triage.json") is None
    finally:
        reg.shutdown()


def test_live_registry_roundtrip_routes_by_site(tmp_path):
    port = _free_port()
    reg = SiteRegistry(tmp_path, CFG, debounce=99)
    from http.server import ThreadingHTTPServer
    httpd = ThreadingHTTPServer(("127.0.0.1", port), listener._make_handler(reg, None))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        time.sleep(0.2)
        for u in ("http://a.site.test/x.js", "http://b.site.test/y.js", "http://lone.test/z.js"):
            data = json.dumps(_http(u)).encode()
            req = urllib.request.Request(f"http://127.0.0.1:{port}/ingest", data=data,
                                         headers={"Content-Type": "application/json"}, method="POST")
            assert json.loads(urllib.request.urlopen(req, timeout=5).read())["ingested"] == 1
        st = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/status", timeout=5).read())
        assert st["sites"] == 2 and set(st["per_site"]) == {"site.test", "lone.test"}
    finally:
        httpd.shutdown()
        reg.shutdown()


def test_optin_fuzz_runs_scoped_to_captured_hosts_dryrun(tmp_path):
    # --fuzz is opt-in and active; in dry-run it plans candidates (no live requests) so
    # this stays hermetic. Verify it runs, is scoped to the captured host, and its
    # summary is folded into the pipeline result.
    s = CaptureStore(tmp_path, CFG)
    s.fuzz = True
    s.fuzz_args = ["--dry-run", "--offline"]
    s.add_http({"url": "http://cap.test/app.js", "status": 200,
                "response_headers": {"content-type": "application/javascript"},
                "response_body": 'fetch("/api/v1/users"); fetch("/admin/panel");'})
    out = s.process()
    assert out["fuzz"]["ran"] is True
    assert out["fuzz"]["scope"] == ["cap.test"]            # scope = captured host only
    assert (tmp_path / "reports/fuzz.json").exists()       # candidates were planned
    # planned candidates must stay within the captured host (scope never widens)
    fuzz = json.loads((tmp_path / "reports/fuzz.json").read_text())
    urls = [r.get("url", "") for r in (fuzz if isinstance(fuzz, list) else fuzz.get("results", []))]
    assert urls and all("cap.test" in u for u in urls)


def test_fuzz_off_by_default(tmp_path):
    s = CaptureStore(tmp_path, CFG)   # default: passive, no fuzzing
    s.add_http({"url": "http://cap.test/app.js", "status": 200,
                "response_headers": {"content-type": "application/javascript"}, "response_body": "1"})
    out = s.process()
    assert "fuzz" not in out
    assert not (tmp_path / "reports/fuzz.json").exists()


def test_flow_key_semantics():
    base = flow_key("GET", "http://h/a?b=1&a=2", "", {})
    # query order and volatile headers do NOT change the key
    assert base == flow_key("GET", "http://h/a?a=2&b=1", "", {"user-agent": "x", "date": "now"})
    # method, body, and auth headers DO change it
    assert base != flow_key("POST", "http://h/a?b=1&a=2", "", {})
    assert base != flow_key("GET", "http://h/a?b=1&a=2", "body", {})
    assert base != flow_key("GET", "http://h/a?b=1&a=2", "", {"authorization": "Bearer z"})
    assert base != flow_key("GET", "http://h/a?b=1&a=2", "", {"cookie": "s=1"})


def _agg_store(tmp_path):
    s = CaptureStore(tmp_path, CFG)
    s.aggressive = True
    s.chromium = ""            # hermetic: no screenshots
    return s


def test_aggressive_records_and_dedupes(tmp_path):
    s = _agg_store(tmp_path)
    cap = {"url": "http://cap.test/api", "method": "GET", "status": 200,
           "response_headers": {"content-type": "application/json"}, "response_body": '{"x":1}'}
    assert s.add_http(cap)
    assert s.add_http(dict(cap))          # identical flow + identical response -> deduped
    rec = s._recorder
    assert rec.stats["flows"] == 1 and rec.stats["duplicates"] == 1
    flow_dirs = list((tmp_path / "assets/flows/cap.test/api/GET").glob("*"))
    assert len(flow_dirs) == 1            # ONE flow dir, not one per capture
    d = flow_dirs[0]
    assert list(d.glob("request_*.txt")) and list(d.glob("response_*.raw"))
    assert (d / "meta.json").is_file()
    assert not (tmp_path / "assets/flows/anomaly.txt").exists()   # no anomaly yet


def test_aggressive_flags_response_change_as_anomaly(tmp_path):
    s = _agg_store(tmp_path)
    base = {"url": "http://cap.test/api", "method": "GET", "status": 200,
            "response_headers": {"content-type": "application/json"}}
    s.add_http({**base, "response_body": '{"x":1}'})
    s.add_http({**base, "response_body": '{"x":2}'})   # SAME flow, DIFFERENT response
    rec = s._recorder
    assert rec.stats["anomalies"] == 1
    d = next((tmp_path / "assets/flows/cap.test/api/GET").glob("*"))
    assert len(list(d.glob("response_*.raw"))) == 2     # both responses kept
    anomaly = (tmp_path / "assets/flows/anomaly.txt").read_text().strip().splitlines()
    assert len(anomaly) == 1 and "cap.test/api/GET" in anomaly[0] and "http://cap.test/api" in anomaly[0]


def test_aggressive_distinct_flows_get_separate_dirs(tmp_path):
    s = _agg_store(tmp_path)
    u = "http://cap.test/api"
    s.add_http({"url": u, "method": "GET", "status": 200, "response_headers": {}, "response_body": "a"})
    s.add_http({"url": u, "method": "POST", "status": 200, "response_headers": {}, "response_body": "a",
                "request_body": "payload"})
    s.add_http({"url": u, "method": "GET", "status": 200, "response_headers": {}, "response_body": "a",
                "request_headers": {"Authorization": "Bearer z"}})
    assert s._recorder.stats["flows"] == 3               # method / body / auth-header each distinct
    assert (tmp_path / "assets/flows/cap.test/api/GET").is_dir()
    assert (tmp_path / "assets/flows/cap.test/api/POST").is_dir()


def test_anomaly_normalization_suppresses_token_noise(tmp_path):
    # Two responses identical except a rotating anti-CSRF token must NOT be an anomaly
    # (default normalization); a genuinely different body MUST be.
    s = _agg_store(tmp_path)      # normalize on by default
    page = "<html><input type='hidden' name='user_token' value='%s' /><p>hi</p></html>"
    base = {"url": "http://cap.test/login", "method": "GET", "status": 200,
            "response_headers": {"content-type": "text/html"}}
    s.add_http({**base, "response_body": page % "aaaaaaaaaaaaaaaa"})
    s.add_http({**base, "response_body": page % "bbbbbbbbbbbbbbbb"})   # only token differs
    assert s._recorder.stats["anomalies"] == 0                          # token noise ignored
    assert not (tmp_path / "assets/flows/anomaly.txt").exists()
    s.add_http({**base, "response_body": "<html><p>REALLY different</p></html>"})
    assert s._recorder.stats["anomalies"] == 1                          # genuine change flagged


def test_anomaly_raw_mode_flags_token_change(tmp_path):
    # With normalization disabled, the same token rotation IS a (raw-byte) anomaly.
    s = _agg_store(tmp_path)
    s.anomaly_normalize = False
    page = "<html><input name='user_token' value='%s' /></html>"
    base = {"url": "http://cap.test/login", "method": "GET", "status": 200,
            "response_headers": {"content-type": "text/html"}}
    s.add_http({**base, "response_body": page % "aaaa"})
    s.add_http({**base, "response_body": page % "bbbb"})
    assert s._recorder.stats["anomalies"] == 1


def test_ledger_persists_across_restart(tmp_path):
    from modules.listener import FlowRecorder
    # First "run": record one flow + response.
    r1 = FlowRecorder(tmp_path / "assets")
    r1.record("GET", "http://cap.test/x", {}, "", 200, {}, "<html>v1</html>", "page")
    assert r1.stats["flows"] == 1
    assert (tmp_path / "assets/flows/ledger.json").is_file()
    # Second "run": a fresh recorder on the same dir rehydrates the ledger.
    r2 = FlowRecorder(tmp_path / "assets")
    assert r2.stats["rehydrated"] == 1
    # Same flow + same response -> deduped (remembered across the restart), not a new flow.
    assert r2.record("GET", "http://cap.test/x", {}, "", 200, {}, "<html>v1</html>", "page") is None
    assert r2.stats["flows"] == 0 and r2.stats["duplicates"] == 1
    # A CHANGED response for that same flow -> anomaly detected against the persisted hash.
    res = r2.record("GET", "http://cap.test/x", {}, "", 200, {}, "<html>v2 CHANGED</html>", "page")
    assert res and res["anomaly"] is True and r2.stats["anomalies"] == 1
    assert "cap.test/x" in (tmp_path / "assets/flows/anomaly.txt").read_text()


def test_anomaly_new_secret_is_high_severity(tmp_path):
    from modules.listener import FlowRecorder
    r = FlowRecorder(tmp_path / "assets")
    base = ("GET", "http://cap.test/cfg", {}, "", 200, {"content-type": "application/json"})
    r.record(*base, '{"debug": false}', "configuration")               # baseline, no secret
    res = r.record(*base, '{"debug": false, "aws": "AKIAIOSFODNN7EXAMPLE"}', "configuration")
    assert res and res["anomaly"] and res["severity"] == "high" and res["kind"] == "new_secret"
    assert any("aws-access-key-id" in s for s in res["added_secrets"])
    anoms = json.loads((tmp_path / "reports/anomalies.json").read_text())
    assert anoms and anoms[-1]["severity"] == "high" and anoms[-1]["added_secrets"]
    assert anoms[-1]["diff"] and (tmp_path / "assets/flows" / anoms[-1]["diff"]).is_file()


def test_anomaly_writes_semantic_json_diff(tmp_path):
    from modules.listener import FlowRecorder
    r = FlowRecorder(tmp_path / "assets")
    base = ("GET", "http://api.test/users", {}, "", 200, {"content-type": "application/json"})
    r.record(*base, '{"users": ["a", "b"]}', "configuration")
    r.record(*base, '{"users": ["a", "b", "c"], "count": 3}', "configuration")
    d = next((tmp_path / "assets/flows/api.test/users/GET").glob("*"))
    sem = next(d.glob("diff_*.semantic.json"))
    diff = json.loads(sem.read_text())
    assert "count" in diff["added"] and any("users" in c for c in diff["changed"])


def test_high_entropy_noise_not_an_anomaly(tmp_path):
    # A response differing only by a random build id (high-entropy, not a secret) is noise.
    from modules.listener import FlowRecorder
    r = FlowRecorder(tmp_path / "assets")
    base = ("GET", "http://cap.test/p", {}, "", 200, {"content-type": "text/html"})
    r.record(*base, "<html>build 9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c</html>", "page")
    r.record(*base, "<html>build 0011223344556677889900aabbccddee</html>", "page")
    assert r.stats["anomalies"] == 0        # only a high-entropy id changed -> masked


def test_image_tiebreaker_suppresses_visually_same(tmp_path, monkeypatch):
    # Hermetic: fake the renderer. A known-flow HTML change whose render matches a stored
    # baseline pHash is suppressed; one whose render differs is a real anomaly.
    from modules import listener
    r = listener.FlowRecorder(tmp_path / "assets", chromium="/usr/bin/true")
    base = ("GET", "http://cap.test/pg", {}, "", 200, {"content-type": "text/html"})
    # seed a baseline flow + give its response a known pHash (as flush would)
    r.record(*base, "<html>page A id=aaaa1111bbbb2222cccc3333</html>", "page")
    fk = next(iter(r._ledger))
    r._ledger[fk]["responses_meta"][-1]["phash"] = "ffffffffffffffff"
    calls = {"n": 0}
    def fake_render(self, body):
        calls["n"] += 1
        # visually identical to baseline for the first change, different for the second
        return ("ffffffffffffffff" if "SAME" in body else "0000000000000000"), None
    monkeypatch.setattr(listener.FlowRecorder, "_render_phash", fake_render)
    r.record(*base, "<html>page A id=zzzz9999 SAME</html>", "page")      # renders same
    assert r.stats["visual_suppressed"] == 1 and r.stats["anomalies"] == 0
    r.record(*base, "<html>totally different DIFF</html>", "page")       # renders different
    assert r.stats["anomalies"] == 1
    assert calls["n"] == 2


def test_anomaly_surfaces_in_db_and_triage(tmp_path):
    import sqlite3
    s = _agg_store(tmp_path)
    base = {"url": "http://cap.test/cfg", "method": "GET", "status": 200,
            "response_headers": {"content-type": "application/json"}}
    s.add_http({**base, "response_body": '{"ok": true}'})
    s.process()
    s.add_http({**base, "response_body": '{"ok": true, "key": "AKIAIOSFODNN7EXAMPLE"}'})  # new secret
    out = s.process()
    assert out["flows"]["anomalies"] >= 1 and out["flows"]["new_secret_anomalies"] >= 1
    con = sqlite3.connect(tmp_path / "database/recon.db")
    rows = con.execute("SELECT severity,value FROM findings WHERE finding_type='response_anomaly'").fetchall()
    con.close()
    assert rows and any(sev == "high" for sev, _ in rows)          # ranked as high in the DB
    assert out["triage"]["hosts_ranked"] >= 1                      # host is ranked (anomaly scored)
    tri = json.loads((tmp_path / "reports/triage.json").read_text())
    hosts = tri if isinstance(tri, list) else tri.get("hosts", [])
    assert any(f["type"] == "response_anomaly"
               for h in hosts for f in h.get("top_findings", []))  # anomaly shows in triage


def test_aggressive_off_by_default(tmp_path):
    s = CaptureStore(tmp_path, CFG)
    s.add_http({"url": "http://cap.test/api", "status": 200, "response_headers": {}, "response_body": "a"})
    assert s._recorder is None and not (tmp_path / "assets/flows").exists()


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def test_live_http_roundtrip(tmp_path):
    port = _free_port()
    store = CaptureStore(tmp_path, CFG)
    from http.server import ThreadingHTTPServer
    httpd = ThreadingHTTPServer(("127.0.0.1", port), listener._make_handler(store, None))
    t = threading.Thread(target=httpd.serve_forever, daemon=True); t.start()
    try:
        time.sleep(0.2)
        cap = json.dumps({"type": "http", "url": "http://rt.test/a.js", "status": 200,
                          "response_headers": {"content-type": "application/javascript"}, "response_body": "1"}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{port}/ingest", data=cap,
                                     headers={"Content-Type": "application/json"}, method="POST")
        assert json.loads(urllib.request.urlopen(req, timeout=5).read())["ingested"] == 1
        st = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/status", timeout=5).read())
        assert st["unique_assets"] == 1
    finally:
        httpd.shutdown()


def test_auth_token_enforced(tmp_path):
    port = _free_port()
    store = CaptureStore(tmp_path, CFG)
    from http.server import ThreadingHTTPServer
    httpd = ThreadingHTTPServer(("127.0.0.1", port), listener._make_handler(store, "sekret"))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        time.sleep(0.2)
        req = urllib.request.Request(f"http://127.0.0.1:{port}/status")
        with pytest.raises(urllib.error.HTTPError) as ei:  # no token -> 401
            urllib.request.urlopen(req, timeout=5)
        assert ei.value.code == 401
        req.add_header("X-JSIntel-Token", "sekret")
        assert urllib.request.urlopen(req, timeout=5).status == 200
    finally:
        httpd.shutdown()
