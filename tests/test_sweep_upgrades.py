"""Regression tests for the upgrades driven by the 2026-10-09 sweep-log analysis.

Covers: dead/wildcard pre-filter, proxychains handling (port scan, Chromium, Go
tools, loopback), code-intel routing, offline fuzz rescore and --reanalyze, katana
crawl flags, stage telemetry, target hygiene, and the sweep health check. No test
sends traffic beyond loopback.
"""
from __future__ import annotations

import json
import os
import shutil
import socketserver
import stat
import subprocess
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest

from modules import proxyutil, sweep_aggregate
from modules.extractor.findings import SecurityFinding
from modules.extractor.writer import JSONWriter
from modules.fuzzer.engine import rescore
from modules.sweep_prefilter import Fingerprint, fingerprint, prefilter

ROOT = Path(__file__).resolve().parents[1]


def _exe(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


# --- pre-filter -----------------------------------------------------------------------

CATCH_ALL = b"<html><title>Parked</title><p>Welcome to {host}</p>" + b"x" * 500


def _fetcher(live: dict[str, bytes], wildcard_parents: set[str], calls: list[str] | None = None):
    def fetch(url: str):
        if calls is not None:
            calls.append(url)
        host = url.split("://", 1)[1].rstrip("/")
        if host in live:
            return 200, url, live[host]
        parent = host.split(".", 1)[1] if "." in host else ""
        if parent in wildcard_parents:   # the parent answers ANY name with its catch-all
            return 200, url, CATCH_ALL.replace(b"{host}", host.encode())
        return None
    return fetch


def test_prefilter_drops_dead_and_collapses_wildcard_duplicates():
    targets = ["asia.kwenta.test", "cdn1.kwenta.test", "crm2.kwenta.test", "app.kwenta.test",
               "dead.example.test", "www.example.test"]
    live = {"app.kwenta.test": b"<title>Kwenta app</title>real app",
            "www.example.test": b"<title>Example</title>"}
    out = prefilter(targets, _fetcher(live, {"kwenta.test"}), random_label=lambda: "zz-random")
    # One representative of the catch-all is kept; the distinct real app is kept.
    assert out["kept"] == ["asia.kwenta.test", "app.kwenta.test", "www.example.test"]
    assert out["skipped"]["cdn1.kwenta.test"].startswith("wildcard: kwenta.test")
    assert "same page as asia.kwenta.test" in out["skipped"]["crm2.kwenta.test"]
    assert out["skipped"]["dead.example.test"].startswith("dead")
    assert out["wildcards"]["kwenta.test"]["collapsed"] == 2


def test_prefilter_only_probes_parents_with_several_targets():
    calls: list[str] = []
    prefilter(["a.solo.test"], _fetcher({"a.solo.test": b"x"}, set(), calls),
              random_label=lambda: "zz")
    assert not any("zz." in c for c in calls)


def test_prefilter_modes():
    targets = ["gone.example.test", "up.example.test"]
    fetch = _fetcher({"up.example.test": b"<title>up</title>"}, set())
    assert prefilter(targets, fetch, mode="wildcard")["kept"] == targets   # dead kept
    assert prefilter(targets, fetch, mode="off")["kept"] == targets
    assert prefilter(targets, fetch)["kept"] == ["up.example.test"]


def test_prefilter_keep_resolving_spares_silent_hosts_for_port_scans():
    targets = ["silent.example.test", "gone.example.test", "up.example.test"]
    fetch = _fetcher({"up.example.test": b"<title>up</title>"}, set())
    out = prefilter(targets, fetch, keep_resolving=True,
                    resolver=lambda h: h == "silent.example.test")
    assert out["kept"] == ["silent.example.test", "up.example.test"]
    assert out["skipped"] == {"gone.example.test": "dead: no address record"}


def test_fingerprint_masks_echoed_host_and_tolerates_small_size_drift():
    a = fingerprint("a.p.test", 200, "https://a.p.test/", CATCH_ALL.replace(b"{host}", b"a.p.test"))
    b = fingerprint("longer-name.p.test", 200, "https://longer-name.p.test/",
                    CATCH_ALL.replace(b"{host}", b"longer-name.p.test"))
    assert a.matches(b)
    assert not a.matches(Fingerprint(200, "other title", a.redirect, a.length))
    assert not a.matches(Fingerprint(a.status, a.title, a.redirect, a.length * 2))
    assert not a.matches(Fingerprint(403, a.title, a.redirect, a.length))


# --- proxychains ----------------------------------------------------------------------

CONF = """strict_chain
proxy_dns
# localnet 127.0.0.0/255.0.0.0
[ProxyList]
socks4 127.0.0.1 9050
http 10.0.0.1 8080
"""
PRELOAD = {"LD_PRELOAD": "/usr/lib/x86_64-linux-gnu/libproxychains.so.4", "PATH": "/usr/bin"}


def test_under_proxychains_detection():
    assert proxyutil.under_proxychains(PRELOAD)
    assert proxyutil.under_proxychains({"JSINTEL_UNDER_PROXYCHAINS": "1"})
    assert not proxyutil.under_proxychains({"LD_PRELOAD": "/usr/lib/libfoo.so"})


def test_chain_proxy_parsing():
    assert proxyutil.first_proxy(CONF) == ("socks4", "127.0.0.1", 9050, False)
    # socks4 is upgraded to socks5 so names are resolved by the proxy (no DNS leak)
    assert proxyutil.proxy_url(PRELOAD, CONF) == "socks5://127.0.0.1:9050"
    assert proxyutil.proxy_url(PRELOAD, "[ProxyList]\nsocks5 1.2.3.4 1080 user pass\n") is None
    assert proxyutil.proxy_url(PRELOAD, "[ProxyList]\nraw 1.2.3.4 1080\n") is None
    assert proxyutil.proxy_url(PRELOAD, "no list here\n") is None


def test_chromium_launch_strips_preload_and_sets_proxy():
    env = {**PRELOAD, "LD_PRELOAD": PRELOAD["LD_PRELOAD"] + " /usr/lib/libkeep.so"}
    launched = proxyutil.chromium_launch(env, CONF)
    assert launched is not None
    new_env, args = launched
    assert new_env["LD_PRELOAD"] == "/usr/lib/libkeep.so"
    assert "--proxy-server=socks5://127.0.0.1:9050" in args
    assert any(a.startswith("--host-resolver-rules=MAP * ~NOTFOUND") for a in args)
    # Not under proxychains: untouched environment, no flags.
    assert proxyutil.chromium_launch({"PATH": "/usr/bin"}, CONF) == ({"PATH": "/usr/bin"}, [])
    # Under proxychains without a usable proxy: refuse (never launch direct).
    assert proxyutil.chromium_launch(PRELOAD, "[ProxyList]\nsocks5 h 1 u p\n") is None


def test_loopback_hostnames_bypass_the_proxy_in_chromium(monkeypatch):
    hosts = ("127.0.0.1 localhost\n127.0.1.1 box.example box\n::1 ip6-localhost\n"
             "10.0.0.5 intranet.test\n127.0.0.4 api.vuln.lab # lab\n")
    assert proxyutil.loopback_hostnames(hosts) == ["box.example", "box", "api.vuln.lab"]
    monkeypatch.setattr(proxyutil, "loopback_hostnames", lambda: ["api.vuln.lab"])
    _, args = proxyutil.chromium_launch(PRELOAD, CONF)
    assert "--proxy-bypass-list=api.vuln.lab" in args
    assert any("EXCLUDE api.vuln.lab" in a for a in args if a.startswith("--host-resolver"))


def test_managed_conf_excludes_loopback_before_proxylist(tmp_path):
    text = proxyutil.managed_conf_text(CONF)
    lines = text.splitlines()
    assert lines.index("localnet 127.0.0.0/255.0.0.0") < lines.index("[ProxyList]")
    assert proxyutil.managed_conf_text(text) == text          # idempotent
    src = tmp_path / "pc.conf"
    src.write_text(CONF)
    out = proxyutil.managed_conf(str(src))
    try:
        assert out and "localnet 127.0.0.0/255.0.0.0" in Path(out).read_text()
    finally:
        if out:
            os.unlink(out)


class _Ok(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


@pytest.fixture()
def http_port():
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Ok)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()


def test_portscan_under_proxychains_skips_raw_scanners(monkeypatch, http_port, tmp_path):
    from modules import portscan
    monkeypatch.setattr(portscan, "under_proxychains", lambda: True)
    monkeypatch.setattr(portscan, "_scan_nmap", lambda *a, **k: pytest.fail("nmap used"))
    monkeypatch.setattr(portscan, "_scan_naabu", lambda *a, **k: pytest.fail("naabu used"))
    found, scanner = portscan.discover_ports(["127.0.0.1"], (http_port,), timeout=1, workers=2,
                                             hosts_file=tmp_path / "h")
    assert found == {"127.0.0.1": {http_port}}
    assert scanner == "python-connect (proxychains)"


def test_webshot_skips_instead_of_connecting_direct(monkeypatch, tmp_path):
    from modules import webshot
    monkeypatch.setattr(webshot, "find_chromium", lambda explicit="": "/usr/bin/chromium")
    monkeypatch.setattr(webshot, "chromium_launch", lambda: None)
    monkeypatch.setattr(webshot, "render_screenshot",
                        lambda *a, **k: pytest.fail("Chromium launched without a proxy"))
    services = tmp_path / "svc.txt"
    services.write_text("https://a.test/\n")
    out = webshot.run(tmp_path, services)
    assert out["captured"] == 0 and out["engine"] == "none"


# --- code intel, rescore --------------------------------------------------------------

def test_structural_findings_go_to_code_intel(tmp_path):
    writer = JSONWriter(tmp_path)
    for ftype in ("call_graph", "class", "export", "cross_asset_dependency", "cross_asset_call"):
        writer.write(SecurityFinding("u", ftype, "info", "x"))
    writer.write(SecurityFinding("u", "hardcoded_secret", "high", "k"))
    writer.close()
    findings = json.loads((tmp_path / "findings.json").read_text())
    code_intel = json.loads((tmp_path / "code_intel.json").read_text())
    assert [f["finding_type"] for f in findings] == ["hardcoded_secret"]
    assert len(code_intel) == 5


def test_rescore_demotes_a_waf_wall_offline(tmp_path):
    wall = [{"url": f"https://h.test/{i}", "category": "api", "origin": "/", "word": str(i),
             "status": 403, "length": 33976 + i % 7, "interesting": True, "note": "match"}
            for i in range(40)]
    real = {"url": "https://h.test/admin", "category": "api", "origin": "/", "word": "admin",
            "status": 200, "length": 512, "interesting": True, "note": "match"}
    (tmp_path / "fuzz.json").write_text(json.dumps(wall + [real]))
    (tmp_path / "fuzz_summary.json").write_text(json.dumps({"candidates": 41, "findings_read": 3}))
    summary = rescore(tmp_path)
    assert summary is not None and summary.interesting == 1 and summary.findings_read == 3
    rows = json.loads((tmp_path / "fuzz.json").read_text())
    assert rows[0]["url"].endswith("/admin")
    assert sum(r["note"] == "repeated-response" for r in rows) == 40
    assert rescore(tmp_path / "nothing") is None


# --- --reanalyze ----------------------------------------------------------------------

def _old_run(tmp_path: Path) -> Path:
    src = tmp_path / "old_run"
    (src / "assets").mkdir(parents=True)
    (src / "reports").mkdir()
    js = src / "assets" / "000000_app.js"
    js.write_text('function f(){ return g(); } function g(){ return 1 }\n'
                  'var k = "AKIAIOSFODNN7EXAMPLQ";\n', encoding="utf-8")
    (src / "reports" / "assets.json").write_text(json.dumps([{
        "url": "https://h.test/app.js", "type": "javascript", "local_path": str(js),
        "status": "downloaded", "sha256": "x", "size_bytes": js.stat().st_size,
        "mime_type": "application/javascript"}]))
    (src / "reports" / "findings.json").write_text("[]\n")       # stale, must not be copied
    (src / "reports" / "summary.json").write_text("{}\n")
    (src / "reports" / "ports.json").write_text("[]\n")          # carried over
    wall = [{"url": f"https://h.test/{i}", "category": "api", "origin": "/", "word": str(i),
             "status": 403, "length": 9000, "interesting": True, "note": "match"} for i in range(30)]
    (src / "reports" / "fuzz.json").write_text(json.dumps(wall))
    return src


def _tree_state(path: Path) -> dict[str, float]:
    return {str(p): p.stat().st_mtime for p in path.rglob("*")}


def test_reanalyze_rebuilds_offline_into_new_dir(tmp_path):
    src = _old_run(tmp_path)
    before = _tree_state(src)
    new = tmp_path / "new_run"
    proc = subprocess.run(["bash", str(ROOT / "jsintel.sh"), "--reanalyze", str(src), "-o", str(new)],
                          capture_output=True, text=True, timeout=300,
                          env={**os.environ, "THREADS": "2"})
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert _tree_state(src) == before                       # source run only read
    summary = json.loads((new / "reports" / "summary.json").read_text())
    assert summary["fuzz_interesting"] == 0                  # the 403 wall was rescored
    assert (new / "reports" / "ports.json").is_file()
    assert json.loads((new / "reports" / "code_intel.json").read_text())   # call graph moved
    assert (new / "database" / "recon.db").is_file()


def test_reanalyze_refuses_to_write_into_source(tmp_path):
    src = _old_run(tmp_path)
    for target in (src, src / "sub"):
        proc = subprocess.run(["bash", str(ROOT / "jsintel.sh"), "--reanalyze", str(src),
                               "-o", str(target)], capture_output=True, text=True, timeout=60)
        assert proc.returncode != 0 and "new directory" in proc.stderr


# --- crawler flags --------------------------------------------------------------------

def _crawl_argv(tmp_path: Path, seed: str = "http://127.0.0.1:9/", **env: str) -> list[str]:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    _exe(bindir / "curl", "exit 7\n")          # redirect probe: no network, seed kept as-is
    # getent as proxychains answers it: /etc/hosts lab names -> 127.x, others -> 224.x
    _exe(bindir / "getent", 'case "$2" in *.lab.test) echo "127.0.0.5 STREAM $2";; '
         '*) echo "224.0.0.1 STREAM $2";; esac\n')
    _exe(bindir / "katana", 'printf "%s\\n" "$@" > "$(dirname "$0")/argv.txt"\n'
         'printf "%s\\n" http://127.0.0.1:9/static/chunks/static/chunks/x.js '
         'http://127.0.0.1:9/_next/static/chunks/x.js '
         'http://127.0.0.1:9/static/chunks/app/static/chunks/z.js?v=1 '
         'http://127.0.0.1:9/assets/js/assets/js/y.js\n')
    out = tmp_path / "out"
    (out / "assets").mkdir(parents=True, exist_ok=True)
    (out / "logs").mkdir(exist_ok=True)
    proc = subprocess.run(
        ["bash", str(ROOT / "modules" / "crawler.sh"), seed],
        env={**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "OUTPUT_DIR": str(out),
             "LOG_FILE": str(out / "logs" / "l.log"), "CONFIG": "/nonexistent", "THREADS": "2",
             "CRAWL_SCOPE": "off", **env},
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return (bindir / "argv.txt").read_text().splitlines()


def test_crawler_bounds_duration_and_routes_go_tool_through_proxy(tmp_path):
    argv = _crawl_argv(tmp_path)
    assert argv[argv.index("-ct") + 1] == "15m" and "-proxy" not in argv
    argv = _crawl_argv(tmp_path, "https://app.example.test/", JSINTEL_CRAWL_DURATION="90s",
                       JSINTEL_PROXY_URL="socks5://127.0.0.1:9050")
    assert argv[argv.index("-ct") + 1] == "90s"
    assert argv[argv.index("-proxy") + 1] == "socks5://127.0.0.1:9050"
    # Loopback seeds are not proxied (a SOCKS proxy cannot reach the operator's 127/8),
    # matching the managed config's localnet rule.
    assert "-proxy" not in _crawl_argv(tmp_path, JSINTEL_PROXY_URL="socks5://127.0.0.1:9050")
    assert "-ct" not in _crawl_argv(tmp_path, JSINTEL_CRAWL_DURATION="0")
    invalid = _crawl_argv(tmp_path, JSINTEL_CRAWL_DURATION="soon")
    assert invalid[invalid.index("-ct") + 1] == "15m"            # typo falls back, never unbounded


def test_crawler_repairs_self_repeating_chunk_urls(tmp_path):
    _crawl_argv(tmp_path)
    kept = (tmp_path / "out" / "assets" / "crawled_urls.txt").read_text().splitlines()
    # Rebuilt under the prefix a well-formed URL on the origin uses (/_next/), deduped;
    # an artifact whose block has no well-formed example (assets/js) is dropped.
    assert kept == ["http://127.0.0.1:9/_next/static/chunks/x.js",
                    "http://127.0.0.1:9/_next/static/chunks/z.js?v=1"]


def test_crawler_treats_hosts_file_loopback_names_as_local(tmp_path):
    proxy = {"JSINTEL_PROXY_URL": "socks5://127.0.0.1:9050"}
    assert "-proxy" not in _crawl_argv(tmp_path, "http://shop.lab.test:3000/", **proxy)
    assert "-proxy" in _crawl_argv(tmp_path, "https://app.example.test/", **proxy)


# --- telemetry, health, sweep wiring --------------------------------------------------

def _target(base: Path, name: str, status: str, summary: dict) -> None:
    tdir = base / "targets" / name
    (tdir / "reports").mkdir(parents=True)
    (tdir / ".sweep_status").write_text(status + "\n")
    (tdir / "reports" / "summary.json").write_text(json.dumps(summary))


def test_health_flags_stages_dead_on_every_target(tmp_path):
    names = [f"t{i}.test" for i in range(60)]
    for n in names:
        _target(tmp_path, n, "ok", {"web_services": 0, "pipeline": {
            "screenshots_attempted": 1, "screenshots_captured": 0, "downloads": {"failed": 2}}})
    warnings = sweep_aggregate.health(tmp_path, names, {"ports", "webshot"})
    assert any("port scan found 0 web services" in w for w in warnings)
    assert any("0 of 60 screenshots" in w for w in warnings)
    assert any("0 of 120 downloads" in w for w in warnings)
    assert sweep_aggregate.health(tmp_path, names[:49], {"ports"}) == []   # too early to judge
    assert not any("port" in w for w in sweep_aggregate.health(tmp_path, names, {"webshot"}))


def test_aggregate_rolls_up_stages_and_prefilter_skips(tmp_path):
    _target(tmp_path, "a.test", "ok", {"stages": {"crawl": {"seconds": 30, "rc": 0},
                                                  "fuzz": {"seconds": 5, "rc": 1}}})
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "prefilter.json").write_text(json.dumps(
        {"skipped": {"b.test": "dead: no HTTP(S) answer"}}))
    agg = sweep_aggregate.aggregate(tmp_path, ["a.test", "b.test"])
    assert agg["stages"]["crawl"] == {"targets": 1, "seconds": 30, "failed": 0}
    assert agg["stages"]["fuzz"]["failed"] == 1
    assert agg["totals"]["skipped"] == 1
    assert "skipped by the pre-filter" in (tmp_path / "reports" / "sweep_summary.md").read_text()


def test_reporter_folds_stage_timings_into_summary(tmp_path):
    out = tmp_path / "run"
    (out / "reports").mkdir(parents=True)
    (out / "assets").mkdir()
    (out / "reports" / "assets.json").write_text(json.dumps(
        [{"url": "u1", "type": "javascript", "status": "downloaded"},
         {"url": "u2", "type": "javascript", "status": "blocked"}]))
    (out / "assets" / "crawled_urls.txt").write_text("u1\nu2\n")
    (out / "reports" / "stages.tsv").write_text("crawl\t12\t0\nextract\t3\t0\nextract\t2\t0\n")
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    subprocess.run(["python3", str(ROOT / "modules" / "database.py"), "--output", str(out),
                    "--config", "/nonexistent", "ingest"], check=True, env=env, capture_output=True)
    subprocess.run(["python3", str(ROOT / "modules" / "reporter.py"), "--output", str(out),
                    "--config", "/nonexistent"], check=True, env=env, capture_output=True)
    summary = json.loads((out / "reports" / "summary.json").read_text())
    assert summary["stages"]["extract"] == {"seconds": 5, "rc": 0, "runs": 2}
    assert summary["pipeline"]["crawl_kept"] == 2
    assert summary["pipeline"]["downloads"] == {"downloaded": 1, "blocked": 1}


FAKE_JSINTEL = 'echo "$@" > "$4/argv"; exit 0\n'
FAKE_PREFILTER = '''import json, sys
from pathlib import Path
args = sys.argv[1:]
out = Path(args[args.index("--output") + 1])
targets = [l.strip() for l in sys.stdin if l.strip()]
kept = [t for t in targets if not t.startswith("dup")]
(out / "reports").mkdir(parents=True, exist_ok=True)
(out / "reports" / "prefilter.json").write_text(json.dumps(
    {"skipped": {t: "wildcard: x" for t in targets if t not in kept}}))
print("\\n".join(kept))
'''


def _fake_sweep(tmp_path: Path, targets: str, **env: str) -> tuple[Path, str]:
    root = tmp_path / "root"
    (root / "modules").mkdir(parents=True)
    for f in ("sweep.sh", "utils.sh", "sweep_aggregate.py", "__init__.py"):
        shutil.copy(ROOT / "modules" / f, root / "modules" / f)
    (root / "modules" / "sweep_prefilter.py").write_text(FAKE_PREFILTER)
    _exe(root / "jsintel.sh", FAKE_JSINTEL)
    tfile = tmp_path / "targets.txt"
    tfile.write_text(targets)
    out = tmp_path / "out"
    proc = subprocess.run(["bash", str(root / "modules" / "sweep.sh"), str(tfile)],
                          env={**os.environ, "OUTPUT_DIR": str(out), "LOG_FILE": "", **env},
                          capture_output=True, text=True, timeout=60, cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr
    return out, (out / "logs" / "jsintel.log").read_text()


def test_sweep_target_hygiene_deny_list_and_prefilter(tmp_path):
    targets = ("_wildcard.yoca.test\n_carddavs._tcp.c.test\n-bad.test\nbad-.test\nx..test\n"
               "Good.Test.\nhttps://app.real.test/path\nsite.files.wordpress.com\n"
               "dup1.real.test\n")
    out, log = _fake_sweep(tmp_path, targets, JSINTEL_SWEEP_DENY="*.files.wordpress.com")
    ran = sorted(p.name for p in (out / "targets").iterdir() if (p / "argv").is_file())
    assert ran == ["app.real.test", "good.test"]
    assert "Deny-list (JSINTEL_SWEEP_DENY) removed 1 target(s)" in log
    assert "Pre-filter kept 2 of 3" in log
    summary = json.loads((out / "reports" / "sweep_summary.json").read_text())
    statuses = {r["target"]: r["status"] for r in summary["targets"]}
    assert statuses["dup1.real.test"] == "skipped: wildcard: x"


def test_sweep_prefilter_off_runs_everything(tmp_path):
    out, _ = _fake_sweep(tmp_path, "dup1.real.test\nok.real.test\n", JSINTEL_SWEEP_PREFILTER="off")
    assert sorted(p.name for p in (out / "targets").iterdir()) == ["dup1.real.test", "ok.real.test"]


def test_forms_driver_refuses_to_launch_chromium_without_proxy(monkeypatch, tmp_path):
    from modules.forms import driver
    monkeypatch.setattr(driver, "chromium_launch", lambda: None)
    monkeypatch.setattr(driver.subprocess, "Popen",
                        lambda *a, **k: pytest.fail("Chromium launched without a proxy"))
    with pytest.raises(RuntimeError, match="no usable proxy"):
        driver._launch_chromium("/usr/bin/chromium", tmp_path, [])


def test_forms_driver_passes_proxy_flags_and_clean_env(monkeypatch, tmp_path):
    from modules.forms import driver
    seen = {}

    class _Proc:
        def poll(self):
            return 0

    def popen(cmd, **kwargs):
        seen["cmd"], seen["env"] = cmd, kwargs.get("env")
        return _Proc()

    monkeypatch.setattr(driver, "chromium_launch",
                        lambda: ({"PATH": "/usr/bin"}, ["--proxy-server=socks5://127.0.0.1:9050"]))
    monkeypatch.setattr(driver.subprocess, "Popen", popen)
    with pytest.raises(RuntimeError):            # fake process "exits" before a debug port
        driver._launch_chromium("/usr/bin/chromium", tmp_path, ["--x"])
    assert "--proxy-server=socks5://127.0.0.1:9050" in seen["cmd"] and "--x" in seen["cmd"]
    assert seen["env"] == {"PATH": "/usr/bin"}


def _subdomains(tmp_path: Path, **env: str) -> dict[str, str]:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in ("assetfinder", "subfinder", "amass"):
        _exe(bindir / tool, f'echo "$* | ${{HTTPS_PROXY:-none}}" > "$(dirname "$0")/{tool}.args"\n')
    out = tmp_path / "out"
    (out / "assets").mkdir(parents=True)
    (out / "logs").mkdir()
    subprocess.run(["bash", str(ROOT / "modules" / "subdomains.sh"), "example.test"],
                   env={**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}",
                        "OUTPUT_DIR": str(out), "LOG_FILE": str(out / "logs" / "l.log"),
                        "CONFIG": "/nonexistent", "THREADS": "2", **env},
                   capture_output=True, text=True, timeout=120, check=True)
    return {t: (bindir / f"{t}.args").read_text().strip() for t in ("assetfinder", "subfinder", "amass")
            if (bindir / f"{t}.args").is_file()}


def test_amass_is_skipped_and_go_tools_proxied_under_proxychains(tmp_path):
    ran = _subdomains(tmp_path, JSINTEL_PROXY_URL="socks5://127.0.0.1:9050")
    # amass resolves through public DNS directly (measured), so it must not run.
    assert "amass" not in ran
    assert ran["assetfinder"].endswith("| socks5://127.0.0.1:9050")
    assert "-proxy socks5://127.0.0.1:9050" in ran["subfinder"]


def test_amass_runs_without_proxychains(tmp_path):
    ran = _subdomains(tmp_path)
    assert set(ran) == {"assetfinder", "subfinder", "amass"}
    assert all(v.endswith("| none") for v in ran.values())
