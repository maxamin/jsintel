"""Resilience of the crawl stage and the mass-sweep driver (2026-10-09 sweep bugs).

* katana was never told the authorized scope, so it used its own default (the seed's
  registered domain): target 12thespis.files.wordpress.com crawled 1,029,170 URLs on
  4,736 other wordpress.com hosts. crawler.sh now passes the scope as katana ``-cs``.

* katana was OOM-killed 485 times (12-34 GB RSS, jsluice allocating in C outside the
  Go GC). crawler.sh now runs it under an RLIMIT_AS cap and warns when it exits
  abnormally instead of silently keeping a truncated crawl.
* 44 targets were lost to sporadic bash segfaults (rc=139) in a stage. sweep.sh now
  retries a crash-signal death once, never retries an operator stop, and can resume
  an interrupted sweep.

Both scripts run against fake ``katana`` / ``jsintel.sh`` executables, so no network
traffic is generated (the crawler's redirect probe targets a closed loopback port).
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")


def _exe(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


# --- crawler.sh: katana memory cap ---------------------------------------------------

FAKE_KATANA = """\
printf '%s\\n' "$@" > "$(dirname "$0")/argv.txt"
# Report the address-space limit katana runs under as a crawlable .js URL.
printf 'http://127.0.0.1:9/vmem-%s.js\\n' "$(ulimit -v)"
case "${FAKE_KATANA_MODE:-ok}" in
  abort) printf 'fatal error: runtime: out of memory\\n' >&2; kill -ABRT $$ ;;
esac
"""


def _crawl(tmp_path: Path, **env: str) -> tuple[str, str]:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    _exe(bindir / "katana", FAKE_KATANA)
    out = tmp_path / "out"
    (out / "assets").mkdir(parents=True, exist_ok=True)
    (out / "logs").mkdir(exist_ok=True)
    log = out / "logs" / "jsintel.log"
    full_env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "OUTPUT_DIR": str(out),
        "LOG_FILE": str(log),
        "CONFIG": str(tmp_path / "missing.yaml"),
        "THREADS": "2",
        "CRAWL_SCOPE": "off",
        **env,
    }
    proc = subprocess.run(
        ["bash", str(ROOT / "modules" / "crawler.sh"), "http://127.0.0.1:9/"],
        env=full_env, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return (out / "assets" / "crawled_urls.txt").read_text(), log.read_text()


def test_katana_runs_under_default_memory_cap(tmp_path: Path) -> None:
    urls, log = _crawl(tmp_path)
    assert f"vmem-{8192 * 1024}.js" in urls
    assert "katana exited" not in log


def test_katana_memory_cap_is_configurable_and_can_be_disabled(tmp_path: Path) -> None:
    urls, _ = _crawl(tmp_path, JSINTEL_KATANA_MAX_VMEM_MB="4096")
    assert f"vmem-{4096 * 1024}.js" in urls
    urls, _ = _crawl(tmp_path, JSINTEL_KATANA_MAX_VMEM_MB="0")
    assert "vmem-unlimited.js" in urls


@pytest.mark.parametrize("value,expected_kb", [("100", 2048 * 1024), ("junk", 8192 * 1024)])
def test_katana_memory_cap_rejects_unusable_values(tmp_path: Path, value: str,
                                                   expected_kb: int) -> None:
    # Below ~1 GB katana cannot even start; a typo must not silently drop the cap.
    urls, _ = _crawl(tmp_path, JSINTEL_KATANA_MAX_VMEM_MB=value)
    assert f"vmem-{expected_kb}.js" in urls


def test_aborted_katana_keeps_partial_urls_and_warns(tmp_path: Path) -> None:
    urls, log = _crawl(tmp_path, FAKE_KATANA_MODE="abort")
    assert "vmem-" in urls                      # URLs printed before the abort survive
    assert "katana exited with status 134" in log
    assert "crawl results may be incomplete" in log


# --- sweep.sh: crash retry and resume ------------------------------------------------

FAKE_JSINTEL = """\
# Behaviour keyed on the target host; attempts are counted per target dir.
target="${2#https://}"; tdir="$4"
n=$(( $(cat "$tdir/.attempts" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$tdir/.attempts"
echo "attempt $n for $target"
case "$target" in
  crash-once.test) (( n == 1 )) && kill -SEGV $$ ;;
  crash-always.test) kill -SEGV $$ ;;
  stopped.test) kill -TERM $$ ;;
  broken.test) exit 1 ;;
esac
exit 0
"""


def _sweep(root: Path, out: Path, targets: list[str], **env: str) -> str:
    (root / "modules").mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / "modules" / "sweep.sh", root / "modules" / "sweep.sh")
    shutil.copy(ROOT / "modules" / "utils.sh", root / "modules" / "utils.sh")
    (root / "modules" / "__init__.py").write_text("")
    (root / "modules" / "sweep_aggregate.py").write_text("")
    _exe(root / "jsintel.sh", FAKE_JSINTEL)
    tfile = root / "targets.txt"
    tfile.write_text("\n".join(targets) + "\n")
    proc = subprocess.run(
        ["bash", str(root / "modules" / "sweep.sh"), str(tfile)],
        env={**os.environ, "OUTPUT_DIR": str(out), "LOG_FILE": "",
             "JSINTEL_SWEEP_PARALLEL": "2", **env},
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return (out / "logs" / "jsintel.log").read_text()


def _status(out: Path, target: str) -> str:
    return (out / "targets" / target / ".sweep_status").read_text().strip()


def _attempts(out: Path, target: str) -> int:
    return int((out / "targets" / target / ".attempts").read_text())


def test_sweep_retries_crash_signal_once(tmp_path: Path) -> None:
    out = tmp_path / "out"
    targets = ["crash-once.test", "crash-always.test", "stopped.test", "broken.test", "ok.test"]
    log = _sweep(tmp_path / "root", out, targets)

    assert _status(out, "crash-once.test") == "ok"
    assert _attempts(out, "crash-once.test") == 2
    first = out / "targets" / "crash-once.test" / "sweep_target.attempt1.log"
    assert "attempt 1" in first.read_text()           # failed attempt's log is kept
    assert "retry crash-once.test (stage died with rc=139" in log

    assert _status(out, "crash-always.test") == "failed rc=139"
    assert _attempts(out, "crash-always.test") == 2     # exactly one retry

    # Operator stop and ordinary failures are not retried.
    assert _status(out, "stopped.test") == "failed rc=143"
    assert _attempts(out, "stopped.test") == 1
    assert _status(out, "broken.test") == "failed rc=1"
    assert _attempts(out, "broken.test") == 1
    assert _status(out, "ok.test") == "ok"


def test_sweep_resume_skips_finished_targets_only(tmp_path: Path) -> None:
    out = tmp_path / "out"
    root = tmp_path / "root"
    _sweep(root, out, ["ok.test", "broken.test"])
    log = _sweep(root, out, ["ok.test", "broken.test"], JSINTEL_SWEEP_RESUME="1")
    assert "skip  ok.test" in log
    assert _attempts(out, "ok.test") == 1               # not re-run
    assert _attempts(out, "broken.test") == 2           # failed target is re-run

    _sweep(root, out, ["ok.test"])                      # default: no resume, re-runs
    assert _attempts(out, "ok.test") == 2


# --- crawler.sh: katana is handed the authorized scope ---------------------------------

def _katana_scope_regex(tmp_path: Path, scope: str) -> str | None:
    _crawl(tmp_path, CRAWL_SCOPE=scope)
    argv = (tmp_path / "bin" / "argv.txt").read_text().splitlines()
    return argv[argv.index("-cs") + 1] if "-cs" in argv else None


def test_katana_gets_anchored_scope_not_registered_domain(tmp_path: Path) -> None:
    rx = _katana_scope_regex(tmp_path, "12thespis.files.wordpress.com,shop.vuln.lab")
    assert rx is not None
    ok = re.compile(rx)
    for url in ("https://12thespis.files.wordpress.com/",
                "https://12thespis.files.wordpress.com:8443/a.js?x=1",
                "http://cdn.12thespis.files.wordpress.com/x",
                "http://shop.vuln.lab#frag",
                "https://user@shop.vuln.lab/p"):
        assert ok.search(url), url
    for url in ("https://wordpress.com/", "https://ahairlessape.wordpress.com/",
                "https://0.gravatar.com/avatar/x", "https://files.wordpress.com/",
                "https://x12thespis.files.wordpress.com/",
                "https://12thespis.files.wordpress.com.evil.net/",
                "https://evil.net/?u=https://shop.vuln.lab/",
                "https://smap.vuln.lab/"):
        assert not ok.search(url), url


def test_katana_scope_escapes_regex_metacharacters(tmp_path: Path) -> None:
    ok = re.compile(_katana_scope_regex(tmp_path, "a.b-c.com") or "")
    assert ok.search("https://a.b-c.com/")
    assert not ok.search("https://aXb-c.com/")       # "." is literal, not "any char"


def test_katana_scope_off_leaves_katana_default(tmp_path: Path) -> None:
    assert _katana_scope_regex(tmp_path, "off") is None
