"""proxychains re-exec helper: command construction, guard, and fallbacks."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from modules.proxyutil import build_proxychains_cmd, maybe_reexec_proxychains

REPO = Path(__file__).resolve().parents[1]


def test_build_cmd_default_config():
    assert build_proxychains_cmd(["python3", "-m", "modules.listener"], "1") == \
        ["proxychains4", "-q", "python3", "-m", "modules.listener"]


def test_build_cmd_explicit_config_path():
    assert build_proxychains_cmd(["a", "b"], "/etc/pc.conf") == \
        ["proxychains4", "-q", "-f", "/etc/pc.conf", "a", "b"]


@pytest.mark.parametrize("sentinel", ["1", "default", "on", "yes"])
def test_build_cmd_treats_sentinels_as_default(sentinel):
    assert "-f" not in build_proxychains_cmd(["x"], sentinel)


def test_maybe_reexec_noop_when_conf_empty():
    # No conf -> returns immediately (would raise if it tried to exec).
    maybe_reexec_proxychains(None)
    maybe_reexec_proxychains("")


def test_maybe_reexec_noop_when_guard_set(monkeypatch):
    monkeypatch.setenv("JSINTEL_UNDER_PROXYCHAINS", "1")
    called = {}
    monkeypatch.setattr(os, "execvpe", lambda *a, **k: called.setdefault("x", True))
    maybe_reexec_proxychains("1")
    assert "x" not in called  # guard prevented the re-exec


def test_maybe_reexec_warns_and_continues_when_binary_absent(monkeypatch, capsys):
    monkeypatch.delenv("JSINTEL_UNDER_PROXYCHAINS", raising=False)
    monkeypatch.setattr("shutil.which", lambda name: None)
    exec_called = {}
    monkeypatch.setattr(os, "execvpe", lambda *a, **k: exec_called.setdefault("x", True))
    maybe_reexec_proxychains("1")
    assert "x" not in exec_called
    assert "proxychains4 is not installed" in capsys.readouterr().err


def test_reexec_runs_once_through_fake_proxychains(tmp_path):
    """End-to-end: a stage re-execs itself exactly once under a fake proxychains4."""
    fakebin = tmp_path / "bin"
    fakebin.mkdir()
    log = tmp_path / "pc.log"
    (fakebin / "proxychains4").write_text(
        "#!/usr/bin/env bash\n"
        f'echo "invoked: $*" >> "{log}"\n'
        'args=(); while [[ $# -gt 0 ]]; do case "$1" in -q) shift;; -f) shift 2;; '
        '*) args+=("$1"); shift;; esac; done\n'
        'exec "${args[@]}"\n'
    )
    (fakebin / "proxychains4").chmod(0o755)

    # A tiny stage that re-execs itself under proxychains, then prints a marker.
    stage = tmp_path / "stage.py"
    stage.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(REPO)!r})\n"
        "from modules.proxyutil import maybe_reexec_proxychains\n"
        "maybe_reexec_proxychains('1')\n"
        "print('STAGE-RAN')\n"
    )
    env = dict(os.environ, PATH=f"{fakebin}:{os.environ['PATH']}")
    env.pop("JSINTEL_UNDER_PROXYCHAINS", None)
    out = subprocess.run([sys.executable, str(stage)], env=env, capture_output=True,
                         text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    assert "STAGE-RAN" in out.stdout
    # Exactly one proxychains invocation (the guard prevents an exec loop).
    assert log.read_text().count("invoked:") == 1
