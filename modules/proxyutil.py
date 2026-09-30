"""Route a stage's network traffic through proxychains via self-re-exec.

proxychains works by ``LD_PRELOAD``-ing a shim into a process *at launch*, so it
cannot be applied to an already-running interpreter's in-process sockets. The clean
way to send a Python stage (and every child it spawns) through a proxy is therefore
to re-exec the whole process under ``proxychains4`` once, guarded by an env var so
it happens exactly once.

Used by the listener and the forms driver so ``--proxychains`` sends their active,
outbound traffic (fuzzer, ``requests`` submissions, headless Chromium) through the
configured proxy chain — matching how ``jsintel.sh`` is commonly run under
``proxychains4`` by hand.
"""
from __future__ import annotations

import os
import shutil
import sys

_GUARD = "JSINTEL_UNDER_PROXYCHAINS"


def build_proxychains_cmd(argv: list[str], conf: str | None = None,
                          binary: str = "proxychains4") -> list[str]:
    """Return the argv that runs ``argv`` under proxychains (``-q`` quiet)."""
    cmd = [binary, "-q"]
    if conf and conf not in ("1", "default", "on", "yes"):
        cmd += ["-f", conf]
    return cmd + argv


def maybe_reexec_proxychains(conf: str | None) -> None:
    """Re-exec the current process under proxychains unless already wrapped.

    ``conf`` is the value of the ``--proxychains`` option: ``None``/empty means "do
    nothing"; a truthy sentinel (``"1"``) uses the default config; any other value is
    treated as a path to a proxychains config file. No-op when already re-exec'd
    (guarded) or when ``proxychains4`` is not installed (a warning is printed and the
    stage continues directly rather than failing).
    """
    if not conf:
        return
    if os.environ.get(_GUARD):
        return
    binary = "proxychains4" if shutil.which("proxychains4") else (
        "proxychains" if shutil.which("proxychains") else "")
    if not binary:
        print("[jsintel] --proxychains requested but proxychains4 is not installed; "
              "continuing WITHOUT a proxy", file=sys.stderr, flush=True)
        return
    env = dict(os.environ)
    env[_GUARD] = "1"
    argv = build_proxychains_cmd([sys.executable, *sys.argv], conf, binary)
    os.execvpe(binary, argv, env)
