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
    argv = build_proxychains_cmd([sys.executable, *sys.argv], managed_conf(conf) or conf, binary)
    os.execvpe(binary, argv, env)


# --------------------------------------------------------------------------- #
# Tools that cannot run under the proxychains preload
# --------------------------------------------------------------------------- #
# The 2026-10-09 sweep ran as `proxychains4 -q ./jsintel.sh -m ...`, which broke two
# stages on all 13,070 targets without an error:
#  * proxy_dns makes getaddrinfo() return a placeholder (224.0.0.1) for every host,
#    so the port scan sent nmap to that address and found 0 web services everywhere.
#    nmap/naabu/masscan send raw packets that never pass through the proxy anyway
#    (and, when they do reach the target, they reveal the operator's real address).
#  * headless Chromium aborts under the LD_PRELOAD shim (rc 134), so every
#    screenshot and every forms-driver page failed.
# The helpers below let those stages detect the preload and route around it.

_CONF_CANDIDATES = ("proxychains.conf", "~/.proxychains/proxychains.conf",
                    "/etc/proxychains4.conf", "/etc/proxychains.conf")


def under_proxychains(env: dict[str, str] | None = None) -> bool:
    """True when this process runs under the proxychains preload."""
    env = os.environ if env is None else env
    return bool(env.get(_GUARD)) or "proxychains" in env.get("LD_PRELOAD", "")


def proxychains_conf(env: dict[str, str] | None = None) -> str | None:
    """Path of the proxychains config in effect, in proxychains' own search order."""
    env = os.environ if env is None else env
    explicit = env.get("PROXYCHAINS_CONF_FILE")
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    for candidate in _CONF_CANDIDATES:
        path = os.path.expanduser(candidate)
        if os.path.isfile(path):
            return path
    return None


def first_proxy(conf_text: str) -> tuple[str, str, int, bool] | None:
    """Return ``(type, host, port, has_credentials)`` of the first [ProxyList] entry."""
    in_list = False
    for raw in conf_text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            in_list = line.lower() == "[proxylist]"
            continue
        if not in_list:
            continue
        parts = line.split()
        if len(parts) >= 3 and parts[2].isdigit():
            return parts[0].lower(), parts[1], int(parts[2]), len(parts) > 3
    return None


def chain_proxy(env: dict[str, str] | None = None,
                conf_text: str | None = None) -> tuple[str, str, int] | None:
    """``(scheme, host, port)`` a non-libc client should use instead of the preload.

    socks4 entries are returned as socks5: socks4 makes the client resolve names
    locally (a DNS leak), and Tor and common SOCKS servers accept both. ``None`` when
    the config is missing, the entry needs credentials, or its type is unsupported.
    """
    if conf_text is None:
        path = proxychains_conf(os.environ if env is None else env)
        if not path:
            return None
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                conf_text = handle.read()
        except OSError:
            return None
    proxy = first_proxy(conf_text)
    if proxy is None:
        return None
    kind, host, port, has_credentials = proxy
    scheme = {"socks5": "socks5", "socks4": "socks5", "http": "http"}.get(kind)
    if scheme is None or has_credentials:
        return None
    return scheme, host, port


def proxy_url(env: dict[str, str] | None = None, conf_text: str | None = None) -> str | None:
    """URL of the chain's proxy for Go tools (katana ``-proxy``, ``HTTPS_PROXY``).

    Go binaries make syscalls directly instead of through libc, so the preload never
    sees their sockets: under ``proxychains4`` katana crawled straight from the
    operator's own address (verified on loopback). They have to be told the proxy.
    """
    found = chain_proxy(env, conf_text)
    return f"{found[0]}://{found[1]}:{found[2]}" if found else None


_LOCALNET = "localnet 127.0.0.0/255.0.0.0"


def managed_conf_text(conf_text: str) -> str:
    """``conf_text`` with loopback excluded from proxying.

    Without it every loopback connection goes to the proxy too: the forms driver's
    DevTools socket to its own Chromium, and lab targets, fail (verified: urlopen to
    127.0.0.1 under proxychains4 is refused). localnet must precede [ProxyList].
    """
    lines = conf_text.splitlines()
    if any(line.split("#", 1)[0].strip() == _LOCALNET for line in lines):
        return conf_text
    for index, line in enumerate(lines):
        if line.strip().lower() == "[proxylist]":
            lines.insert(index, _LOCALNET)
            break
    else:
        lines.insert(0, _LOCALNET)
    return "\n".join(lines) + "\n"


def managed_conf(source: str | None = None, env: dict[str, str] | None = None) -> str | None:
    """Write the loopback-excluding copy of ``source`` (or the default config) to a
    private temp file and return its path; ``None`` when no config can be found."""
    import tempfile
    env = os.environ if env is None else env
    path = source if source and source not in ("1", "default", "on", "yes") else proxychains_conf(env)
    if not path or not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as handle:
        text = managed_conf_text(handle.read())
    fd, out = tempfile.mkstemp(prefix="jsintel-proxychains-", suffix=".conf")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    return out


def chromium_launch(env: dict[str, str] | None = None,
                    conf_text: str | None = None) -> tuple[dict[str, str], list[str]] | None:
    """Environment and extra flags for launching Chromium safely.

    Outside proxychains: the current environment and no flags. Under it: the preload
    is removed from ``LD_PRELOAD`` (Chromium aborts with it) and Chromium is pointed
    at the chain's first proxy with ``--proxy-server`` instead, with local name
    resolution disabled so no DNS query leaks around the proxy. A socks4 entry is
    used as socks5 (Chromium resolves names locally over socks4, which would leak;
    Tor and common SOCKS servers speak both). Returns ``None`` when no usable proxy
    can be derived (missing config, credentials, unsupported type): the caller must
    then skip Chromium rather than let it connect directly.
    """
    base = dict(os.environ if env is None else env)
    if not under_proxychains(base):
        return base, []
    found = chain_proxy(base, conf_text)
    if found is None:
        return None
    scheme, host, port = found
    preload = [p for p in base.get("LD_PRELOAD", "").replace(":", " ").split()
               if "proxychains" not in p]
    if preload:
        base["LD_PRELOAD"] = " ".join(preload)
    else:
        base.pop("LD_PRELOAD", None)
    rules = "MAP * ~NOTFOUND" + (f" , EXCLUDE {host}" if not host.replace(".", "").isdigit() else "")
    return base, [f"--proxy-server={scheme}://{host}:{port}", f"--host-resolver-rules={rules}"]


def main(argv: list[str] | None = None) -> int:
    """``proxy-url`` prints the Go-tool proxy URL (exit 1 if none);
    ``managed-conf [src]`` writes the loopback-excluding config and prints its path."""
    args = sys.argv[1:] if argv is None else argv
    if args[:1] == ["proxy-url"]:
        url = proxy_url()
        if url:
            print(url)
        return 0 if url else 1
    if args[:1] == ["managed-conf"]:
        path = managed_conf(args[1] if len(args) > 1 else None)
        if path:
            print(path)
        return 0 if path else 1
    print("usage: python3 -m modules.proxyutil {proxy-url | managed-conf [conf]}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
