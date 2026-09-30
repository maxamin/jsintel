"""Best-effort headless-Chromium driver: trigger client-side JS and capture XHR.

This is JSIntel's *AJAX Spider* path. It loads a page in headless Chromium (spoken
to over the Chrome DevTools Protocol via a minimal stdlib WebSocket client — no
Playwright/Selenium dependency), instruments ``XMLHttpRequest``/``fetch``/
``WebSocket``/``sendBeacon`` before any script runs, fills every form field with the
synthesized values, dispatches ``input``/``change``/``blur`` and ``click``/
``submit`` events so the app's own handlers fire, and reads back the requests those
handlers made — endpoints a passive crawl never sees.

Everything that does not need a live browser (the instrumentation script, the
capture-parsing) is a plain function so it is unit-testable without Chromium; the
transport is thin and the whole thing is gracefully skipped when Chromium is
absent or unreachable.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

try:
    from modules.webshot import find_chromium
except Exception:  # pragma: no cover - webshot import is trivial
    def find_chromium(explicit: str = "") -> str:  # type: ignore
        import shutil
        for name in ("chromium", "chromium-browser", "google-chrome", "chrome"):
            p = shutil.which(explicit or name)
            if p:
                return p
        return ""


# =============================================================================
# Instrumentation script (pure string builder -> unit-testable)
# =============================================================================
def build_instrumentation_js() -> str:
    """JS injected before page scripts: hook network APIs into ``window.__jsintel``.

    Records every XHR/fetch/WebSocket/sendBeacon call as {method,url,body} so the
    driver can read the endpoints the page's JavaScript talked to.
    """
    return r"""
(function(){
  if (window.__jsintel) return;
  var log = []; window.__jsintel = {net: log};
  function push(method, url, body){
    try {
      var u = String(url);
      try { u = new URL(u, location.href).href; } catch(e){}  // resolve to absolute
      log.push({method: String(method||'GET').toUpperCase(),
                url: u, body: body ? String(body).slice(0,2048) : ''});
    } catch(e){}
  }
  var _open = XMLHttpRequest.prototype.open, _send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(m,u){ this.__jm=m; this.__ju=u; return _open.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function(b){ push(this.__jm, this.__ju, b); return _send.apply(this, arguments); };
  if (window.fetch){ var _f = window.fetch; window.fetch = function(i, init){
    try { var u = (i && i.url) ? i.url : i; var m = (init && init.method) || (i && i.method) || 'GET';
          push(m, u, init && init.body); } catch(e){}
    return _f.apply(this, arguments); }; }
  if (window.WebSocket){ var _W = window.WebSocket; window.WebSocket = function(u, p){
    push('WS', u, ''); return new _W(u, p); }; window.WebSocket.prototype = _W.prototype; }
  if (navigator.sendBeacon){ var _b = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function(u, d){ push('BEACON', u, d); return _b(u, d); }; }
})();
"""


def build_fill_and_trigger_js(fill_map: dict[str, str], submit: bool,
                              deny_source: str) -> str:
    """JS that fills fields by name from ``fill_map`` and fires events / submits.

    ``fill_map`` maps a field *name* to the value to type. Events are dispatched so
    frameworks (React/Vue/Angular) that listen on ``input``/``change`` react. When
    ``submit`` is true, forms whose action does not match ``deny_source`` (a RegExp
    source string) are submitted and any submit/primary buttons clicked.
    """
    return (
        "(function(){\n"
        "  var values = " + json.dumps(fill_map) + ";\n"
        "  var deny = new RegExp(" + json.dumps(deny_source) + ", 'i');\n"
        "  var doSubmit = " + ("true" if submit else "false") + ";\n"
        "  function setVal(el, v){\n"
        "    try {\n"
        "      var tag = el.tagName.toLowerCase(), t = (el.type||'').toLowerCase();\n"
        "      if (t==='checkbox' || t==='radio'){ el.checked = true; }\n"
        "      else if (tag==='select'){ if (el.options.length) el.selectedIndex = Math.max(0, el.options.length-1); }\n"
        "      else { el.value = v; }\n"
        "      ['input','change','blur','keyup'].forEach(function(ev){\n"
        "        el.dispatchEvent(new Event(ev, {bubbles:true})); });\n"
        "    } catch(e){}\n"
        "  }\n"
        "  var filled = 0;\n"
        "  document.querySelectorAll('input,select,textarea').forEach(function(el){\n"
        "    if (el.disabled) return; var n = el.name || el.id;\n"
        "    var v = values[el.name] != null ? values[el.name] : values[el.id];\n"
        "    if (v == null) v = 'test' + Math.floor(Math.random()*1000);\n"
        "    setVal(el, v); filled++;\n"
        "  });\n"
        "  var submitted = 0;\n"
        "  if (doSubmit){\n"
        "    document.querySelectorAll('form').forEach(function(f){\n"
        "      var action = f.action || location.href; if (deny.test(action)) return;\n"
        "      try {\n"
        "        var btn = f.querySelector('button[type=submit],input[type=submit],button:not([type])');\n"
        "        if (btn){ btn.click(); } else { f.requestSubmit ? f.requestSubmit() : f.submit(); }\n"
        "        submitted++;\n"
        "      } catch(e){}\n"
        "    });\n"
        "    document.querySelectorAll('button,[role=button],a[href^=\"#\"]').forEach(function(b){\n"
        "      try { if (!deny.test((b.getAttribute('href')||'') + (b.textContent||''))) b.click(); } catch(e){}\n"
        "    });\n"
        "  }\n"
        "  return {filled: filled, submitted: submitted};\n"
        "})();"
    )


def parse_captured(net_log) -> list[dict]:
    """Normalize the ``window.__jsintel.net`` array into unique endpoint records."""
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for e in net_log or []:
        if not isinstance(e, dict):
            continue
        url = str(e.get("url") or "").strip()
        method = str(e.get("method") or "GET").upper()
        if not url or url.startswith(("data:", "blob:", "javascript:")):
            continue
        key = (method, url.split("#", 1)[0])
        if key in seen:
            continue
        seen.add(key)
        rec = {"method": method, "url": url}
        if e.get("body"):
            rec["body"] = str(e["body"])[:2048]
        out.append(rec)
    return out


# =============================================================================
# Minimal CDP-over-WebSocket transport
# =============================================================================
def _ws_key() -> str:
    return base64.b64encode(os.urandom(16)).decode()


class _WS:
    """A tiny synchronous WebSocket client (client frames masked, text only)."""

    def __init__(self, url: str, timeout: float = 20.0):
        parts = urlsplit(url)
        self.sock = socket.create_connection((parts.hostname, parts.port), timeout=timeout)
        self.sock.settimeout(timeout)
        path = parts.path + (("?" + parts.query) if parts.query else "")
        handshake = (
            f"GET {path} HTTP/1.1\r\nHost: {parts.hostname}:{parts.port}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {_ws_key()}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(handshake.encode())
        self._buf = b""
        # Read past the 101 handshake response headers.
        while b"\r\n\r\n" not in self._buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("websocket handshake failed")
            self._buf += chunk
        self._buf = self._buf.split(b"\r\n\r\n", 1)[1]

    def send(self, text: str) -> None:
        payload = text.encode()
        header = bytearray([0x81])  # FIN + text
        n = len(payload)
        mask = os.urandom(4)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def _read(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("websocket closed")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def recv(self) -> str:
        b0, b1 = self._read(2)
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._read(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._read(8))[0]
        data = self._read(length)  # server->client frames are not masked
        return data.decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


@dataclass
class DriveResult:
    url: str
    ok: bool = False
    reason: str = ""
    filled: int = 0
    submitted: int = 0
    endpoints: list[dict] = dc_field(default_factory=list)

    def to_record(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in ("", None, [], 0) or k in ("ok",)}


class CDPSession:
    """Correlated CDP command channel over one page target's WebSocket."""

    def __init__(self, ws_url: str, timeout: float = 20.0):
        self.ws = _WS(ws_url, timeout)
        self._id = 0
        self.timeout = timeout

    def call(self, method: str, params: dict | None = None, wait: bool = True):
        self._id += 1
        mid = self._id
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        if not wait:
            return None
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == mid:
                return msg.get("result", {})
        raise TimeoutError(f"CDP call timed out: {method}")

    def close(self):
        self.ws.close()


def _launch_chromium(chromium: str, user_dir: Path, extra_args: list[str]) -> tuple[subprocess.Popen, int]:
    """Start headless Chromium with remote debugging; return (proc, port)."""
    cmd = [chromium, "--headless=new", "--no-sandbox", "--disable-gpu",
           "--remote-debugging-port=0", "--remote-allow-origins=*",
           "--disable-dev-shm-usage", f"--user-data-dir={user_dir}", *extra_args, "about:blank"]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    port_file = user_dir / "DevToolsActivePort"
    for _ in range(100):  # up to ~10s for the port file to appear
        if port_file.is_file():
            try:
                return proc, int(port_file.read_text().splitlines()[0])
            except (ValueError, IndexError):
                pass
        if proc.poll() is not None:
            raise RuntimeError("chromium exited before opening a debug port")
        time.sleep(0.1)
    raise TimeoutError("chromium did not report a debug port")


def _open_target(base: str, timeout: float) -> dict:
    """Open a new DevTools page target (PUT, then POST, then reuse an existing one)."""
    for method in ("PUT", "POST"):
        try:
            req = Request(f"{base}/json/new?about:blank", method=method)
            return json.loads(urlopen(req, timeout=timeout).read())
        except Exception:
            continue
    # Fall back to whatever page target already exists (the launch about:blank).
    targets = json.loads(urlopen(f"{base}/json", timeout=timeout).read())
    for t in targets:
        if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
            return t
    raise RuntimeError("no debuggable page target available")


def drive_page(url: str, fill_map: dict[str, str], *, submit: bool = True,
               headers: dict[str, str] | None = None, chromium: str = "",
               deny_source: str = "", timeout: float = 25.0,
               settle: float = 2.5) -> DriveResult:
    """Load ``url`` in headless Chromium, fill+trigger, and return captured endpoints.

    Best-effort: any failure (no Chromium, launch error, CDP error) returns a
    :class:`DriveResult` with ``ok=False`` and a reason rather than raising.
    """
    res = DriveResult(url=url)
    chromium = chromium or find_chromium()
    if not chromium:
        res.reason = "chromium not found"
        return res
    if urlsplit(url).scheme not in ("http", "https"):
        res.reason = f"non-http url ({url!r})"
        return res

    tmp = Path(tempfile.mkdtemp(prefix="jsintel-forms-"))
    proc = None
    try:
        proc, port = _launch_chromium(chromium, tmp, [])
        base = f"http://127.0.0.1:{port}"
        # Open a fresh tab and grab its debugger websocket. Newer Chromium requires
        # PUT for /json/new; fall back to the existing about:blank target on refusal.
        info = _open_target(base, timeout)
        sess = CDPSession(info["webSocketDebuggerUrl"], timeout=timeout)
        try:
            sess.call("Page.enable")
            sess.call("Runtime.enable")
            sess.call("Network.enable")
            if headers:
                sess.call("Network.setExtraHTTPHeaders", {"headers": headers})
            # Instrument BEFORE navigation so hooks catch first-load XHR/fetch.
            sess.call("Page.addScriptToEvaluateOnNewDocument", {"source": build_instrumentation_js()})
            sess.call("Page.navigate", {"url": url})
            time.sleep(min(settle, timeout))
            fill_js = build_fill_and_trigger_js(fill_map, submit, deny_source or "(?!)")
            r = sess.call("Runtime.evaluate", {"expression": fill_js, "returnByValue": True})
            rv = (r or {}).get("result", {}).get("value") or {}
            res.filled = int(rv.get("filled", 0))
            res.submitted = int(rv.get("submitted", 0))
            time.sleep(min(settle, timeout))  # let triggered XHR fire
            got = sess.call("Runtime.evaluate",
                            {"expression": "JSON.stringify((window.__jsintel&&window.__jsintel.net)||[])",
                             "returnByValue": True})
            raw = (got or {}).get("result", {}).get("value") or "[]"
            res.endpoints = parse_captured(json.loads(raw))
            res.ok = True
        finally:
            sess.close()
    except Exception as ex:
        res.reason = f"{type(ex).__name__}: {ex}"
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    return res
