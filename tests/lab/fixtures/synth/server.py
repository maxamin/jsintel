#!/usr/bin/env python3
"""Synthetic multi-host estate for mass-sweep stress testing.

One threaded HTTP server bound to a single loopback IP that answers *per Host
header*, so N synthetic hostnames (all mapped to this IP in /etc/hosts) look like N
distinct vulnerable sites to JSIntel's mass-sweep mode. Each host serves a small,
representative surface: links + a form (no CSRF token) + an injectable query param,
a JS bundle with a planted secret and a sourceMappingURL, that bundle's source map
(secret hidden in sourcesContent), an OpenAPI spec, and an exposed /.git/config.

Loopback-only by construction. Usage: server.py <bind-ip> <port> [host-count]
"""
import sys
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.10"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80

_MAP = json.dumps({
    "version": 3, "sources": ["src/secrets.js"],
    "sourcesContent": ["const AWS_ACCESS_KEY_ID='AKIAIOSFODNN7EXAMPLE';\n"
                       "fetch('https://api.internal.synth/api/v3/private');\n"],
    "names": [], "mappings": "", "file": "app.js",
})
_SPEC = json.dumps({"openapi": "3.0.0", "info": {"title": "synth"},
                    "paths": {"/api/v1/users": {}, "/api/v1/login": {}, "/api/v1/_debug": {}}})


def _index(host: str) -> bytes:
    return (f"""<!doctype html><html><head><title>{host}</title>
<meta name="generator" content="SynthCMS 2.1"></head><body>
<a href="/admin/">admin</a> <a href="/api/v1/users">users</a>
<a href="/vulnerabilities/sqli/?id=1">sqli</a> <a href="/download?file=report.pdf">dl</a>
<script src="/app.js"></script>
<form action="/login" method="POST"><input name="user"><input name="pass"></form>
<!-- TODO remove /backup/{host}.sql before launch -->
</body></html>""").encode()


def _appjs() -> bytes:
    return (b"var a='AKIA',b='IOSFODNN7',c='EXAMPLE';var key=a+b+c;\n"
            b"fetch('/api/v2/orders');new WebSocket('wss://synth/ws');\n"
            b"//# sourceMappingURL=/app.js.map\n")


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "SynthServer/1.0")  # banner disclosure signal
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        host = (self.headers.get("Host") or "synth").split(":")[0]
        p = self.path.split("?", 1)[0]
        if p == "/" or p == "/index.html":
            self._send(200, _index(host))
        elif p == "/app.js":
            self._send(200, _appjs(), "application/javascript")
        elif p == "/app.js.map":
            self._send(200, _MAP.encode(), "application/json")
        elif p == "/openapi.json":
            self._send(200, _SPEC.encode(), "application/json")
        elif p == "/.git/config":
            self._send(200, b"[core]\n\trepositoryformatversion = 0\n", "text/plain")
        elif p in ("/api/v1/users", "/api/v2/orders", "/admin/", "/login"):
            self._send(200, b'{"ok":true}', "application/json")
        else:
            self._send(404, b"not found")

    do_HEAD = do_GET
    do_POST = do_GET


if __name__ == "__main__":
    srv = ThreadingHTTPServer((BIND, PORT), H)
    print(f"synth server on {BIND}:{PORT}", flush=True)
    srv.serve_forever()
