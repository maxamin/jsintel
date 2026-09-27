#!/usr/bin/env python3
"""JSIntel capture streamer for mitmproxy.

Load it into mitmproxy/mitmdump to stream every request/response (and WebSocket
message) it proxies straight into the JSIntel listener's ``/ingest`` (``/ws``),
so the whole pipeline runs on live traffic you browse through the proxy — no
re-fetching, since the body is already in the flow.

    # 1) start the JSIntel listener (loopback)
    python3 -m modules.listener --output output_live --port 8799

    # 2) run mitmproxy with this addon (proxy on :8080 by default)
    JSINTEL_LISTEN_URL=http://127.0.0.1:8799 \\
    JSINTEL_SCOPE=example.com,api.example.com \\
      mitmdump -s integrations/mitmproxy/jsintel_mitm.py

    # 3) point your browser / curl at the proxy
    curl -x http://127.0.0.1:8080 http://app.example.com/

Config (environment variables):
    JSINTEL_LISTEN_URL    listener base URL          (default http://127.0.0.1:8799)
    JSINTEL_LISTEN_TOKEN  X-JSIntel-Token, if the listener requires auth
    JSINTEL_SCOPE         comma/space hosts to stream (substring match); empty = all

This module intentionally does NOT import mitmproxy, so its serialization helpers
are unit-testable with plain Python; mitmproxy calls the hook methods by name.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor

LOG = logging.getLogger("jsintel_mitm")

# Content types whose bodies are text (sent as-is); everything else is base64-encoded
# so binary bodies survive the JSON transport (the listener understands *_body_b64).
_TEXTY = ("text/", "application/json", "application/javascript", "application/ecmascript",
          "application/xml", "application/xhtml", "application/x-www-form-urlencoded",
          "image/svg", "+json", "+xml")


def _is_texty(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return any(t in ct for t in _TEXTY)


def _encode_body(raw: bytes | None, content_type: str) -> tuple[str, bool]:
    """Return (body_str, is_base64). Text stays text; binary/undecodable -> base64."""
    if not raw:
        return "", False
    if _is_texty(content_type):
        try:
            return raw.decode("utf-8"), False
        except UnicodeDecodeError:
            pass
    return base64.b64encode(raw).decode("ascii"), True


def build_http_capture(url: str, method: str, req_headers: dict, req_body: bytes | None,
                       status: int, resp_headers: dict, resp_body: bytes | None) -> dict:
    """Build a JSIntel native HTTP capture from decoded request/response parts."""
    rb, rb64 = _encode_body(resp_body, resp_headers.get("content-type", ""))
    qb, qb64 = _encode_body(req_body, req_headers.get("content-type", ""))
    cap = {"type": "http", "url": url, "method": (method or "GET").upper(), "status": status,
           "request_headers": req_headers, "response_headers": resp_headers,
           "response_body": rb, "response_body_b64": rb64}
    if qb:
        cap["request_body"] = qb
        cap["request_body_b64"] = qb64
    return cap


def build_ws_capture(url: str, from_client: bool, content: bytes) -> dict:
    """Build a JSIntel WebSocket-frame capture from a proxied message."""
    try:
        payload, opcode = content.decode("utf-8"), "text"
    except (UnicodeDecodeError, AttributeError):
        payload, opcode = base64.b64encode(content or b"").decode("ascii"), "binary"
    return {"type": "ws", "url": url, "direction": "send" if from_client else "recv",
            "opcode": opcode, "payload": payload}


def in_scope(host: str, scope: list[str]) -> bool:
    """True if host matches any scope entry (substring), or scope is empty (= all)."""
    if not scope:
        return True
    h = (host or "").lower()
    return any(s.lower() in h for s in scope)


def post_capture(endpoint: str, obj: dict, token: str | None, timeout: float = 15.0) -> bool:
    """POST one capture to the listener. Best-effort: never raise into the proxy loop."""
    data = json.dumps(obj).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-JSIntel-Token"] = token
    try:
        req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")
        urllib.request.urlopen(req, timeout=timeout).read()
        return True
    except Exception as ex:  # noqa: BLE001 - a listener hiccup must not break browsing
        LOG.warning("jsintel: post to %s failed: %s", endpoint, ex)
        return False


def _headers_to_dict(headers) -> dict:
    """mitmproxy Headers (or any items()-able) -> {lowercased-name: value}."""
    try:
        return {str(k).lower(): str(v) for k, v in headers.items()}
    except Exception:  # noqa: BLE001
        return {}


class JSIntelStreamer:
    """mitmproxy addon: stream proxied HTTP/WebSocket traffic to the JSIntel listener."""

    def __init__(self) -> None:
        self.base = os.environ.get("JSINTEL_LISTEN_URL", "http://127.0.0.1:8799").rstrip("/")
        self.token = os.environ.get("JSINTEL_LISTEN_TOKEN") or None
        self.scope = [s for s in re.split(r"[,\s]+", os.environ.get("JSINTEL_SCOPE", "")) if s]
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="jsintel-mitm")
        self.sent = 0
        LOG.info("jsintel: streaming to %s (scope=%s, auth=%s)",
                 self.base, self.scope or "ALL", "on" if self.token else "off")

    def _send(self, path: str, obj: dict) -> None:
        self.sent += 1
        self.pool.submit(post_capture, self.base + path, obj, self.token)

    # -- mitmproxy hooks (called by name; flow is duck-typed) ----------------
    def response(self, flow) -> None:  # noqa: ANN001
        req, resp = flow.request, flow.response
        if resp is None or not in_scope(req.pretty_host, self.scope):
            return
        try:
            req_body = req.raw_content if req.raw_content is not None else req.content
        except Exception:  # noqa: BLE001
            req_body = None
        try:
            resp_body = resp.content  # decoded (de-gzipped) body bytes
        except Exception:  # noqa: BLE001
            resp_body = resp.raw_content
        cap = build_http_capture(req.pretty_url, req.method, _headers_to_dict(req.headers),
                                 req_body, resp.status_code, _headers_to_dict(resp.headers), resp_body)
        self._send("/ingest", cap)

    def websocket_message(self, flow) -> None:  # noqa: ANN001
        if not in_scope(flow.request.pretty_host, self.scope):
            return
        msg = flow.websocket.messages[-1]
        self._send("/ws", build_ws_capture(flow.request.pretty_url, msg.from_client, msg.content))

    def done(self) -> None:
        self.pool.shutdown(wait=True)
        LOG.info("jsintel: streamed %d captures", self.sent)


addons = [JSIntelStreamer()]
