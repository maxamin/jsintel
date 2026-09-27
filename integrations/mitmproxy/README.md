# JSIntel × mitmproxy

Stream everything you browse through [mitmproxy](https://mitmproxy.org/) into the JSIntel
listener, so the full pipeline (classify → extract → live analysis → DB → triage, plus
optional `--fuzz` / `--aggressive`) runs on real captured traffic — no re-fetching.

## Use

```bash
# 1) start the JSIntel listener (loopback)
python3 -m modules.listener --output output_live --port 8799
#    (add --aggressive / --fuzz / --token as needed)

# 2) run mitmproxy with the addon (proxy on :8080 by default)
JSINTEL_LISTEN_URL=http://127.0.0.1:8799 \
JSINTEL_SCOPE=example.com,api.example.com \
  mitmdump -q --listen-host 127.0.0.1 --listen-port 8080 \
    -s integrations/mitmproxy/jsintel_mitm.py

# 3) point your browser / tool at the proxy and browse the authorized target
curl -x http://127.0.0.1:8080 http://app.example.com/
```

For HTTPS targets, install mitmproxy's CA in the client (see mitmproxy docs) so it can
see decrypted bodies.

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `JSINTEL_LISTEN_URL` | `http://127.0.0.1:8799` | Listener base URL. |
| `JSINTEL_LISTEN_TOKEN` | — | Sent as `X-JSIntel-Token` when the listener requires auth. |
| `JSINTEL_SCOPE` | *(empty = all)* | Comma/space hosts to stream (substring match). **Set this** to avoid streaming third-party traffic. |

## What it sends

- Every HTTP response → `POST /ingest` as a native capture (`url`, `method`, request +
  response headers, request/response body; binary bodies base64-encoded with `*_body_b64`).
- Every WebSocket message → `POST /ws`.

Posts run on a small background thread pool so proxying stays responsive; a listener
outage never breaks browsing (failures are logged and dropped).

> **Authorization.** Only proxy and stream hosts you are authorized to assess. Use
> `JSINTEL_SCOPE` to keep off-scope traffic out, and keep the listener on loopback.
