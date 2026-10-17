# Capture listener (`modules/listener.py`) and the mitmproxy addon

## What it is
A loopback `ThreadingHTTPServer` daemon (`python3 -m modules.listener --output DIR --port 8799`)
that receives captured HTTP exchanges and WebSocket frames pushed from Burp, browser HAR
exports, HTTPToolkit, or mitmproxy. It runs the **existing** pipeline over them without
re-fetching anything: classify → extract → passive live analysis → DB ingest →
reporter → triage. It is passive by default.

## Endpoints
`POST /ingest` (one capture, a list, or a HAR `{log:{entries}}`), `POST /ws` (one frame),
`POST /flush` (process every site now), `GET /status`, `GET /reports/<site>/<name>`, and
`WS /stream`. If `JSINTEL_LISTEN_TOKEN` or `--token` is set, every request must carry
`X-JSIntel-Token`.

Native capture shape:
```json
{"type":"http","url":"...","method":"GET","status":200,"request_headers":{},"response_headers":{"content-type":"..."},"response_body":"...","response_body_b64":false}
{"type":"ws","url":"wss://...","direction":"recv","opcode":"text","payload":"..."}
```

## Key components
- `site_key` groups captures per registered domain (`--group regdom`, the default) or
  per host. `SiteRegistry` routes each capture to one `CaptureStore` per site, so there
  is one output dir per site. A debounce loop (`--debounce 2s`) and
  `--max-concurrent 2` coalesce bursts into a few scans.
- `classify(url, content_type)`: **strong code extensions (.js, .mjs, .map, .wasm) beat a
  mislabeled content-type.** Charset params, casing, `+json`, and query/fragment
  stripping are handled, as are misleading paths (`/track.js/pixel`, `?to=/app.js`).
  Heavily tested in `tests/test_listener.py`.
- `capture_intel_text` mines the **whole HTTP stream**: it flattens the URL,
  URL-decoded (including double-encoded) query values, and selected request/response
  headers (`Authorization`, `X-Api-Key`, `Cookie`, `Set-Cookie`, `Location`,
  `Referer`, `Link`) into a quoted text blob. That blob is fed in as a `page`
  pseudo-asset, so PageAnalyzer and SecretsAnalyzer are reused without new extractors.
- `--fuzz` (opt-in) runs the fuzzer scoped to **only the hostnames seen in that site's
  captures**. `--forms` likewise runs the forms stage. `--fuzz-arg` and `--forms-arg`
  pass options through. `--proxychains` re-execs under proxychains.

## `--aggressive`: FlowRecorder and the anomaly engine
- `flow_key` = sha256(method + normalized URL (lower host, sorted query) + body + auth
  headers). Each distinct flow gets recorded under `assets/flows/<site>/...` as raw
  request, raw response, and meta. The ledger is persisted atomically, so dedup and
  anomaly detection survive restarts.
- Order inside `record()`: (1) fingerprint the response's secrets first
  (`secrets_analyzer.scan_text`). (2) Build a signature from the normalized body
  (`normalize_for_anomaly` masks CSRF tokens, nonces, session ids, and timestamps with
  bounded regexes), mask high-entropy runs (`_HE_RE`), and add the secret
  fingerprints. A new secret always changes the signature even though random tokens
  are masked. (3) When the signature differs for the same flow key, record an anomaly
  in `anomaly.txt`, `reports/anomalies.json`, a unified diff, and a JSON semantic diff
  (`_json_semantic_diff`). Optionally the HTML is rendered offline to a pHash so
  visual changes can be compared.
- `--anomaly-raw` switches to strict byte comparison.
- `database.py` ingests anomalies as `response_anomaly` findings. One that adds a
  secret is high severity.
- **Truthfulness rule:** validate change detection against genuinely dynamic pages
  (fetch DVWA login twice, where `user_token` rotates, and expect no anomaly) and
  against real state changes (VAmPI: `GET /createdb`, snapshot `GET /users/v1`,
  `POST /users/v1/register`, snapshot again, and expect an anomaly).

## mitmproxy addon (`integrations/mitmproxy/jsintel_mitm.py`)
```bash
python3 -m modules.listener --output output_live --port 8799 [--aggressive --fuzz --token T]
JSINTEL_LISTEN_URL=http://127.0.0.1:8799 JSINTEL_SCOPE=example.com \
  mitmdump -q --listen-host 127.0.0.1 --listen-port 8080 -s integrations/mitmproxy/jsintel_mitm.py
```
`build_http_capture` sends text bodies as text and binary bodies as base64. `in_scope`
uses the pipeline's dotted-suffix rule (host equals an entry or is a subdomain of one;
single-label entries match only exactly; scope set but all entries invalid matches
nothing), and an empty scope means everything. `post_capture` is best-effort and never
raises into the proxy loop. Tests: `tests/test_mitm_addon.py`.
