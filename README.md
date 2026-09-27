# JSIntel

JSIntel is a JavaScript-aware **asset intelligence and recon framework** for
**authorized security testing and asset inventory**. Given a scope you are
permitted to assess, it enumerates hosts, discovers web services (including on
non-standard ports), crawls for client-side assets, downloads them with integrity
metadata, extracts intelligence (endpoints, secrets, dangerous sinks, frameworks),
optionally fuzzes for hidden content and screenshots the live services, then rolls
everything into a SQLite-backed set of reports and a single prioritized **triage**
view.

> **Authorization first.** Every active stage (subdomain enumeration, port scan,
> fuzzing, screenshots, crawling) only ever touches hosts inside the
> operator-supplied authorized scope, and off-scope redirects can never widen it.
> Never run JSIntel outside a scope you are authorized to assess.

> Phase 2 is an additive migration to a typed, plugin-based intelligence platform.
> The existing `jsintel.sh` workflow remains compatible while new collection,
> analysis, graph, and reporting capabilities move behind stable interfaces. See
> [Architecture](docs/ARCHITECTURE.md) and the [Plugin Guide](docs/PLUGINS.md).

## Features

- **JavaScript-aware crawling** (Katana) for `.js`, `.mjs`, source maps, JSON,
  WebAssembly, workers, and manifests, with scope-anchored URL normalization.
- **Subdomain enumeration** (`-s`) over an authorized scope, liveness-probed and
  added to the crawl as extra seeds.
- **Web-service port scanning** (`-p`) that finds HTTP(S) services on
  **non-standard ports** (not just 80/443), confirms which speak HTTP, detects CDN
  fronting, and feeds confirmed services into the crawl and fuzzer.
- **Parallel, resumable downloads** with SHA-256, byte size, MIME type, and
  failure/timeout/retry handling.
- **Streaming extraction engine** (`modules/extractor/`) with independently
  discovered analyzer plugins and typed findings: URLs, API/GraphQL-like paths,
  WebSocket URLs, imports/requires, framework signatures, hardcoded secrets, and
  dangerous-sink/taint analysis. Multi-language AST parsing (JS/JSX/TS/TSX) with
  graceful fallback; one bad asset never aborts a scan (`errors.json`).
  Extraction is process-parallel and **size-aware**: a single large bundle is split so
  its heavy analyzers run across workers (the Amdahl bottleneck) — ~1.8× on a run
  dominated by one 1.2 MB bundle. Tune with `JSINTEL_SPLIT_BYTES` (default 200 KB; 0 off).
- **Feedback discovery loop**: after extraction, assets referenced by other extracted
  assets (an endpoint/URL/spec path the crawler never saw) are fetched and re-extracted —
  strictly **on hosts already in scope** (new paths, never a new host), budget-capped and
  bounded by `JSINTEL_DISCOVER_ROUNDS` (default 3; 0 disables) / `JSINTEL_DISCOVER_LIMIT`.
- **Live-service analysis** of the discovered services (runs with `-p`): flags
  missing/weak security headers (CSP, HSTS, X-Frame-Options, …), server-banner
  disclosure, insecure cookies, **GraphQL introspection** exposure, and JWT
  algorithm weaknesses (`alg:none`, symmetric signing) — written to
  `reports/security.json` and folded into the per-host triage.
- **Content-discovery fuzzing** (`-f`), opt-in and scope-gated, that extends
  discovered paths with category-appropriate [Assetnote wordlists](https://wordlists.assetnote.io/)
  (or local [SecLists](https://github.com/danielmiessler/SecLists) when present).
  See [Fuzzing](docs/FUZZING.md).
- **Headless screenshots** (`-w`) of discovered services with near-identical pages
  clustered into a visual-triage gallery (`reports/screenshots.html`).
- **SQLite database** (assets, urls, endpoints, technologies, findings,
  fuzz_results, **services**) with an ad-hoc query interface.
- **Unified triage report** (`reports/triage.{json,html,md}`): one prioritized,
  per-host view that joins services, sensitive endpoints, and findings into a
  single risk score — "here are the hosts that matter and why".
- **Run-to-run diff** (`modules/diff.py`): what changed between two runs — the
  basis for continuous monitoring.
- **Mass sweep** (`-m`): run the whole pipeline across many targets and aggregate.
- Reporting in JSON, Markdown, and CSV.

## Installation

On Kali Linux or Debian:

```bash
chmod +x install.sh jsintel.sh modules/*.sh modules/*.py
./install.sh
```

The installer installs `katana` and `httpx` under `$(go env GOPATH)/bin` — ensure
that directory is on `PATH`. Port scanning uses `nmap` (with optional `naabu`);
screenshots use headless Chromium. Fuzzing uses `ffuf`/`feroxbuster`.

## Usage

Create a scope file with one authorized seed URL per line:

```text
https://app.example.test
https://api.example.test
```

Run the core pipeline:

```bash
./jsintel.sh -i crawled_urls -o target_output -t 50
```

`-i` also accepts a single `http(s)` URL. `-o` defaults to `./output`; `-t`
defaults to the `config/config.yaml` value (50).

### Flags

| Flag | Purpose |
|------|---------|
| `-i <file\|url>` | Seed URLs (one per line) or a single URL. |
| `-o <dir>` | Output directory (default `./output`). |
| `-t <n>` | Concurrent crawl/download workers. |
| `-s <scope>` | Enumerate subdomains of the authorized scope and add reachable ones as seeds. Accepts a domain, comma/space-separated domains, or a `FILE`/`@file`. |
| `-p <scope>` | Port-scan in-scope hosts for web services on non-standard ports; writes `assets/services.txt` and `reports/ports.json`. Override ports with `JSINTEL_PORTS` (e.g. `"80,443,8000-8100"`). |
| `-w` | Screenshot discovered services into a clustered gallery. Pairs with `-p`. |
| `-f <scope>` | Enable content-discovery fuzzing against the authorized scope. Extra options via `JSINTEL_FUZZ_ARGS` (e.g. `--dry-run`, `--offline`). |
| `-m <file>` | **Mass sweep**: run the full pipeline per target into `<output>/targets/<domain>/` and write an aggregate `sweep_summary.{json,md}`. Enable per-target stages with `-S/-P/-W/-F`. |
| `-v` | Verbose: surface tool output and warn about silent failures. |
| `--cookie <value>` | Authenticated mode: send this `Cookie` header (e.g. `"PHPSESSID=…; security=low"`) with every request across all stages. |
| `--jwt <token>` | Authenticated mode: send `Authorization: Bearer <token>` with every request. Combinable with `--cookie`. |

### Authenticated targets

Supply a session so JSIntel crawls, downloads, fuzzes, and analyzes as a logged-in
user. The session is only ever sent to in-scope hosts.

```bash
# e.g. after logging into DVWA and grabbing its PHPSESSID
./jsintel.sh -i http://app.example.test/ -o out \
  -p app.example.test -f app.example.test \
  --cookie "PHPSESSID=<sid>; security=low"

# or a bearer/JWT for an API
./jsintel.sh -i https://api.example.test/ -o out -f api.example.test --jwt "<token>"
```

A supplied `--jwt` is also checked by the live analyzer for a dangerous algorithm
(`alg:none`, symmetric signing).

Example — subdomains + non-standard-port services + fuzz + screenshots:

```bash
./jsintel.sh -i seeds.txt -o target_output \
  -s example.test -p example.test -f example.test -w -v
```

## Output

```text
target_output/
├── assets/
│   ├── crawled_urls.txt
│   ├── services.txt              # discovered web services (with -p)
│   └── 000001_asset.js
├── database/recon.db
├── logs/jsintel.log
└── reports/
    ├── assets.json / assets.csv
    ├── urls.json / endpoints.json / websocket.json / imports.json
    ├── frameworks.json / findings.json / errors.json
    ├── ports.json                # web services (with -p)
    ├── security.json             # live-service findings: headers, GraphQL, JWT (with -p)
    ├── fuzz.json / fuzz_summary.json   # with -f
    ├── screenshots.json / screenshots.html   # with -w
    ├── triage.json / triage.html / triage.md # prioritized per-host view
    ├── summary.json / summary.md
    └── diff.json / diff.md        # when you run modules/diff.py
```

### Start with the triage report

`reports/triage.md` (or `triage.html`) ranks hosts by a risk score combining
finding severity, sensitive-endpoint exposure, and non-standard-port services, so
you see the handful of hosts that matter first.

### Ad-hoc queries

```bash
python3 modules/database.py --output target_output query 'SELECT endpoint FROM endpoints'
```

### Diff two runs

```bash
python3 -m modules.diff last_week_output this_week_output -o this_week_output
cat this_week_output/reports/diff.md    # new/removed hosts, services, endpoints, findings
```

## Testing against a vulnerable lab

A repeatable estate of intentionally-vulnerable apps (Juice Shop, WebGoat/WebWolf,
DVWA, VAmPI, and Damn Vulnerable GraphQL App) — a `/etc/hosts` subdomain tree on
non-standard ports, all bound to loopback — is provided for regression and stress
testing:

```bash
tests/lab/lab.sh up juice webgoat dvwa
sudo tests/lab/lab.sh hosts install
tests/lab/lab.sh seeds > tests/lab/seeds_up.txt
JSINTEL_PORTS="80,443,3000,8081,8082,9090" \
  ./jsintel.sh -i tests/lab/seeds_up.txt -o output_lab_full \
    -p shop.vuln.lab,goat.vuln.lab,dvwa.vuln.lab -w
```

See [`tests/lab/README.md`](tests/lab/README.md) for the full estate and safety
model. Run the unit suite with `python3 -m pytest`.

## Live capture listener (Burp / browser / HTTPToolkit)

Instead of crawling, JSIntel can **ingest traffic a proxy or browser extension already
captured** and run it through the whole pipeline — no re-fetching, since the response
body is in the capture. Start the daemon (loopback-only by default):

```bash
python3 -m modules.listener --output output_live --port 8799   # optional: --token <secret>
```

A ready-made **mitmproxy addon** ships in
[`integrations/mitmproxy/`](integrations/mitmproxy/README.md) — run
`mitmdump -s integrations/mitmproxy/jsintel_mitm.py` and browse an authorized target
through the proxy to stream its traffic straight into the listener. You can also point a
Burp extension, a Firefox devtools/HAR export, HTTPToolkit, or anything else at it:

| Endpoint | Purpose |
|---|---|
| `POST /ingest` | one capture, a JSON array, or a HAR (`{log:{entries}}`) |
| `POST /ws` | one captured **target** WebSocket frame |
| `WS /stream` | stream captures/frames in real time (one JSON message each) |
| `POST /flush` | force the full pipeline over every site now |
| `GET /status` | per-site capture counts + which sites are processing |
| `GET /reports/<site>/<name>` | fetch a produced report, e.g. `triage.json`, for one site |

Native capture shape:

```json
{"type":"http","url":"https://app/x.js","status":200,
 "response_headers":{"content-type":"application/javascript"},
 "response_body":"…", "response_body_b64":false}
{"type":"ws","url":"wss://app/socket","direction":"recv","opcode":"text","payload":"…"}
```

**One site → one directory → one scan.** Every capture is routed to the store for its
**registered domain** (eTLD+1), so `app.site.com/x.js`, `cdn.site.com/y.js`,
`site.com/api`, and the same XHR fired a hundred times all collapse into
`output_live/sites/site.com/` and a *single* scan — never a directory or a scan process
per URL. Each site is (re)scanned in the background once it has been **quiet for
`--debounce` seconds** (coalescing a burst into one run), and `--max-concurrent` caps how
many sites scan at once, so resource use stays flat no matter how chatty the proxy is
(`--group host` keeps every hostname separate instead; `POST /flush` forces a scan now).

The listener is **passive by default** — it analyzes captured bytes and never touches the
target. The content-discovery **fuzzer is opt-in**: pass `--fuzz` and, after each site's
scan, the fuzzer runs **scoped to only the hostnames seen in that site's traffic**, seeded
by the endpoints/URLs just mined, and its hits fold into the DB/reports/triage. This sends
live requests to the captured hosts (reachability from the daemon is the operator's
responsibility); extra fuzzer options pass through with `--fuzz-arg` (e.g.
`--fuzz-arg=--offline --fuzz-arg=--max-words=200`, or `--fuzz-arg=--dry-run` to only plan).

**`--aggressive` flow recording.** With `--aggressive`, each *distinct* request/response
flow is recorded and deduped so the extractor→fuzzer/crawler cycle never re-processes the
same flow. A flow's identity is `method + normalized URL (sorted query) + request body +
auth headers` (`Authorization`/`Cookie`/`Content-Type`/…) — volatile headers like
`User-Agent` are ignored, so a repeat of the *same* logical request is skipped. Each new
flow is written under a nested tree:

```text
assets/flows/<host>/<path…>/<METHOD>/<reqhash>/
├── request_<reqhash>.txt        # raw request line + headers + body
├── response_<resphash>.raw      # one per DISTINCT response the flow returned
├── screenshot_<resphash>.png    # offline render of page/HTML responses (needs Chromium)
└── meta.json                    # url, method, timestamps, responses[]
assets/flows/anomaly.txt         # <iso-ts>\t<response path>\t<url> per response-hash change
```

When a flow that was seen before returns a response whose hash **differs**, the new
response is kept alongside the old one and a line is appended to `assets/flows/anomaly.txt`
— a cheap way to catch a page/endpoint whose behaviour changed between captures.
Screenshots are rendered offline from the captured body (no extra traffic) and are skipped
silently if Chromium is not installed.

The flow ledger is **persisted** to `assets/flows/ledger.json` and rehydrated on startup, so
dedup and anomaly detection survive daemon restarts and span sessions — capture the same
estate over days and a response that changes between runs is flagged even across a restart.

Anomaly classification is **secret-aware and multi-signal**, in this order:

1. **Secrets first** — the response body is scanned for hardcoded secrets, and those
   fingerprints feed the comparison, so a **newly-appearing secret is always a change**
   (never masked away as noise) and is flagged **high severity** (`new_secret`).
2. **Noise-masked signature** — the rest of the body is normalized (anti-CSRF tokens,
   CSP/script nonces, session ids, timestamps) and high-entropy tokens (build ids, random
   handles) are masked, so a page that only rotated a token is *not* a false anomaly.
3. **Image tie-breaker** — for an ambiguous HTML change, the response is rendered offline
   and compared to the prior render's perceptual hash; if it looks identical, the anomaly
   is suppressed. Rendering happens only in that uncertain case (raw bytes are always kept
   as evidence). Pass `--anomaly-raw` to compare raw bytes with no masking.

Each anomaly stores a **unified diff** (and, for JSON, a **semantic** added/removed/changed
key diff) in the flow dir, appends a line to `anomaly.txt`, and is written to
`reports/anomalies.json` — which the DB ingests as a `response_anomaly` finding so it
**ranks per host in triage** (a new secret in a changed response scores high).

Each capture is classified (strong code extensions `.js/.mjs/.map/.wasm` win over a
mislabeled content-type — servers routinely serve JS as `text/html`/`octet-stream` —
otherwise the content-type is authoritative, then a URL fallback), the body is analyzed
by the full extractor (JS AST + page + tech-fingerprint + cloud + source-map), and the
**request side is mined too**: the request URL with its **URL-decoded query values**
(so a token or URL hidden in `?next=https%3A%2F%2F…` / `?token=…` is surfaced, not left
as opaque escapes) and the **request/response headers** (`Authorization`, `Cookie`,
`X-Api-Key`, `Set-Cookie`, `Location`, …) are flattened into a page pseudo-asset so the
URL/endpoint and secret analyzers pull URLs, API paths and hardcoded secrets out of them
as well as out of bodies. Response **headers** also get a passive security-header pass,
any captured **OpenAPI/Swagger** spec has its paths harvested as endpoints, **XHR/fetch
JSON bodies** and WebSocket text frames are mined too, and the result flows to the DB,
reporter, and per-host `triage`. Set `JSINTEL_LISTEN_TOKEN` (or `--token`) to require `X-JSIntel-Token`
on every request. It binds `127.0.0.1` by default — never expose it, as captures may
contain sensitive traffic.

## Project layout

```text
jsintel/
├── jsintel.sh                 # Pipeline launcher / orchestrator
├── install.sh                 # Debian/Kali dependency installation
├── modules/                   # crawl, classify, download, extract, fuzz,
│   │                          #   portscan, webshot, database, reporter, triage, diff, listener
│   └── extractor/             # streaming extraction engine + analyzer plugins
├── database/schema.sql        # SQLite schema (incl. services table)
├── config/config.yaml         # Runtime defaults
├── tests/                     # pytest suite (+ tests/lab/ vulnerable-target lab)
├── docs/                      # Architecture, Configuration, Development, Fuzzing, Plugins
└── output/                    # Default runtime output root
```

## Notes

The crawler uses Katana when installed; without it, supplied HTTP URLs are recorded
as candidate assets (useful for offline/constrained environments but without page
crawling). Downloads are limited to discovered HTTP(S) URLs and saved with
sanitized filenames.
