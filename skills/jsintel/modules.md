# File-by-file reference

Paths are relative to the repo root. LOC numbers are approximate and show relative
weight. "CLI" means the file runs standalone as `python3 -m modules.X` or `python3 modules/X.py`.

## Root

| File | Purpose |
|---|---|
| `jsintel.sh` (246) | Orchestrator. Pre-parses long options (`--cookie --jwt --forms --proxychains`), then getopts. Computes `CRAWL_SCOPE` and runs the stages in order (see architecture.md). `-m` delegates to `modules/sweep.sh`. |
| `install.sh` | apt-installs python3, jq, curl, sqlite3, golang, proxychains4, nmap, chromium. pip installs `requirements.txt`. `go install` katana and httpx. |
| `requirements.txt`, `pyproject.toml` | requests, PyYAML, bs4, tree-sitter(+javascript, +typescript), playwright, rich. pytest config: `testpaths=tests`, `norecursedirs` includes `runtime`. ruff line length 100. mypy strict on `src`. Version 0.2.0. |
| `config/config.yaml` | `threads: 50`, `crawler.depth: 5`, `download.{timeout:15, retries:3, max_seconds:90, max_bytes:25MiB}`, `database.path` (ignored: the DB always lives at `<out>/database/recon.db`). |
| `.gitignore` | Ignores `output_*/`, `*.log`, `domains.txt`, `urls`, `seeds.txt`, `howhold`, `ether_fi_runs/`, `.claude/`, and `tests/lab/runtime/`. These hold real-target data. Never commit them. |
| `domains.txt` (36k lines), `seeds.txt`, `urls`, `howhold` | Operator's target and seed lists. Untracked. **Never delete them.** |
| `output_*/`, `output_deep*/`, `ether_fi_runs/`, `sweep_2026-10-09/` (≈10.2k targets) | Historical run results. Untracked. **Never delete them.** They serve as FP-analysis corpora. |

## `modules/` — shell stages

| File | Purpose / key facts |
|---|---|
| `utils.sh` | Sourced helpers: `log/log_info/log_warn/log_error` (UTC, also appended to `$LOG_FILE`), `die`, `require_command`, `config_value KEY FALLBACK` (top-level YAML scalars only; nested keys are read with inline awk in each script). |
| `crawler.sh` | Reads the seeds, then resolves redirects with `curl -L` (carrying auth). An off-scope redirect is not followed when the scope is anchored. Scope = `CRAWL_SCOPE`, or the eTLD+1 of the post-redirect seeds (`reg_dom`, which passes IPs through unchanged). Runs `katana -list -d DEPTH -jc -jsl -silent -c THREADS -cs <scope regex> </dev/null` under `ulimit -v` (`JSINTEL_KATANA_MAX_VMEM_MB`, 8192). `-cs` is built from the scope hosts (host or subdomain, any port); without it katana follows its own default, the seed's whole registered domain. A non-zero katana exit is logged as a warning (partial crawl). When authenticated it adds `-H Cookie/Authorization` and `-cos` with the logout regex. `clean_and_scope` unescapes `\/`, drops backslash/`%5c` URLs, keeps `ASSET_RE` (js, mjs, map, json, wasm, worker, manifest) plus `PAGE_RE` (php, asp, jsp, html, cgi..., `/`-ending and extensionless routes; disable with `JSINTEL_CRAWL_PAGES=0`), then scope-filters with awk. `repair_repeated_segments` (awk, two-pass) rebuilds URLs whose path repeats a two-segment block (katana chunk mis-resolution). It takes the tail from the block's last occurrence, under the prefix a well-formed URL on the same origin uses for that block (e.g. `/_next/`), and drops the URL when no such prefix exists. katana also gets `-ct $JSINTEL_CRAWL_DURATION` (15m) and `-proxy $JSINTEL_PROXY_URL` under proxychains (not for all-loopback seeds). |
| `classifier.sh` | Inline Python `classify(url)`. Order: `.js/.mjs`→javascript, `.map`→source_map, `.wasm`→webassembly, manifest→manifest, worker path→worker, `.json`→configuration, page extensions or extensionless→page, else other. Adds a `<bundle>.js.map` candidate for each JS asset (`JSINTEL_MAP_DISCOVERY=0` disables). Writes `reports/assets.json`. |
| `downloader.sh` | Inline Python, ThreadPool(THREADS). Uses requests with urllib3 Retry (429/5xx). Range-resume from `.part`. Reads with `raw.read1` so the hard `MAX_SECONDS`/`MAX_BYTES` ceilings can fire on trickling streams (SSE). Sends auth headers. Merges `local_path, sha256, size_bytes, mime_type, status` into the manifest (failures → `status: failed, error`). Per-host breaker: after `JSINTEL_DOWNLOAD_BLOCK_AFTER` (25) consecutive 403/429 responses (including 429s that exhausted urllib3 retries), the rest of that host's assets get `status: blocked` with no request sent. |
| `extractor.sh` | Wrapper: `python3 -m modules.extractor.main --manifest --output reports/`. |
| `fuzzer.sh` | Wrapper: `python3 -m modules.fuzzer --output --scope SCOPE $JSINTEL_FUZZ_ARGS`. Refuses to run with an empty scope. `python3 -m modules.fuzzer --output DIR --rescore` re-applies `suppress_repeated` to an existing `fuzz.json` offline (`engine.rescore`). |
| `subdomains.sh` | Expands the scope (domains, comma lists, or `@file`). Runs assetfinder, subfinder, and amass (passive) when installed, each under `timeout`. Scope-filters with awk on dotted suffixes. Liveness probe in Python requests (https, then http). Writes `assets/subdomains_hosts.txt` and `subdomains.txt` (URLs). |
| `portscan.sh` | Builds the candidate hosts from subdomains + seeds + scope domains, scope-filters them, then runs `python3 -m modules.portscan --hosts --workers [--ports $JSINTEL_PORTS]`. |
| `webshot.sh` | Targets: services.txt + subdomains.txt, falling back to the seeds. Runs `python3 -m modules.webshot`. |
| `sweep.sh` | Mass mode. Normalizes the targets file into a list of domains. Runs `jsintel.sh -i https://T -o OUT/targets/T` with per-target `-s/-p/-w/-f T`, bounded by `JSINTEL_SWEEP_PARALLEL` (default 3, uses `wait -n`). Records `.sweep_status`. Ends with `python3 -m modules.sweep_aggregate`. Then: hostname hygiene + `JSINTEL_SWEEP_DENY`, the `sweep_prefilter` pass, a crash-signal retry, `JSINTEL_SWEEP_RESUME`, and periodic `--health` warnings. |

## `modules/` — Python stages and helpers

| File | Purpose / key facts |
|---|---|
| `database.py` (CLI `ingest` / `query SQL`) | Loads `database/schema.sql`. `ingest()` deletes assets (cascades) and fuzz_results, then re-inserts from reports: assets.json, ports.json (as `asset_type='service'` carriers), urls/websocket/endpoints/api_spec_endpoints, frameworks→technologies, findings.json + security.json → findings, anomalies.json → `response_anomaly` findings, fuzz.json (excluding the `dry-run`/`out-of-scope` notes), services (+ screenshot join). |
| `reporter.py` | Reads the DB and writes `summary.md`, `summary.json`, `assets.csv`. Excludes `service` assets from the counts. Info-severity findings (structural) are counted separately from security findings. Collapses CDN mirrors and status-400 services. Adds `pipeline` (crawl_kept, downloads by status, screenshots attempted/captured) and `stages` (from `stages.tsv`) to `summary.json`. |
| `triage.py` | Per-host risk score = findings severity (crit 100 / high 40 / med 10 / low 3) + sensitive endpoints (×4, cap 40) + exposure (non-standard port 5, open 200 no-auth 2, cap 30). Writes `triage.{json,md,html}`. Masks values. |
| `diff.py` (CLI `old new [-o]`) | Diffs two output dirs using report JSONs only: hosts, services, endpoints, and findings added or removed. Writes `diff.{json,md}`. |
| `discover.py` | Feedback loop. Builds candidates from endpoints, urls, and api_spec_endpoints on hosts **already in the manifest** only. Skips templated or garbage paths (`_SKIP`). Dedupes via `reports/.discovered.json`. Downloads, appends to `assets.json`, prints the count added. |
| `liveanalysis.py` | For each service in ports.json: security headers (`missing_security_header`, `clickjacking`, `information_disclosure`, `insecure_cookie`), GraphQL introspection on 5 paths, API docs/spec (`exposed_api_spec/docs`, plus `parse_spec_paths` → `api_spec_endpoints.json`), debug pages (`debug_page_exposed`), `SENSITIVE_FILES` (`.git/config`, `.env`, `.htpasswd`, bak, phpinfo, server-status, fetched without redirects, with HTML soft-404 rejection), JWT (`jwt_exposed`, `jwt_alg_none`, `jwt_weak_alg`, which also checks the `--jwt` token). Output goes to `reports/security.json` with `source: "live-service"`. |
| `portscan.py` | `parse_ports`. Scanner preference: naabu, then nmap (resolve first, keyed by IP so CDN-shared IPs map back to hostnames), then a threaded Python connect scan. `_http_probe` tries https then http, gets title/server, and **must catch `http.client.HTTPException`** (non-HTTP banners like VNC/SSH once aborted the scan). `_detect_cdn`. `mark_port_mirrors` sets `mirror_of` on alt ports that echo :80/:443. `DEFAULT_WEB_PORTS` is a curated tuple of ~90 ports. Under proxychains (`proxyutil.under_proxychains`), skips naabu/nmap and connect-scans hostnames through the preload. |
| `webshot.py` | Finds chromium. Runs `--headless --screenshot` per URL with a timeout. `_is_blank`. dHash `perceptual_hash`, Hamming clustering (threshold 10). Flags hosts that have high findings. Self-contained `screenshots.html`. |
| `listener.py` (1329) | Capture daemon. See listener.md. |
| `authutil.py` | `auth_headers()` builds Cookie/Authorization from `JSINTEL_AUTH_COOKIE`/`JSINTEL_AUTH_BEARER`. Also `bearer_token`, `mask`, `describe` (CLI `--describe`). |
| `proxyutil.py` | `maybe_reexec_proxychains(value)` re-execs the Python process under `proxychains4 -q [-f conf]` once (guard env `JSINTEL_UNDER_PROXYCHAINS`). Used by listener and forms. Also: `under_proxychains`, `proxychains_conf`, `first_proxy`, `chain_proxy`/`proxy_url` (Go tools), `managed_conf[_text]` (adds loopback `localnet`), `chromium_launch` (strip preload + `--proxy-server`, or `None`), CLI `proxy-url` / `managed-conf`. |
| `sweep_aggregate.py` | Reads each `targets/<sanitized>/` and writes `sweep_summary.{json,md}` (live subs, services, alt-port count, assets, endpoints, findings, fuzz hits, status). Also rolls up per-stage seconds/failures, marks pre-filter skips (`skipped: <reason>`), and `health()` / `--health STAGES` warns when ports, screenshots or downloads are zero across at least 50 finished targets. |
| `sweep_prefilter.py` | Before a sweep: one GET per target (https then http) and one random-label GET per parent with 2 or more targets. `prefilter(targets, fetch, mode)` is pure (inject `fetch`). It drops dead hosts (`full` mode; with `--keep-resolving`, passed by sweep.sh for `-P`, only names without an address record are dropped) and keeps the first target per wildcard parent whose `Fingerprint` (status, title, redirect shape with the host masked, size within 10%) matches the random probe. Writes `reports/prefilter.json` and prints kept targets. |

## `modules/extractor/` (see extractor.md)

`main.py` (CLI, streaming manifest parser `iter_assets`, sequential/parallel runners,
LPT bin-packing, analyzer-group split of big bundles, JSONL shards), `models.py`
(frozen `Asset` with hidden `_tree`), `analyzer.py` (ABC: `id`, `supported_asset_types`,
`initialize/analyze/finalize`), `ast_analyzer.py` (`analyze_ast(asset, source, tree|None)`),
`registry.py` (`discover()` auto-imports `analyzers/*`, rejects duplicate ids;
`select()` filters by asset type), `findings.py` (URL/Endpoint/WebSocket/Import/
Framework/SecurityFinding → report name), `writer.py` (`JSONWriter.reports` tuple),
`parser.py` (tree-sitter JS/TS/TSX singletons, returning None on failure),
`ast_utils.py` (node text, per-file type index cache, `_find_nodes`, member chains,
`ScopeResolver` for lexical scoping, `function_params`, `enclosing_function`),
`utils.py` (`read_asset` uses utf-8 with errors=ignore), `analyzers/` (18 analyzers +
`_urlutil.is_plausible_url` + `token_patterns.json`).

## `modules/fuzzer/` (see active-stages.md)

`main.py` (CLI; refuses live probing without `--scope`), `engine.py` (load origins
from endpoints and urls → classify → candidates → probe → `fuzz.json`), `classify.py`
(`Category` api/graphql/js/file/parameter/directory/generic), `catalog.py` (category →
Assetnote wordlist URL), `local.py` (SecLists autodetect, preferred when present),
`wordlists.py` (cache → download → bundled `seeds/*.txt`; never empty),
`candidates.py` (extend known-good directory prefixes), `prober.py` (per-directory
soft-404 calibration, scope re-check before each send, `suppress_repeated` WAF/
catch-all demotion), `scope.py` (allowlist; empty allows nothing), `transport.py`
(stdlib urllib, no-redirect, never raises on a status), `urlutil.safe_urlsplit`,
`models.py` (dataclasses incl. `FuzzConfig`).

## `modules/forms/` (see active-stages.md)

`main.py` (CLI; pages from `--url`, `--urls-file`, or downloaded page assets; scope;
writes `forms.json` and appends endpoints to `crawled_urls.txt`), `parser.py` (stdlib
`html.parser`; handles `form=` linkage and orphan controls), `models.py` (`Field`,
`Form`, `semantic`), `synth.py` (constraint-aware value synthesis + a bounded regex
`sample_pattern`), `engine.py` (requests-based fill/submit honouring method/enctype/
auth), `driver.py` (headless Chromium over raw CDP with a hand-rolled WebSocket client;
instruments XHR/fetch/WS/beacon before page scripts; fills and fires events),
`safety.py` (destructive-URL denylist for payment/swap/withdraw/delete/logout...,
plus `masked_fields`).

## `src/jsintel/` — Phase 2 platform (only tests use it)

`models.py` (AssetType enum + many typed models: ScanRun, JavaScriptAsset, SourceMap,
Endpoint, GraphQLOperation, SecretFinding, ...), `plugins/base.py` (Plugin ABC,
PluginContext, PluginResult, ModelSink), `plugins/registry.py` (topological order,
dependency validation), `storage.py` (MigrationManager over `database/migrations/*.sql`,
KnowledgeGraphStore with nodes, edges, and traversal), `config.py` (typed
`PlatformConfig.from_yaml`).

## Other

| Path | Purpose |
|---|---|
| `database/schema.sql` | Phase 1 tables: assets, urls, endpoints, technologies, findings, fuzz_results, services. |
| `database/migrations/0001_platform.sql` | Phase 2 scan provenance + graph tables (used only by `src/jsintel/storage.py`). |
| `integrations/mitmproxy/` | `jsintel_mitm.py` addon + README (see listener.md). |
| `enhancements/bench.py`, `ENHANCEMENTS.md` | Benchmark harness and notes behind `BENCHMARKS.md`. |
| `problems/` | `problems.md` (false negatives found on the lab), `required-features.md` (backlog derived from it), README. |
| `tests/` | 48 pytest files (662 tests), `fixtures/*.js|ts|tsx`, `lab/` (see testing-and-lab.md). |
| `docs/` | ARCHITECTURE, PLUGINS, CONFIGURATION, DEVELOPMENT, FUZZING. |
