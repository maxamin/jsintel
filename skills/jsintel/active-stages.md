# Active stages: scope-gated and opt-in

Every stage here sends live traffic. Each one constrains its host set to the
operator's authorized scope **at the point of sending**, independently of any upstream
filtering. Keep it that way (defense in depth).

## Subdomains (`-s`, `modules/subdomains.sh`)
Uses assetfinder, subfinder, and amass (passive, `-norecursive`, stderr dropped
because of its progress bar), each wrapped in `timeout subdomain_timeout` (default 120).
The apex is always included. Hosts are lower-cased, wildcard-stripped, regex-checked,
and filtered on scope suffix. A threaded requests liveness probe tries https and then
http. **Known gap:** wildcard-DNS zones produce thousands of phantom hosts (see
recommendations §3).

## Port scan (`-p`, `modules/portscan.py`)
- Host list = subdomains + seed hosts + the scope domains, filtered on scope.
- Ports: `JSINTEL_PORTS` (e.g. `80,443,8000-8100`) or `DEFAULT_WEB_PORTS`.
- Engines in order: naabu, then nmap (greppable output; resolve hosts first, then map IP
  results back to every hostname that shares the IP), then a pure-Python connect scan
  (`--no-tools` forces it).
- `confirm_web_services`: an HTTPS-then-HTTP probe that records status, server, title,
  and CDN. `mark_port_mirrors` sets `mirror_of` so CDN alt-port echoes do not inflate
  counts. Any non-HTTP banner must be caught (`http.client.HTTPException` and a final
  guard). That bug once aborted 80-10443 sweeps.
- Outputs `assets/services.txt` (fed to the crawler) and `reports/ports.json`.

## Live analysis (`modules/liveanalysis.py`, auto-runs when ports.json is non-empty)
Passive GETs plus one GraphQL introspection POST per GraphQL path. Finding catalogue
is in modules.md. Sensitive-file checks use a **no-redirect** opener and reject HTML
bodies for plaintext-secret files (soft-404 and login catch-alls). OpenAPI `paths`
are written to `reports/api_spec_endpoints.json` and ingested as endpoints.

## Fuzzer (`-f`, `python3 -m modules.fuzzer`)
- Origins = `endpoints.json` + `urls.json`. `classify_path` assigns a `Category`, and
  `catalog.spec_for` maps the category to an Assetnote wordlist. Local SecLists
  (`/usr/share/seclists`) are preferred. Fallback chain: cache → CDN → bundled
  `modules/fuzzer/seeds/*.txt`.
- `candidates_for` extends known-good directory prefixes (`--context-depth 2`), deduped
  and capped (`--max-candidates 20000`, `--max-words 1500`).
- `Prober`: re-checks scope before each send (`out-of-scope` note). Per-directory
  calibration with a random path gives the baseline status and length (with
  tolerance). A response matching the baseline is not interesting, and that includes
  uniform 403/401/500 WAF walls. After probing, `suppress_repeated` demotes any
  response shape shared by 10 or more distinct words on a host (`note:
  repeated-response`). Slash-append directory redirects are exempt.
- Record fields: `url, category, origin, word, status, length, words, redirect, error,
  interesting, note`. Notes include `dry-run`, `out-of-scope`, `filtered-status`,
  `unmatched-status`, `matches-soft-404-baseline`, `matches-catchall-baseline`,
  `match`, and `repeated-response`.
- Useful flags: `--dry-run` (no network), `--offline`, `--delay`, `--concurrency`,
  `--extensions`, `--match-status`, `--filter-status`, `--follow-redirects`,
  `--no-calibrate`, `--cookie`, `--jwt`. Pass them through `JSINTEL_FUZZ_ARGS`.
- Backlog: live WAF-wall early stop, budget weighting, recursion, per-host rate limits,
  and template-param-aware fuzzing.

## Screenshots (`-w`, `modules/webshot.py`)
Headless Chromium `--screenshot` per distinct service (6 workers). Blank-render
detection, dHash clustering (Hamming ≤ 10), a gallery that flags hosts with
critical/high findings. Runs after extraction so the cross-reference works.

## Forms / AJAX spider (`--forms`, `python3 -m modules.forms.main`)
- Pages come from `--url`, `--urls-file`, or the downloaded `page` assets in the output dir.
  Pages are scope-filtered by the `--scope` values (jsintel.sh passes the -f, -s, or -p scope).
- `parser.parse_forms` uses the stdlib, attaches `form=` controls, and gathers orphan
  controls into a synthetic form. `synth.Synthesizer(seed)` produces spec-valid values
  that respect type, pattern, min/max, length, step, and options. `sample_pattern` is a
  bounded generator for HTML5 `pattern` (ReDoS-safe by construction; a test times it).
- `engine.submit_form` does a requests submit with auth headers. **Submit is on by
  default.** `safety.is_destructive` skips payment, trade/crypto, delete, reset, and
  logout URLs (`--deny TERM` adds terms, `--no-safe-denylist` overrides, `--no-submit`
  reports only).
- `driver.drive_page` (`--browser`) launches Chromium with remote debugging and speaks
  raw CDP over a minimal stdlib WebSocket. It injects network-API hooks before page
  scripts, fills fields and fires events, waits `--settle` seconds, and collects
  XHR/fetch/WS/beacon endpoints.
- Output is `reports/forms.json`. New endpoints are appended to `assets/crawled_urls.txt`.

## Discovery loop (`modules/discover.py`)
Up to `JSINTEL_DISCOVER_ROUNDS` (3) rounds × `JSINTEL_DISCOVER_LIMIT` (200) fetches.
URLs are only built on hosts already in the manifest. Templated, garbage, and `..`
paths are skipped. State lives in `reports/.discovered.json`. The pipeline re-runs
extraction only when a round adds something.

## Mass sweep (`-m file`, `modules/sweep.sh`)
Per-target isolation, `JSINTEL_SWEEP_PARALLEL` (3), and stage toggles `-S/-P/-W/-F`.
`JSINTEL_SWEEP_RESUME=1` skips targets whose `.sweep_status` is `ok`. A crash-signal death
(rc 134/135/137/139) is retried once, and the first log is kept as
`sweep_target.attempt1.log`. rc 130/143 (operator stop) is never retried. The
operator runs very large sweeps (58.5k targets, multi-day) from `screen`, sometimes under
proxychains. **Never edit `sweep.sh`, `jsintel.sh`, or any `modules/*.sh` while
`pgrep -f sweep.sh` shows a live sweep.** bash re-reads scripts while it runs them, so
edits corrupt the in-flight targets. Python modules are re-imported per process, so
edits there affect later targets only. Still, be careful.

## proxychains
`jsintel.sh --proxychains [conf]` re-execs the whole run under `proxychains4 -q [-f conf]`
once. The listener and forms CLIs do the same through `proxyutil.maybe_reexec_proxychains`.
The operator's Tor SOCKS proxy is on 127.0.0.1:9050.
