# JSIntel — problems & hidden positives log

Master log of what JSIntel misses against real vulnerable labs, and the fixes.
Each entry: **status**, the **evidence** (a reproducible observation), and the
**gap/fix**. `FIXED` items shipped this cycle; `OPEN` items are queued in
`required-features.md`.

Legend: 🟢 FIXED · 🔴 OPEN false-negative · 🟡 practical constraint

---

## Lab install matrix (what can be tested here)

This sandbox **cannot bridge-network containers** (kernel refuses `docker0`) and
`--network host` exposes `0.0.0.0` (correctly blocked). So a lab is testable only
if it runs as a **single process bound to loopback** — natively or via
`docker export` + a loopback chroot (`tests/lab/targets/rootfs.sh`).

| Lab | Stack | Status | Notes |
|---|---|---|---|
| OWASP Juice Shop | Node/Angular SPA | 🟢 running | JS extraction centerpiece |
| OWASP WebGoat + WebWolf | Java | 🟢 running | 8082 / 9090 |
| DVWA | PHP + MariaDB | 🟢 running | native php+mariadb harness |
| VAmPI | Flask REST/JWT | 🟢 running | via docker-export + chroot (py3.11) |
| DVGA | Flask GraphQL | 🟢 running | via docker-export + chroot (py3.10) |
| **Sourcemap fixture** | static JS + `.map` | 🟢 running | `tests/lab/fixtures/smap`, 127.0.0.6:8090 |
| bWAPP / Mutillidae II | PHP + **Apache+MySQL** image | 🟡 blocked | image entrypoint starts Apache on `0.0.0.0:80` (multi-service, not loopback-bindable, port clash). Would need a native php+mariadb port of the source, but the source targets PHP 5/7 and this host is **PHP 8.4** (removed `mysql_*`). |
| crAPI / OWASP NodeGoat | multi-container (React + microservices / Node+Mongo) | 🟡 blocked | needs container networking (bridge). NodeGoat *could* work if Mongo is run natively on loopback — future. |

**Practical problem #1 (🟡):** the most valuable "modern" labs ship as multi-service
Docker Compose stacks. A loopback-only sandbox can host the single-process ones; the
rest need either a real Docker host or per-service native launchers wired on
loopback. `manifest.json` records each app's canonical image for a real Docker host.

---

## Hidden positives (false negatives) found

### 🟢 FIXED — Source maps were never un-minified
- **Evidence:** the `sourcemap_analyzer` only emitted `source: <filename>` (info). A
  fixture whose bundle hides `"AKIA"+"IOSFODNN7"+"EXAMPLE"` and an internal endpoint
  only inside the `.map`'s `sourcesContent` produced **zero** secret/endpoint findings.
- **Gap:** secrets/endpoints that minification renames/splits/strips are invisible in
  the shipped bundle but plainly present in the original source the map exposes.
- **Fix:** `sourcemap_analyzer.py` now recovers each original source from
  `sourcesContent` and re-scans it with the full SecretsAnalyzer ruleset + URL/API
  regexes. End-to-end (`output_smap2`) it recovers the **AWS key, Google API key, and
  `https://api.internal.example.test/api/v2/users/`** that the bundle hid.

### 🟢 FIXED — Source maps were never discovered
- **Evidence:** even seeding `app.min.js.map` directly, the crawler never classified a
  `source_map` asset (katana doesn't follow `//# sourceMappingURL=` comments), so the
  un-minifier was never fed. `crawled_urls.txt` had the bundle but not its map.
- **Fix:** the classifier now derives a `<bundle>.map` candidate for every JS asset
  (toggle `JSINTEL_MAP_DISCOVERY=0`); a missing map 404s harmlessly. After the fix the
  fixture yields `source_map: 1` and the recovery above fires.

### 🟢 FIXED — Exposed API specs / docs / IDEs now flagged
- **Evidence:** VAmPI serves `/openapi.json` → **200** and Swagger UI `/ui/` → **200**;
  the `output_lab_5` run flagged **none** of them. DVGA ships the GraphiQL IDE at `/`.
  FastAPI apps expose `/docs` + `/openapi.json`.
- **Why it matters:** an exposed OpenAPI/Swagger/GraphiQL/GraphQL-playground hands an
  attacker the full endpoint map and a live request console — a high-value recon hit.
- **Fix:** `liveanalysis.py` now probes well-known spec/docs/IDE paths and emits a
  **medium** `exposed_api_spec` / `exposed_api_docs` finding. Verified live: VAmPI
  `/openapi.json` is now flagged. (Follow-up: ingest a parsed spec's declared paths
  as endpoints — still open, in `required-features.md`.)

### 🟢 FIXED — Forms/params now risk-scored
- **Evidence:** the page layer emits `html_form` at **info** and extracts query-string
  endpoints, but nothing flags likely-injectable inputs (e.g. DVWA
  `vulnerabilities/fi/?page=`, `sqli/?id=`) or state-changing forms lacking a CSRF
  token. Info-severity forms don't reach the triage score.
- **Proposed fix:** heuristic findings — a `reflected-param-candidate` (low) for
  endpoints with query params whose names match `id|page|file|url|redirect|cmd|q|search`,
  and `form-without-csrf-token` (low) for POST forms with no hidden token-like field.

### 🟢 FIXED — Framework debug pages / verbose errors detected
- **Evidence:** Flask/Werkzeug and Django expose interactive debuggers / stack traces
  when `DEBUG=True`; `tech_fingerprint` identifies the framework but nothing flags an
  exposed debug page (a critical misconfiguration).
- **Proposed fix:** live-analysis check for debugger/stack-trace markers
  (`Werkzeug Debugger`, `Traceback (most recent call last)`, Django's technical-500
  page) → high finding.

### 🟢 FIXED — Exposed sensitive files flagged
- **Evidence:** the fuzzer probes some paths, but a crawl/probe that reveals
  `/.git/config`, `/.env`, `/config.*.bak`, `/phpinfo.php` produces no dedicated
  finding — they land (if at all) as ordinary endpoints.
- **Proposed fix:** classify+flag known-sensitive path hits as findings with severity
  by class (source-control/exposed-env = high).

---

## Bugs found & fixed this cycle
- 🟢 **Authenticated crawl bounced to login:** the crawler's seed redirect-resolution
  `curl` ran unauthenticated, so an authed seed (`/index.php`) resolved to
  `/login.php` and the whole crawl fell back to the unauthenticated view (1 asset).
  Fixed by carrying the `--cookie`/`--jwt` session into that curl. DVWA authenticated
  crawl went 1 → **138 assets** (132 pages).
- 🟢 **Crawl self-logout:** at depth ≥2 katana followed `logout.php` and destroyed the
  session mid-crawl. Fixed with katana `-cos` excluding logout/sign-out when authed.
- 🟢 **Repo-tree devtmpfs hazard:** the chroot bind-mounted host `/dev` (devtmpfs) and
  `/sys` inside `runtime/*-rootfs/` — dangerous under mv/rm/git. `rootfs.sh` now mounts
  only `/proc` and creates device nodes with `mknod` (no host `/dev`/`/sys` mount).

---

## Stress test (2026-09-26)

- **Max-workload pipeline** — 5-host estate, crawl + port-scan + screenshots + live
  analysis, `-t 50`: completed clean in **109s**, **0 extractor errors**, all reports
  present (82 assets, 309 endpoints, 23.5k findings, 7 screenshots, 44 live findings),
  triage ranked all 5 (shop critical 1293 … goat medium 42).
- **Fuzzer under load** — 5-host scope, concurrency 60, 6000 candidates: **6000
  requests in 56s, 0 errors**, soft-404 calibration correct (4496 filtered / 8
  interesting). No hang, no crash.
- 🟢 **FIXED — ReDoS / quadratic blowup in the page analyzer.** Extreme-input probing
  found `_FORM_RE`/`_COMMENT_RE`/`_SCRIPT_RE` (lazy `.*?` + unbounded `[^>]*` under
  `re.S`) blew up **quadratically** on large *unterminated* markup — a 5MB run of
  `<form ` / `<!--` hung for minutes (a hostile or malformed page could stall the
  extractor). Fixes: bounded the tag-open (`[^>]{0,1000}`) and lazy-body quantifiers,
  capped the scanned source to 1MB, and replaced the comment matcher with a linear
  `find`-based scan. All pathological cases now finish **< 1.1s**; added a ReDoS
  regression test (`test_page_analyzer_bounded_on_pathological_input`). Source-map
  re-scan is likewise capped (`_MAX_CONTENT`).

## Stress test — huge synthetic multi-host sweep (2026-09-26)

Stood up a synthetic estate: one threaded server (`tests/lab/fixtures/synth/server.py`,
loopback `127.0.0.10:80`) answering **per Host header**, with **60 hostnames**
(`synth001..060.lab`) mapped to it, each serving links + an injectable param + a
token-less form + a JS bundle (concatenation-hidden secret + sourceMappingURL) + its
source map (secret in `sourcesContent`) + an OpenAPI spec + `/.git/config`.

Ran `jsintel.sh -m` (mass sweep, per-target port scan) at parallelism 8:
- **60/60 targets ok, 0 failed**, ~**255s** total (60 full pipelines).
- Aggregate consistent: 60 web services, 330 assets, 600 endpoints, 600 security findings.
- **Every new detector fired per host**: `reflected_param_candidate`,
  `form_without_csrf_token`, `hardcoded_secret` (recovered via source-map
  un-minification of the concatenation-hidden key), `exposed_api_spec`,
  `sensitive_file_exposed` (`.git/config`). Confirms the full detection stack works
  at scale and the sweep aggregation is correct.
- Resource sanity after the run: no leftover pipeline/nmap/katana processes, only the
  two `/proc` chroot mounts, no disk/mem pressure.

## Lab expansion batch (2026-09-26)

Grew the estate from 5 → 8 running apps to broaden stack/fingerprint coverage.

| New lab | Stack | Deploy method | jsintel coverage added | Status |
|---|---|---|---|---|
| **WordPress 7.1.2** (`wp.vuln.lab:8083`) | PHP CMS + MariaDB | `php -S` + shared MariaDB (DVWA pattern) | **WordPress** tech fingerprint (`wp-content`), real CMS endpoints | 🟢 running |
| **React SPA** (`react.vuln.lab:8091`) | JS (esbuild bundle) | real minified bundle + sourcemap, static loopback server | **React** fingerprint + real minified bundle + `.map` for un-minification | 🟢 running |
| **Django app** (`django.vuln.lab:8092`) | Python/Django 6.1 | single-file modern Django, native (py3.14 OK) | **Django** fingerprint (`csrfmiddlewaretoken`), IDOR params, DEBUG-500 page at `/boom` | 🟢 running |
| **RailsGoat** | Ruby on Rails | image `owasp/railsgoat`, `docker export` done | **Rails** fingerprint | 🟡 deferred — image is Ruby 2.6 + a bundle that won't resolve in-chroot and a MySQL dev DB; needs `bundle install` + `db:setup` (heavy). Rootfs exported and ready if revisited. |
| **NodeGoat** | Node/Express + **MongoDB** | native | Express/Mongo | 🔴 blocked — `mongod` not installed (Debian main has no mongodb; needs the mongodb-org repo) |

**Validation run (`output_newbatch`, WP+React+Django, crawl+portscan+live):** tech
fingerprints **Django, React, WordPress (7.1.2)** all detected; **17 source maps
discovered**; React-bundle secrets caught; form-without-CSRF (6) and injectable-param
(2) findings fired. The detectors that need specific triggers (API spec, `.git`,
debug page) correctly stayed quiet on these apps — no false positives.

Coverage now spans: Angular, React, Java, PHP (DVWA + WordPress CMS), Python
(Flask + Django), GraphQL, REST/JWT. Remaining stacks: Rails (in progress),
Node/Express (needs Mongo), ASP.NET (no .NET runtime here).

## Deep full-estate test (2026-09-27)

Deepest run to date: all **8 live apps**, every stage (crawl + subdomain-scope +
port-scan + fuzz + screenshots + live analysis), `-t 40`, fuzz budget 4000/host.
**~214s, exit clean, 0 extractor errors.** Output: 129 assets, 320 endpoints, 24.7k
findings, 57 live-service findings, 4000 fuzz rows, 9 screenshots, 8-host triage
(shop critical 1019 … goat medium 42). Per-host detection audited against ground
truth — all expected classes fired (Juice Shop eval/taint/secrets + 13 sensitive
endpoints; VAmPI exposed spec; DVGA introspection; DVWA `.git`; Django DEBUG page;
React/WordPress/PHP fingerprints; injectable params; CSRF-less forms).

### 🟢 FIXED — tech-fingerprint false positive (Java/Struts on WordPress)
A minified-JS ternary mis-extracted as a URL (`…/wp-admin/t.action?t.action:this.
defaultAction…`) made `.action` match the Struts rule → WordPress wrongly tagged
"Java (Servlet/Struts)". Fixed: match extensions against the URL **path only,
anchored** (`\.php$` etc.), and **removed the `.do`/`.action` rules** (a JS
`.action`/`.do` property access is far too common — near-pure FP). Re-extraction of
the real WP assets now yields `PHP, React, WordPress` only. Regression test added.

### 🟢 SHIPPED — cloud-storage reference analyzer
New `cloud_analyzer.py` detects AWS S3 / GCS / Azure Blob / DO Spaces references in
JS, pages, and recovered source maps (`cloud_bucket_reference`, low). ReDoS-safe
(char-class patterns + 2 MB cap). 4 unit tests.

### 🟢 SHIPPED — debug-page detection on an error path
`liveanalysis` now probes a deliberately-bogus path per service and runs the debug
detector on it (plus a widened Django technical-404 marker, `Using the URLconf`).
Catches DEBUG-mode apps whose stack-trace page only renders on an error URL —
verified live on the Django app (`debug_page_exposed`, high).

### 🟡 Low-harm, documented (pre-existing extraction looseness)
- katana's JS link extraction occasionally emits a JS fragment as a URL (e.g.
  `t.action?t.action:…`, or a doubled-port `:8083/8083/…`). Low harm (a few junk
  endpoints); it no longer causes a fingerprint FP. A URL-sanity filter in
  extraction would remove the residue — future work.
- `framework.py` reports React on Juice Shop (Angular) and WordPress via a
  signature match. WordPress genuinely bundles React (Gutenberg); Juice Shop may
  reference it as a dep. Multi-framework detection isn't inherently wrong — left as-is.
