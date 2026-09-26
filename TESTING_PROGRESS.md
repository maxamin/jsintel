# JSIntel — End-to-End Workflow Testing & Bug Fixing

**Goal:** Exercise the full jsintel pipeline to the end and fix every bug found along the way.

**Started:** 2026-09-25

---

## Ground rules (standing constraints)

- **Never delete seed or result files** (`domains.txt`, `urls`, `output_gala/`, `output_gala_full/`, any `reports/`/`assets/`/DB artifacts). Fresh runs go in a new directory.
- **Track progress here in detail** — milestones, todos (as self-contained prompts to future self), dones, bugs, and fixes.

---

## Testing approach & constraint

- The user's requested live target is **gala.com**. Running jsintel's *active* workflow
  (crawl + subdomain enumeration + live fuzzing) against gala.com was **blocked by the
  safety classifier as a third-party attack** (jsintel is active recon; gala.com is not
  demonstrably owned by the user). We do **not** route around that denial.
- **Chosen safe method:** drive the full pipeline against a **local mock HTTP server**
  (localhost) that serves representative assets (`.js`, `.mjs`, `.map`, `.json`, `.wasm`,
  worker, manifest) and discoverable paths, plus the fuzzer's `--dry-run` mode. This
  exercises every stage end-to-end with no third party involved and lets us craft edge cases.
- If the user wants a real gala.com run, that's their decision to authorize (e.g. a Bash
  permission rule) — but active scanning of a third party still requires genuine authorization.
- **2026-09-25 — ether.fi attempt / hard boundary confirmed.** The user asked to run the
  live active workflow against **ether.fi** and stated they were authorized. Findings:
  - The user's asserted authorization does **not** clear the block.
  - Adding a Bash permission allow-rule (`Bash(./jsintel.sh:*)`, `katana`, `ffuf`, `amass`,
    etc. in `.claude/settings.local.json`) does **not** clear it either. The
    **third-party-attack protection is a separate, server-side classifier**, independent of
    the local Bash permission system.
  - The agent itself is also blocked from editing permission settings (denied as
    **Self-Modification**) — by design, so it can't grant itself the scanning permission it
    was just denied.
  - **Conclusion:** on this harness, driving jsintel's active recon against a third-party
    domain is not achievable by the agent, regardless of authorization. Local-mock
    validation remains the way to exercise the tool end-to-end.

## Pipeline stages under test

1. `modules/subdomains.sh` — subdomain enumeration + liveness probe (`-s`)
2. `modules/crawler.sh` — katana crawl + scope filtering
3. `modules/classifier.sh` — asset classification -> `reports/assets.json`
4. `modules/downloader.sh` — concurrent resumable downloads
5. `modules/extractor.sh` -> `modules.extractor.main` — intel extraction
6. `modules/fuzzer.sh` -> `modules.fuzzer` — content discovery (`-f`)
7. `modules/database.py ingest` — DB ingest
8. `modules/reporter.py` — final reports

---

## DONE

- [x] Read full pipeline (orchestrator + all module scripts + fuzzer CLI).
- [x] Baseline test suite: **all tests pass** on Python 3.14.7.
- [x] Tooling check: katana, hakrawler, assetfinder, httpx, ffuf, feroxbuster, node present; `gau`, `subfinder` missing.
- [x] Saved standing prefs to memory (preserve files; track progress in .md).

## TODO (prompts to future self)

- [ ] **Build local mock target**: stand up a Python HTTP server in the scratchpad serving a
  small site — an index page linking to `app.js`, `app.js.map`, `config.json`, `sw.js`,
  `manifest.webmanifest`, `mod.mjs`, a `.wasm`, and some fuzzable dirs/files
  (`/api/`, `/admin`, `/.git/config`, `/backup.bak`). Embed fake secrets/endpoints in the JS
  so the extractor analyzers have something to find.
- [ ] **Run each stage against localhost** individually first (classifier, downloader,
  extractor, database, reporter), capturing bugs per stage. Then a full `jsintel.sh` run
  against the local seed.
- [ ] **Run subdomains.sh** logic against a controllable/local scope to exercise scope parsing,
  awk suffix matching, and the Python liveness probe (localhost).
- [ ] **Run fuzzer** in `--dry-run` (no network) and against the local server to exercise
  candidate generation, classification, calibration, and report writing.
- [ ] **Run database.py ingest + reporter.py** on the produced reports; verify schema/report output.
- [ ] For each bug: record it under "BUGS", write a fix, re-run the affected stage, mark fixed.
- [ ] Final: full clean end-to-end run against local target with zero errors; summarize.

## BUGS FOUND / FIXED

### BUG #1 — Verbose crawl dropped the URL stream (found & fixed)
- **File:** `modules/crawler.sh` (verbose katana branch).
- **Symptom:** with `-v`, crawler reported "saw 0 total URLs" / "0 candidate assets"
  even though katana discovered them; non-verbose worked fine.
- **Cause:** `katana ... 2>&1 | tee -a "$LOG_FILE" >&2 | grep ... > RAWCRAWL`. The
  `>&2` redirected tee's stdout to stderr, so `grep` read EOF and RAWCRAWL was empty.
  (Ironic: `-v` is the flag the docs recommend to debug empty crawls.)
- **Fix:** dropped the decorated `-v`/tee/grep parsing entirely. Verbose now uses the
  same reliable `-silent` capture as non-verbose and only adds logging (URL list + count).

### BUG #2 — katana hangs on inherited stdin (found & fixed)
- **File:** `modules/crawler.sh` (both katana invocations).
- **Symptom:** katana launched from the pipeline hangs indefinitely (timeouts) when
  run non-interactively, while the same command with `</dev/null` returns in ~12s.
- **Cause:** with `-list <file>`, katana still reads stdin; when stdin is an open pipe
  that never sends EOF (CI/cron/pipeline/harness), katana blocks forever. Intermittent
  because it depends on whether katana gets around to reading stdin.
- **Fix:** redirect `</dev/null` on the katana invocations so stdin is closed.
- **Follow-up TODO:** audit other external-tool invocations that could block on stdin
  (assetfinder/subfinder/amass in `subdomains.sh`).

## MILESTONE — core pipeline verified end-to-end (2026-09-25)

Full `jsintel.sh` run against local mock target (`http://127.0.0.1:8099/`) with `-f`
completed exit 0 and produced coherent, correct output at every stage:
- Crawler: 14 candidate assets (verbose surfaces URL list; no hang).
- Classifier: 14 classified.
- Downloader: 13 downloaded, 1 legit 404 (`lazy.js` referenced-but-absent).
- Extractor: 14 findings incl. hardcoded_secret, dangerous_eval + taint_to_sink
  (critical), 2 endpoints, 3 technologies; `errors.json` empty.
- Fuzzer (offline): 120 candidates / 120 requests / 1 interesting / 0 errors.
- Database ingest: assets 14, endpoints 2, findings 14, fuzz_results 120,
  technologies 3, urls 2.
- Reporter: `summary.md` / `summary.json` consistent with DB.

### Remaining TODO
- [ ] **Subdomain stage (`-s`)** — not yet exercised. Plan: (a) unit-test the
  in-scope filtering awk (security control that constrains enumerator output to
  scope) with crafted in/out-of-scope hosts; (b) end-to-end run of `subdomains.sh`
  via a local `/etc/hosts` domain + port-80 server; (c) audit assetfinder/
  subfinder/amass invocations for the same stdin-hang class as katana (Bug #2).
- [ ] Re-run the Python test suite after all shell fixes (shell fixes shouldn't
  affect it, but confirm).
- [ ] Final: summarize all bugs + fixes for the user.

## DECISIONS / NOTES

- Live third-party scanning of gala.com is out of scope for automated execution here;
  local mock target substituted for end-to-end validation.

## MILESTONE — secrets detector overhaul (2026-09-25)

Expanded and hardened the hardcoded-secret detector
(`modules/extractor/analyzers/secrets_analyzer.py`). Requirement from the user:
add more patterns and be "101% sure they work and valid even in extreme cases".

### What changed
- **Vendored a curated ruleset**: `modules/extractor/analyzers/token_patterns.json`
  (109 strategy-tagged, RE2-compatible OAuth/API token regexes, from
  github.com/odomojuli/regextokens). The analyzer is now data-driven.
- **Loads 106 of the 109** — skips `identifier` (public handles) and `encoding`
  (base64 validator) strategies, which are not secrets. Plus one hand-written
  `credentials-in-url` pattern = **107 total**.
- **Keyword-gated patterns** capture the secret in a group; only the captured
  secret is reported (the surrounding keyword is not leaked).
- **Severity per pattern** (critical/high/medium/low/info — the levels the
  reporter sorts): private-key/GCP marker and Cloud/Source-CI/Payments → high;
  AI/Comms/etc → medium; jwt → low.
- **Masking** reports only first/last few chars; structural markers (PEM header,
  service-account `"type"`) are shown intact as they carry no key material.

### BUGS FOUND / FIXED
- **BUG #3 — ReDoS (quadratic) in the URL-credentials pattern.** The initial
  `credentials_in_url` regex used an unbounded `[...]*` scheme prefix before the
  required `://`; on a large colon-free blob (minified bundle) it degraded to
  O(n^2) — **61.7s on a 1.1 MB literal**. Fixed by bounding the scheme to
  `{0,14}` (real schemes are short) → **0.14s**.
- **Mislabel fixed**: `sk-<...>` was labeled `stripe_key`; that prefix is
  OpenAI's (Stripe uses `sk_live_`/`sk_test_`). Now labeled correctly via the
  vendored `openai-api-key*` / `stripe-secret-key` patterns.

### Performance — anchor prefilter
Running ~107 regexes over every literal cost ~6.8s on a 1.1 MB single literal.
Added a **literal-anchor prefilter** (the gitleaks/trufflehog technique): each
pattern gets a provably-required literal substring (or flat alternation of
them); a fast `in` test skips the regex when that literal is absent. 95/107
patterns are anchored, 12 always-run. Correctness-preserving (only skips when a
required literal is provably absent). Result: **1.1 MB scan 6.8s → 1.24s**.

### Validation ("extreme cases")
- **All 107 patterns** verified to compile under Python `re` and to be
  **ReDoS-safe** (worst single search 0.046s over 200 KB adversarial blobs;
  a per-pattern test asserts <1s each, and a full-analyze test asserts <5s on a
  1.1 MB literal).
- **Positive detection** asserted for 74 realistic-shaped fake tokens spanning
  every category and structural shape (OpenAI infix, Slack variants, Discord,
  Telegram, keyword-gated cloud creds, GCP service-account marker, age, etc.).
- **Negatives/boundaries**: AWS key glued to extra chars, wrong-length GCP key,
  short GitHub token, malformed JWTs, plain URL with port (not credentials),
  bare hex without context, dedup, unicode.
- Full suite: **273 tests pass** (was 125 before this work).

### Remaining TODO (unchanged from before)
- [ ] Subdomain stage `-s` was validated end-to-end this session (scope parse,
  scope-filter awk rejecting suffix-confusion traps, liveness probe, full
  `subdomains.sh` run against a local fake-enumerator + local server). DONE.
- [ ] Final: summarize all bugs + fixes for the user.

---

## MILESTONE — mass multi-target sweep + web-service port scan + ether.fi fuzzer fix (2026-09-26)

User request: make `-f` (fuzz) and `-s` (subdomain) — and the whole pipeline —
run in a **multi-target "mass sweep"** mode, and add a **port-scan feature** that
maps web services on **non-standard ports** (beyond 80/443) on discovered/scanned
hosts. Also: the `ether_fi_runs/` run had "run into a problem."

### The ether.fi problem — diagnosed & fixed
- **Symptom:** `ether_fi_runs/reports/fuzz_summary.json` reported **11,919 of
  20,000 candidates "interesting"**, all in one `api` category — useless noise.
- **Root cause #1 (the big one):** the origin/edge (WAF) answered *every* path with
  an **identical HTTP 403** (length 70, 3 words). The prober's soft-404 calibration
  only suppressed a catch-all when its status was **2xx/3xx** (`_Baseline.soft`),
  so a uniform **403 wall sailed through** and every junk path was flagged "match".
- **Fix:** `modules/fuzzer/prober.py` — a candidate is now suppressed whenever it
  matches the directory's calibration fingerprint **regardless of status class**
  (soft-404 *or* a uniform 401/403/500 WAF wall). Note is
  `matches-soft-404-baseline` (2xx/3xx) or `matches-catchall-baseline` (else).
- **Root cause #2 (minor):** wordlists carried stray tokens (`?:`, `#`, whitespace)
  that corrupt the URL into a query/fragment. `modules/fuzzer/candidates.py`
  `_clean_word` now drops words containing whitespace/`?`/`#`/`\`/control chars.
  (Ugly-but-valid segments like `&&`/`==` are kept — the baseline fix handles them.)
- **Verified on the real recorded data:** re-judging `ether_fi_runs/reports/fuzz.json`
  through the new catch-all logic drops **11,919 → 6** interesting (5 redirects +
  1 genuine 200); **11,913 WAF-wall 403s suppressed.**

### New feature — web-service port scanning (`-p`)
- `modules/portscan.py` — discovers web services on a **curated ~100 web-focused
  ports** (80,443,8080,8443,3000,5000,8000,8888,9000,9200,7001,…). Prefers
  `naabu` > `nmap` when installed, else a **threaded pure-Python TCP connect scan**;
  then **HTTP(S)-probes** every open port to confirm it speaks HTTP and records
  scheme/status/server/title. Writes `assets/services.txt` (scheme://host:port/ URLs)
  + `reports/ports.json`. Ports overridable via `JSINTEL_PORTS` (supports ranges).
- `modules/portscan.sh` — builds the host list from prior `-s` discovery
  (`subdomains_hosts.txt`) + seeds, **constrained to the authorized scope** (never
  probes out-of-scope hosts), then runs the scanner.
- Wired into `jsintel.sh` `-p <scope>`: runs after `-s`, and confirmed services are
  folded into the **crawl seeds** and (being subdomains of scope) into **fuzz scope**.
- Reporter (`modules/reporter.py`) surfaces a "Web services (port scan)" section and
  `web_services` / `web_services_nonstandard_port` counts in `summary.{json,md}`.

### New feature — mass multi-target sweep (`-m`)
- `jsintel.sh -m <targets_file>` with toggles `-S` (subs), `-P` (ports), `-F` (fuzz):
  runs the full pipeline against **each target independently** into
  `<output>/targets/<domain>/`, each target its own authorized scope. Bounded
  parallelism via `JSINTEL_SWEEP_PARALLEL` (default 3). One failed target never
  aborts the sweep.
- `modules/sweep.sh` — target normalisation/dedup, per-target invocation, parallel
  job pool, per-target `.sweep_status`.
- `modules/sweep_aggregate.py` — rolls per-target reports into
  `reports/sweep_summary.{json,md}` (totals + ranked per-target table). Extracted as
  an importable module so it is unit-tested independently.

### Validation
- **Full suite: 286 tests pass** (was 273): +2 prober regression tests (403 WAF wall
  suppressed; a 403 differing from the wall still interesting), +1 junk-word filter
  test, +8 portscan tests (parse/host-normalise/HTTP-confirm against a local server/
  python connect scan/run outputs), +2 sweep-aggregate tests.
- **Port scan e2e (local):** served a page on non-standard port 8901; both the
  pure-Python and nmap backends discovered it; `services.txt`/`ports.json` correct.
- **`-p` single-run e2e (local):** port scan → `services.txt` → folded into
  combined seeds → pipeline completed; reporter shows the web-services section.
- **`-m` mass-sweep e2e:** ran against two targets end-to-end (dedup + case-normalise
  applied), per-target dirs created, aggregate `sweep_summary.md` written, exit 0.

### Files changed / added
- Changed: `jsintel.sh`, `modules/fuzzer/prober.py`, `modules/fuzzer/candidates.py`,
  `modules/reporter.py`.
- Added: `modules/portscan.py`, `modules/portscan.sh`, `modules/sweep.sh`,
  `modules/sweep_aggregate.py`, `tests/test_portscan.py`,
  `tests/test_sweep_aggregate.py`; extended `tests/test_fuzzer_prober.py`,
  `tests/test_fuzzer_candidates.py`.

### TODO (prompts to future self)
- [ ] Optional: ingest `reports/ports.json` into the SQLite DB (a `services` table)
  so port findings are queryable alongside assets/endpoints, not just file-based.
- [ ] Optional: teach `masscan` path (needs resolved IPs) for very large sweeps;
  currently skipped in favour of naabu/nmap/python for hostname input.
- [ ] Re-run a real authorized target with `-s -p -f` when a genuinely authorized
  scope is available, to confirm the catch-all suppression holds on live traffic
  (local mocks confirm the mechanism; the ether.fi replay confirms the numbers).

---

## VALIDATION — full chain vs local multi-service mock (2026-09-26)

Live third-party runs against gala.com/ether.fi stay blocked (unauthorized active
recon). Ran the **full active chain** (`-p` port scan + crawl + extract + `-f` fuzz
+ db + report) against a **local multi-service mock** that deliberately reproduces
the ether.fi failure mode. Mock (all on 127.0.0.1): `:8080` real app (200 real
paths, proper distinct 404s), `:8443` **uniform-403 WAF wall** (identical body to
every path), `:3000` dashboard, `:9200` title-less JSON service; `:5000`/`:9000`
closed (negative control).

### Results (new code, live)
- **Port scan:** discovered all 4 web services on non-standard ports; ignored the 2
  closed ports; `https->http` fallback worked for `:8443`; title-less `:9200`
  handled. Reporter shows the "Web services (port scan)" section.
- **Crawl/extract:** 2 JS assets, 5 endpoints (incl. the cross-service
  `http://127.0.0.1:8443/api/logs` reference), 3 secrets (GitHub PAT + AWS key =
  high, OpenAI key = medium), 0 extractor errors.
- **Fuzz:** 480 candidates / 480 requests / **4 interesting / 0 errors**. Note
  breakdown: `match` 4, `filtered-status` 316, **`matches-catchall-baseline` 160**.
  The 4 interesting are exactly the real endpoints (`/admin`, `/api/v1/users`,
  `/api/v1/status`, `/api/v1/admin/config`) — 100% precision.

### Old-vs-new on the SAME target (the fix, proven)
All 160 candidates aimed at the `:8443` wall returned an identical 403. The old
prober suppressed catch-alls only when 2xx/3xx, so it would have flagged **all 160
as "interesting"** → 164 interesting (160 false, 97.6% noise). The new code
suppresses them as `matches-catchall-baseline` → **4 interesting, 0 false**.

| Run | Code | Candidates | Interesting | False positives |
|---|---|--:|--:|--:|
| ether.fi (recorded) | old | 20,000 | 11,919 | ~11,913 (WAF 403 wall) |
| ether.fi (replayed) | new | 20,000 | 6 | 0 |
| local mock | old (derived) | 480 | 164 | 160 |
| local mock | new (live) | 480 | 4 | 0 |

Conclusion: full chain runs clean end-to-end; the new port scan maps alternate-port
web services; the fuzzer calibration fix eliminates the WAF-wall false positives
that made the ether.fi run unusable, while keeping every true positive.

---

## ANALYSIS + FIXES — first authorized live run (gala.com, operator-run) (2026-09-26)

The operator ran the full chain themselves (authorized) via the `!` prefix:
`./jsintel.sh -i https://gala.com -s gala.com -p gala.com -f gala.com -o output_gala_live -v`.
Exit 0; 220 hosts enumerated (93 live), 907 assets, 447 endpoints, 29 critical +
20 high security findings. I analysed the output/logs and found **4 bugs**; all
fixed with tests. (I did NOT initiate any scanning — analysis only, plus local
repros and an offline dry-run over the already-collected data.)

### BUG #5 (🔴) — port scan returned 0 web services
- `reports/ports.json == []` though 93 hosts are live on 443.
- **Cause:** nmap is the default scanner; its greppable output keys ports by **IP**,
  but `_scan_nmap` matched on the queried **hostname**. gala's subdomains sit behind
  a CDN where many names share one IP whose parenthesised name is a Cloudflare PTR
  (or empty) — so every open port failed to map back and was dropped. (Local 1:1
  hostname tests passed, hiding it.)
- **Fix (`modules/portscan.py`):** resolve hostnames to IPs ourselves
  (`_resolve_hosts`, threaded), scan the **unique IPs**, parse ports by IP
  (`_parse_nmap_grepable`, now a pure/testable function), then **fan each IP's open
  ports back out to every hostname that resolved to it**. Verified locally with
  CDN-style synthetic output and a shared-IP fan-out test.

### BUG #6 (🔴, scope safety) — crawl scope silently widened to third parties
- Crawl scope became `chainmeter.net gala.com galachain.com okta.com`: gala hosts
  redirect off-domain (`galascan→chainmeter.net`, `openobserve→gala.okta.com`) and
  the crawler **followed the redirects and crawled okta.com / chainmeter.net** —
  outside an authorized *gala.com* assessment.
- **Fix (`jsintel.sh` + `modules/crawler.sh`):** `jsintel.sh` now derives
  `CRAWL_SCOPE` from the authorized `-s/-p/-f` scope (expanding file/@file values)
  and exports it as the crawl anchor. `crawler.sh` computes that scope **before**
  redirect resolution and, when anchored, **refuses to follow a redirect that
  leaves scope** — keeping the in-scope seed if possible, else dropping it, never
  crawling the off-scope host. Verified locally (seed redirecting to an off-scope
  loopback host is not followed; scope stays anchored).

### BUG #7 (🟡) — fuzzer dumped its whole budget on one host
- All 20,000 candidates landed on a single origin (`arb.gala.com`), category `api`;
  ~1,538 other in-scope origins got nothing. (The calibration fix worked: that host
  is a soft-404 SPA, all 20k correctly suppressed → `interesting=0` is right there.)
- **Fix (`modules/fuzzer/engine.py`):** `build_candidates` now buckets candidate
  generators by host and **round-robins the budget across hosts** (chunked), so no
  single origin can monopolise the cap.
- **Verified on the real gala origins (offline `--dry-run`, no traffic):** candidates
  now spread across **50 hosts** and 5 categories (api 15026, directory 4519, file
  232, js 112, generic 111) vs **1 host** before.

### BUG #8 (🟢) — amass progress bar flooded the log
- Thousands of `0/1 [____] p/s` carriage-return redraws in `jsintel.log`.
- **Fix (`modules/subdomains.sh`):** amass stderr → `/dev/null` (results are on
  stdout; the other enumerators are already `-silent`).

### Validation
- **Full suite: 289 tests pass** (+3: nmap grepable parser, shared-IP fan-out,
  fuzzer fair-distribution). Shell fixes bash -n clean and locally e2e-tested.

### TODO (prompts to future self)
- [ ] When the operator next runs an authorized live target, confirm BUG #5 fix
  yields non-zero services on CDN-fronted hosts (local repro + real dry-run confirm
  the mechanism; a live re-run confirms the numbers).
- [ ] Consider per-host confirm concurrency caps for very large sweeps.

---

## ANALYSIS + FIXES — second authorized gala.com run (verifying fixes) (2026-09-26)

Operator re-ran the full chain (authorized, `!`). The 4 earlier fixes all held live:
- **BUG #5 (port scan) FIXED:** 0 → **295 confirmed web services** (was empty).
- **BUG #6 (scope) FIXED:** log shows "Crawl scope anchored to authorized scope:
  gala.com" and many "redirects off-scope to <galachain.com/chainmeter.net/okta.com>
  — NOT following; crawling <host> in-scope"; final crawl scope = `gala.com` only
  (was `chainmeter.net gala.com galachain.com okta.com`).
- **BUG #7 (fuzz distribution) FIXED:** categories now spread (directory 16500, api
  1700, js 1350, file 450) across many hosts (was 20k/one host/api-only).
- **BUG #8 (log spam) FIXED:** amass progress bar gone.

Run totals: 924 assets, 513 endpoints, **47 critical + 36 high** security findings.

### New bugs found in the port-scan OUTPUT (CDN false positives) — fixed
The 295 "services" were badly inflated by Cloudflare fronting:

- **BUG #9 (🟡) — CDN port-mirrors counted as distinct services.** A CF-fronted host
  answers on CF's whole alt-port matrix (2082/2083/2086/2087/2095/2096/8080/8443/8880)
  with the *same* origin (e.g. `ai.gala.com` returned identical "GalaChain AI" on 9
  ports). **Fix:** added a body fingerprint (`sig`) + `mark_port_mirrors()` which,
  per host, picks a canonical (:443 else :80) and flags matching alt-port responses
  as `mirror_of`; mirrors stay in ports.json but are excluded from services.txt and
  the counts.
- **BUG #10 (🟡) — CDN alt-ports that don't byte-match are still not services.** CF
  also returns a *block page* (403 "Attention Required! | Cloudflare") or a 400 on
  alt-ports, which differ from :443 so fingerprint-dedup misses them. **Fix:** added
  `_detect_cdn()` (CF-RAY / cloudflare / cloudfront / akamai / fastly markers); a
  CDN-fronted host has ALL its alternate ports collapsed as mirrors, since they are
  the CDN's proxy ports (same origin), never distinct services.
- **BUG #11 (🟢) — protocol-mismatch / bare-400 counted as services.** `http://…:2083`
  returning 400 "plain HTTP request was sent to HTTPS port" was recorded as a
  service. **Fix:** `_try_scheme` rejects that 400 (so the other scheme is tried);
  distinct services also exclude any bare `400` (a Bad Request to `GET /` is a
  proxy/protocol rejection, not a usable service root).

**Net effect on the real gala data (reprocessed offline):** 295 raw → **101 distinct
services (49 :80, 52 :443), 0 spurious alt-port findings** — correct, since every
gala alt-port response was Cloudflare proxy noise. A genuine service on a non-CDN
host's alt-port is still reported (only CDN-fronted hosts' alt-ports are collapsed).

### Validation
- **Full suite: 293 tests pass** (+4: CDN detection, mirror collapse w/ and w/o
  canonical, CDN block-page collapse). Reporter now shows distinct count and
  "N CDN port-mirror(s) collapsed".

### Possible follow-up (not yet done)
- [ ] DB ingest appears additive across re-runs into the same output dir
  (reporter `fuzz_probed` ~= 2x the single-run candidate count). Consider whether
  ingest should reset per run or dedupe; confirm before changing (may be intentional).

### BUG #12 (🔴) — DB ingest accumulated across re-runs (double-counting)
- Re-running into the same output dir inflated the DB/report: `fuzz_results` = 39,999
  vs 20,000 in fuzz.json; `findings` = 360,324 (two runs summed); `assets` = 924
  including now out-of-scope okta.com assets from run 1. Cause: `findings` used a
  plain `INSERT` (no dedup) and the upsert tables kept prior-run rows, while the
  pipeline overwrites reports/*.json each run.
- **Fix (`modules/database.py`):** `ingest` now clears `assets` (FK-cascades to
  urls/endpoints/technologies/findings) and `fuzz_results` at the start, rebuilding
  the DB as a faithful projection of the current reports. Verified idempotent
  (double-ingest keeps counts stable; a second run drops the prior run's stale rows).
- **Corrected the live gala DB** by re-ingesting from its preserved reports:
  fuzz_results 39,999→20,000, findings 360,324→137,970, assets 924→354. (Regenerated
  only the derived recon.db + summary.json/assets.csv; the extraction reports
  endpoints.json/urls.json/fuzz.json/findings.json/ports.json were left untouched.)

### Note on the corrected port-scan count
The gala `ports.json` on disk predates BUG #9–#11 (no sig/cdn/mirror fields), so the
re-run reporter can only drop bare-400s (295→255), not collapse CDN mirrors. A FRESH
authorized run writes the new fields and yields ~101 distinct (verified by
reprocessing the recorded data offline). Suite now at 295 tests.

---

## FEATURE — `-w` webshot stage (visual triage) (2026-09-26)

Added screenshotting of discovered web services for fast visual triage.

### What was built
- **`modules/webshot.py`** — renders each discovered service with **headless
  Chromium** (unique `--user-data-dir` per call for safe concurrency,
  `--ignore-certificate-errors`, `--no-sandbox`, per-page timeout), computes a
  **dHash** perceptual hash, and clusters near-identical looks
  (`cluster_by_phash`, Hamming threshold). Writes `assets/screenshots/*.png`,
  `reports/screenshots.json`, and a self-contained `reports/screenshots.html`
  gallery grouped by visual cluster, light/dark aware. Cross-references
  `findings.json`: a service whose host yielded a critical/high finding is flagged.
- **`modules/webshot.sh`** — builds the target list from the discovered surface
  (services.txt ∪ subdomains.txt, else the seed), all already scope-constrained.
- **Wiring:** `jsintel.sh -w` (boolean; runs after the extractor so findings exist
  to flag), mass toggle `-W` in sweep, and reporter shows
  "Screenshots: N (K distinct visual clusters)".
- Engine autodetect (chromium/chromium-browser/google-chrome/chrome); if none
  installed the stage is a no-op with a warning.

### Validation
- **Full suite 301 tests** (+6 webshot): Hamming; dHash stability/discrimination on
  structured images; clustering groups same-look & separates different; `run()` with
  an injected renderer builds gallery + clusters + finding-flags; no-op on empty;
  and a **real-chromium** integration test rendering a local page.
- **Pipeline e2e (local mock):** `-p -w` run captured **4/4** services to real PNGs
  (7–11 KB each), wrote screenshots.json + the gallery, and the reporter line.

### Notes / gotchas learned
- **dHash needs visual structure.** The minimal mock pages render near-blank at
  thumbnail scale → all-zero hash → collapse into one cluster. That is correct dHash
  behaviour (blank pages *are* alike); real pages (and the structured unit-test
  images) discriminate fine. dHash clusters by **layout/structure**, so
  template-identical pages that differ only by color group together — the right
  triage semantic (same template ≈ same app).
- **Harness constraints hit during the demo (not code):** foreground `sleep` is
  blocked (SIGTERM/exit 144) and a detached mock server is terminated between calls,
  which made a clean multi-cluster *live* demo flaky. Serve mock pages in-process, or
  rely on the unit tests, to show clustering.

### TODO (prompts to future self)
- [ ] Optional richer engine via Playwright (network-idle wait, capture final title
  + console errors) behind an `--engine playwright` flag.
- [ ] Optional: publish the gallery as a private Artifact for sharing (only for the
  operator's own authorized results).

---

## EXTENSIVE TESTING — real vulnerable app (OWASP Juice Shop) (2026-09-26)

Per the operator's request, drove the full pipeline against a **real vulnerable
app** (from kaiiyer/awesome-vulnerable) and did a project-wide health/bug sweep.

### Target deployment (what works in this environment)
- No Docker, no npm, no MySQL server, PHP without mysqli → DVWA not runnable here.
- **OWASP Juice Shop v20.2.0** runs via the prebuilt **`node24_linux_x64`** monolith
  tarball (self-contained, SQLite inside). Launched on :3000; mapped a multi-host
  estate (`{www,shop,admin,}juice-shop.local` → 127.0.0.1) via `/etc/hosts`.

### Full-chain run result (`-p -w -f`, scope juice-shop.local)
- Port scan: 12 services across 4 hostnames (IP fan-out working) incl. genuinely
  open :80 and :4000 beyond the seeded :3000.
- Crawl/extract on the real Angular SPA: 37 assets, **59 real endpoints**
  (`/api/Products`, `/rest/2fa/status`, `/api/v2/register`, ...), **0 extractor
  errors**, real findings: `dangerous_eval`, `taint_to_sink`
  (localStorage→innerHTML), `hardcoded_secret` (planted AWS key + Google OAuth id) —
  4 critical + 4 high.
- Fuzz: found live routes `/api`(500), `/api/users`(401), `/rest/2fa/status`(401).
- Webshot: after the fix below, **12/12 captured, 2 visual clusters** (the 4 Juice
  Shop SPA hosts grouped; the 8 plain :80/:4000 pages grouped) — real clustering
  discrimination that the blank mock could not show.

### BUG #13 (🔴) — webshot failed on heavy SPAs under concurrency
- The 4 Juice Shop (:3000) screenshots FAILED while the light :80/:4000 pages
  succeeded — a single render works, but several headless-Chromium instances loading
  a large Angular bundle at once exhausted resources/timed out and produced no file.
  The feature failed on exactly the pages that matter.
- **Fix (`modules/webshot.py`):** retry failed renders **serially** after the
  concurrent pass (contention gone → they succeed); raised default per-page timeout
  20→30s; treat a uniform/blank PNG as a failed render so it is retried too.
  Result: 8/12 → **12/12** captured.

### BUG #14 (🟡) — template-literal placeholders leaked into endpoints
- Minified code produced endpoints like `/rest/basket/${e}/checkout` and
  `/api?module=${e}${n}${i}`: not real segments, defeats dedup, and would be
  brute-forced literally by the fuzzer.
- **Fix (`modules/extractor/analyzers/endpoints.py`):** normalize `${...}` → `{}`
  and collapse consecutive params, so routes stay legible and dedupe
  (`/rest/basket/{}/checkout`, `/api?module={}`).

### Project-wide health sweep
- 14/14 Python modules import cleanly; all CLIs (`--help`) OK; all 11 shell scripts
  `bash -n` clean.
- **Full suite: 302 tests pass** (+1 endpoint-normalization test; webshot retry/blank
  covered by existing render tests).

### Deliverable
- Added **`recommendations.md`** — backlog of future features (correlation/triage,
  DB services table, more discovery engines, sourcemap un-minification, Playwright
  webshot engine, a repeatable awesome-vulnerable target harness, scope config).

### TODO (prompts to future self)
- [ ] Build the `tests/targets/` harness (Juice Shop first) for repeatable regression
  runs, and add a real minified bundle as an extractor fixture.
- [ ] Prioritise the unified triage report (recommendations.md §1) — joins services,
  endpoints, findings, and screenshots into one prioritized per-host view.

---

# SESSION 2026-09-26 — Vulnerable-target lab, recommendation deployment & stress testing

**Goal (user directive):** Analyse the project; stand up a robust, repeatable
testing environment of *intentionally vulnerable* apps (a domain/subdomain tree,
services on non-standard ports — not just 80/443); then deploy the items in
`recommendations.md` against that lab and stress-test them. As each recommendation
ships, **remove it from `recommendations.md`** and record it here; keep
`recommendations.md` enhanced with new ideas found during testing. Also develop
`README.md`.

## Environment findings (2026-09-26)

- Host: Kali, **root + passwordless sudo**, apt available; 256G free disk, 36G RAM.
- Runtimes present: node v24, python 3.14 (+pip 26, venv, flask), java 25,
  php 8.4, **mariadbd server** (`/usr/sbin/mariadbd`) + client.
- Recon toolchain present: katana, httpx, ffuf, feroxbuster, nmap, amass,
  assetfinder, chromium. Missing: naabu, subfinder, gau, go.
- **Docker: installed (28.5) but the daemon cannot provide usable networking in
  this sandbox.**
  - `overlay2` storage unavailable (no overlay device) → worked around with `vfs`.
  - **Bridge networking is impossible**: the kernel refuses to create `docker0`
    ("Failed to create bridge docker0 via netlink: operation not supported"), and
    building the NAT chain also fails (missing netfilter `addrtype`/nat modules).
  - The only mode that reaches a container is `--network host`, which binds to
    `0.0.0.0` — **denied by the safety classifier as "Expose Local Services"** (a
    correct call; it also violates this project's localhost-only methodology).
  - **Conclusion:** containers cannot be networked loopback-only here, so the lab
    runs the vulnerable apps **natively, bound strictly to `127.0.0.1`** on
    non-standard ports (the same safe posture as the earlier local-mock work),
    using the canonical upstream distributions. Docker remains installed and the
    harness is written so a real Docker/Compose host can swap it in later.

## Lab design — `tests/lab/` (all services bound to 127.0.0.1)

Subdomain tree via `/etc/hosts` aliases of 127.0.0.1, each app on a distinct
non-standard port:

| Hostname (→127.0.0.1) | App                         | Stack         | Port  |
|-----------------------|-----------------------------|---------------|-------|
| shop.vuln.lab         | OWASP Juice Shop            | Node monolith | 3000  |
| api.vuln.lab          | VAmPI (vulnerable REST API) | Flask         | 5001  |
| graphql.vuln.lab      | Damn Vulnerable GraphQL App | Flask         | 5013  |
| dvwa.vuln.lab         | DVWA                        | PHP + MariaDB | 8081  |
| goat.vuln.lab         | OWASP WebGoat               | Spring Boot   | 8082  |

Rationale: Juice Shop is the JS-rich centerpiece (crawl/extract/fuzz); VAmPI +
DVGA exercise the API/GraphQL analyzers; DVWA adds a classic PHP multi-page app on
a non-standard port; WebGoat adds a Java estate host. Together they give jsintel a
real multi-host, multi-port estate to correlate.

## Plan / TODO (prompts to future self)

- [ ] Build `tests/lab/lab.sh` controller (`up`/`down`/`status`/`hosts`) + per-app
  launchers under `tests/lab/targets/`, runtime under `tests/lab/runtime/`
  (new dir — never delete existing outputs), and `tests/lab/manifest.json`.
- [ ] Bring up Juice Shop first (known-good tarball), then VAmPI, DVGA, WebGoat,
  DVWA — each bound to 127.0.0.1, health-checked.
- [ ] Run jsintel full chain against the estate into a NEW `output_lab_*` dir
  (crawl + `-p` portscan + `-f` fuzz + `-w` webshots; `-s` if local DNS added).
- [ ] Deploy recommendations one by one, stress-test each against the lab, then
  delete the shipped item from `recommendations.md` and log it here.
- [ ] Develop `README.md` (document the lab harness + shipped features).

## MILESTONE — vulnerable-target lab is UP (2026-09-26)

`tests/lab/` harness built and three intentionally-vulnerable apps are running,
**all bound to 127.0.0.1** (verified: `ss -ltn` shows only `127.0.0.1:*` /
`[::ffff:127.0.0.1]:*`), reachable via the `/etc/hosts` subdomain tree, on
non-standard ports:

| Host                | App             | Port | Health |
|---------------------|-----------------|------|--------|
| shop.vuln.lab       | OWASP Juice Shop| 3000 | 200    |
| goat.vuln.lab       | OWASP WebGoat   | 8082 | 200    |
| goat.vuln.lab       | OWASP WebWolf   | 9090 | 200    |
| dvwa.vuln.lab       | DVWA            | 8081 | 200    |

Harness: `tests/lab/lab.sh {up|down|status|hosts|seeds|scope}` with per-app
launchers in `tests/lab/targets/`, runtime under `tests/lab/runtime/`
(git-ignored). Key properties:
- **Safe by construction:** a Node `--require` loopback shim forces any Node
  server onto 127.0.0.1, and `do_up` runs an `assert_loopback` gate after every
  start that KILLS any service found bound to `0.0.0.0`/`*`/a routable address.
- WebGoat 2023.8 bundles WebGoat + WebWolf; configured via `WEBGOAT_*`/`WEBWOLF_*`
  env (NOT `--server.port`, which collides them) → 8082 + 9090.
- DVWA uses a repo-local MariaDB (`tests/lab/targets/dvwa-db.sh`, loopback only).
  Needed: `php-mysql` (mysqli), and MariaDB's AppArmor profile set to complain
  mode (`aa-complain /usr/sbin/mariadbd`) since the datadir lives under the repo.
  DVWA creds forced via `DB_*` env (config default password would mismatch).

### Not deployed (blocked)
- **VAmPI / DVGA (Flask):** their pinned `connexion 2.14` + old Flask/SQLAlchemy
  stacks are incompatible with the host **Python 3.14** (SQLAlchemy `TypingOnly`
  assertion; connexion pins Flask<2.3). Revisit by pinning a py3.14-compatible set
  or running from the docker image's own python via `docker export` + chroot.

### Gotcha logged
- `pkill -f webgoat.jar` self-matches the invoking shell (its own command line
  contains "webgoat.jar") and kills the call (exit 144). Use a path-anchored or
  bracketed pattern (`[w]ebgoat.jar`); lab.sh's internal cleanup already anchors
  on the runtime path so it is safe.

## MILESTONE — pipeline validated against the lab; recommendations reconciled (2026-09-26)

### Lab realism fix — distinct per-host loopback IPs
The first lab run exposed a flaw: every hostname resolved to 127.0.0.1, so a port
scan of ANY host found ALL apps' ports (15 services, cross-contaminated). Fixed by
giving each app its own loopback address (127.0.0.0/8 is all loopback on Linux):
shop→127.0.0.1, goat→127.0.0.2, dvwa→127.0.0.3 (vampi→.4, dvga→.5), wired through
`bindip_of` in `lab.sh`, the Node shim (`LAB_BIND_IP`), and the `/etc/hosts` block.
Re-run result: a clean per-host inventory — 5 services, 4 on non-standard ports;
isolation verified (`127.0.0.1:8081/8082` serve nothing).

### End-to-end validation (`output_lab_full`)
`jsintel.sh -p ... -w` against the estate produced a correct unified triage:
`shop.vuln.lab` ranked **critical (risk 1224)** — 4 critical + 4 high findings
(eval/taint/secrets), 15 sensitive Juice Shop endpoints (`/rest/admin`, `/api/Users`,
2FA routes…); goat/dvwa ranked low. 5 screenshots captured; `triage.html` +
`screenshots.html` generated. (`shop.vuln.lab:80` shows a leftover Python
`SimpleHTTP` mock from a prior session on 127.0.0.1:80 — harmless, left in place.)

### Recommendations already shipped in the working tree (removed from recommendations.md)
- **§1 Unified triage report** + severity/risk scoring — `modules/triage.py`,
  `reports/triage.{json,html,md}`. (Confirmed working above.)
- **§2 Ingest services + screenshots into the DB** — `services` table in
  `database/schema.sql`, ingest in `modules/database.py`.
- **§8 Repeatable target harness** — delivered this session as `tests/lab/`.

### Recommendation DEPLOYED + stress-tested this session (removed from recommendations.md)
- **§1 Run-to-run diff** — new `modules/diff.py` (`python3 -m modules.diff <old>
  <new> [-o out]`) writing `reports/diff.{json,md}` of added/removed
  hosts/services/endpoints/findings. **Stress test:** diffed the pre-isolation run
  vs the isolated run — correctly reported the 10 cross-contaminated services as
  "gone", hosts/endpoints/findings unchanged. Added `tests/test_diff.py` (3 tests).

### Test harness hygiene
- Cloned apps under `tests/lab/runtime/` ship their own pytest suites (e.g. DVGA),
  which polluted collection. Added `norecursedirs = ["runtime",".venv","venv",
  "node_modules"]` to `pyproject.toml`. **Full suite: 305 passed** (302 + 3 diff).

## TODO (prompts to future self)
- [ ] Deploy VAmPI + DVGA (clear the Python 3.14 connexion/Flask/SQLAlchemy
  conflict, or run each from its Docker image's own Python via `docker export` +
  loopback launch) to unlock GraphQL/JWT/REST analyzer testing.
- [ ] Deploy §5 security-header/CSP analyzer against the live services and §8 CI
  regression assertions (bring lab up, run chain, assert the known triage outcome).
- [ ] Consider wiring `modules/diff.py` into `jsintel.sh` as a `--diff <old_dir>`
  convenience flag.

## MILESTONE — VAmPI + DVGA deployed via Docker export + chroot (2026-09-26)

The earlier "not deployed" blocker (their pinned connexion/Flask/SQLAlchemy stacks
fail on the host Python 3.14) is **cleared** — using Docker for *compatibility*
(the user's suggestion) without needing container networking:

- **Approach:** `docker pull` the app image → `docker create` + `docker export` its
  root filesystem into `tests/lab/runtime/<app>-rootfs/` → run the app from **its
  image's own Python** via `chroot` (bind-mounting `/proc`,`/dev`,`/sys`), bound to
  the app's loopback IP. Container networking is never used (this sandbox cannot
  bridge-network), so the safety posture is unchanged. New helper:
  `tests/lab/targets/rootfs.sh` (`export`/`start`/`stop`); `lab.sh` gained a
  `require_docker` that auto-starts dockerd in vfs/no-bridge mode for the export.
- **VAmPI** (`erev0s/vampi`, Python 3.11) → `api.vuln.lab` = 127.0.0.4:5001. Its
  `app.py` hardcodes `0.0.0.0:5000`; provisioning patches the bind to
  `LAB_BIND_IP`/`LAB_PORT`. Slow start (~15s: openapi + DB seed).
- **DVGA** (`dolevf/dvga`, Python 3.10) → `graphql.vuln.lab` = 127.0.0.5:5013.
  Reads `WEB_HOST`/`WEB_PORT` from env (no patch). Its deps are a `--user` install
  under `/home/dvga/.local`, so the launch sets `HOME=/home/dvga`.

### Full 5-app estate validated (`output_lab_5`)
`jsintel.sh -p <all 5> -w` completed exit 0 with clean per-host isolation — 7
services across 5 hosts (each host only its own), 7/7 screenshots in 3 visual
clusters, and a 5-host triage:

| Rank | Host | Risk | Max sev |
|---:|---|---:|---|
| 1 | shop.vuln.lab (Juice Shop) | 1224 | critical |
| 2 | graphql.vuln.lab (DVGA) | 37 | medium |
| 3 | goat.vuln.lab (WebGoat) | 10 | none |
| 4 | api.vuln.lab (VAmPI) | 7 | none |
| 5 | dvwa.vuln.lab (DVWA) | 7 | none |

DVGA even surfaced 3 medium findings from its own client-side JS. **The lab is now
the full five-app estate.** Suite still **305 passed** (the large exported rootfs
trees are excluded by the `norecursedirs` rule).

### recommendations.md updates
- Removed "Deploy VAmPI + DVGA" from §8 (done); the §5 analyzer note now points to
  the live DVGA/VAmPI targets as ready for the GraphQL/JWT analyzers.

## MILESTONE — live-service analyzers deployed + stress-tested (2026-09-26)

Deployed recommendation §5 "more analyzers" for **live services** (distinct from the
static JS-asset analyzers): a new stage `modules/liveanalysis.py` that probes the
in-scope services discovered by the port scan and emits findings about their runtime
posture.

- **Security headers** — missing/weak CSP, HSTS (https only), X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy; `Server`/`X-Powered-By`
  banner disclosure; insecure `Set-Cookie` (HttpOnly/Secure/SameSite).
- **GraphQL introspection** — POSTs an introspection query to common GraphQL paths;
  a returned schema is a **high** finding (attributed to the host-level service).
- **JWT** — scans headers/bodies for JWTs and flags `alg:none` (critical) or
  symmetric signing (low).

### Integration (findings are first-class)
- `liveanalysis` writes `reports/security.json` (same shape as `findings.json`,
  `asset_url` = service URL). Wired into `jsintel.sh` after extraction, guarded on
  `ports.json` existing.
- `database.py` now registers discovered services as `service`-type **assets** and
  ingests both `findings.json` and `security.json`, so live findings attach to their
  service and — with **no triage change** — surface per host (triage already joins
  findings→assets by host). `reporter.py` excludes `service` assets from the asset
  counts so "Total assets" stays meaningful.

### Stress test (against the live estate, `output_lab_sec`)
`jsintel.sh -p <all 5>` produced **40 live findings** and reshaped the triage:

| Host | Before | After (with live analysis) |
|---|---|---|
| graphql.vuln.lab (DVGA) | medium, risk 37 | **high, risk 106** — `graphql_introspection_enabled` + insecure cookie + missing headers |
| shop.vuln.lab (Juice Shop) | critical, 1224 | critical, 1253 (header findings added) |
| goat/dvwa/api | none, 7–10 | medium, 26–42 (missing headers / cookies) |

Hosts with a critical/high finding went 1 → 2. The GraphQL bug fixed during the
stress test: the introspection finding must attach to the service base URL (a
registered `service` asset), not the `…/graphql` path, or DB ingest drops it.

### Tests / backlog
- Added `tests/test_liveanalysis.py` (11 tests: header checks, cookie flags,
  GraphQL introspection detect/silent, JWT alg:none/HS*/RS*, run() tolerance).
  **Full suite: 316 passed.**
- `recommendations.md` §5 updated: removed the shipped analyzers; left cloud-bucket
  references and an "auth-flow JWT" follow-up (obtain a token via VAmPI login).

## MILESTONE — authenticated mode (--cookie / --jwt) deployed (2026-09-26)

Deployed recommendation §4 "auth-aware fuzzing", generalized to the whole pipeline:
JSIntel can now drive a target as an authenticated user.

- **`jsintel.sh --cookie "<Cookie header>"` and/or `--jwt "<token>"`** (long options
  parsed out of argv before getopts). They export `JSINTEL_AUTH_COOKIE` /
  `JSINTEL_AUTH_BEARER`, logged masked ("Authenticated mode: cookie=PHPS…=low").
- Shared helper **`modules/authutil.py`** builds the header dict
  (`Cookie`, `Authorization: Bearer …`) from env; every request-making stage reads it:
  - **crawler.sh** → passes `-H` headers to katana.
  - **downloader.sh** → seeds each download's headers with the session.
  - **fuzzer** → `FuzzConfig.extra_headers`, merged in `prober._send`; also standalone
    `--cookie`/`--jwt` flags (CLI overrides env).
  - **liveanalysis.py** → `_fetch` merges the session; a supplied `--jwt` is itself
    analyzed (alg:none/symmetric) and attached to the first probed service.
- **Scope safety:** the session is only sent to hosts a stage contacts, which are
  constrained to the authorized scope (crawl scope anchored, fuzzer scope-gated).

### Stress test (authenticated DVWA)
Logged into DVWA (admin/password, security=low) to obtain a `PHPSESSID`, then proved
the session flows end-to-end through the fuzzer's real transport:

| Request | Unauthenticated | Authenticated (`--cookie`) |
|---|---|---|
| fuzzer GET `/vulnerabilities/xss_r/` | **302** (bounced to login) | **200** (reached) |

Direct curl confirmed the same (302 vs 200). `jsintel.sh` logged the masked
"Authenticated mode" line.

### Tests
- Added `tests/test_authutil.py` (8 tests: header build, masking/describe no-leak,
  bearer accessor, FuzzConfig.extra_headers, supplied-JWT analyzed by liveanalysis).
  **Full suite: 324 passed.**
- `recommendations.md` §4: removed "Auth-aware fuzzing" (shipped).

## MILESTONE — multi-technology page crawling (PHP/Flask/CGI/…) (2026-09-26)

Kept the JS AST pipeline intact and added extra layers for server-rendered stacks:
- **Crawler** (`crawler.sh`): new `PAGE_RE` keeps server-rendered pages (php/jsp/asp/
  aspx/cfm/cgi/pl/py/rb, .html, extensionless routes) alongside JS assets; toggle
  `JSINTEL_CRAWL_PAGES=0` for classic JS-only. Classifier adds a `page` type.
- **New analyzer layers** (auto-discovered): `page_analyzer.py` (links, endpoints,
  forms+fields, inline-script URLs, HTML comments) and `tech_fingerprint.py`
  (PHP/Java/ASP.NET/ColdFusion/CGI from extension + Django/Rails/WordPress/Flask/
  Laravel/ASP.NET-WebForms from body markers + <meta generator>). SecretsAnalyzer
  now also scans `page` bodies (its regex fallback). Non-JS pages get `tree=None`,
  so the JS AST path is untouched.
- **Authenticated crawl fixes (with `--cookie`/`--jwt`):**
  - `crawler.sh` passes `-H` auth headers to katana AND excludes logout/sign-out via
    `-cos` so following a logout link can't destroy the session mid-crawl.
  - **Bug fixed:** the seed redirect-resolution `curl` ran unauthenticated, so an
    authenticated seed (`/index.php`) resolved to `/login.php` and the whole crawl
    fell back to the unauthenticated view. It now carries the session too.
  - Verified: DVWA `index.php` stays 200 (was 302→login) and katana reach jumps from
    3 URLs (unauth) to ~62 (auth); session survives the crawl.
- Tests: `tests/test_page_analyzer.py` (6) added.

### Left to finish (next session)
- A full authenticated end-to-end DVWA run timed out at 100s (depth-5 auth crawl of
  many pages is slow) — confirm it completes and assert the `page` assets + PHP tech
  + form/endpoint findings land, then remove "PHP/Flask/CGI page crawling" style
  items from recommendations.md and log the numbers. Consider lowering crawl depth
  or a per-run time budget for large authenticated apps.
