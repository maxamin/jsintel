# Architecture

## Pipeline order (`jsintel.sh`, single-target mode)

```
argv pre-pass: --cookie/--jwt -> env JSINTEL_AUTH_COOKIE/JSINTEL_AUTH_BEARER
               --forms -> FORMS=1 ; --proxychains [conf] -> re-exec whole script under proxychains4 (once, guard JSINTEL_UNDER_PROXYCHAINS)
getopts -i -o -t -s -p -w -f -m -S -P -W -F -v -h
-m <file>  -> exec modules/sweep.sh (mass mode; each target runs jsintel.sh again in its own dir)

CRAWL_SCOPE = union of -s/-p/-f scope values (files/@files expanded, host-only, lower-case)
 1. modules/subdomains.sh <scope>         (-s)  -> assets/subdomains_hosts.txt, assets/subdomains.txt
 2. modules/portscan.sh <scope> <input>   (-p)  -> assets/portscan_hosts.txt, assets/services.txt, reports/ports.json
    if -s or -p: seeds = input + subdomains.txt + services.txt -> assets/seeds.txt
 3. modules/crawler.sh <seeds>                  -> assets/crawled_urls.txt         (katana; scope filter; redirect resolution)
 4. modules/classifier.sh crawled_urls.txt      -> reports/assets.json             (url,type) + <bundle>.js.map candidates
 5. modules/downloader.sh assets.json           -> assets/NNNNNN_name + assets.json enriched (local_path, sha256, size, mime, status)
 6. modules/extractor.sh assets.json            -> reports/{urls,endpoints,websocket,imports,frameworks,findings,errors}.json
 7. discover loop (JSINTEL_DISCOVER_ROUNDS, default 3): modules/discover.py fetches new in-scope paths -> appends assets.json -> re-run 6
 8. modules/liveanalysis.py   (if reports/ports.json non-empty) -> reports/security.json, reports/api_spec_endpoints.json
 9. modules/webshot.sh        (-w)  -> assets/screenshots/*.png, reports/screenshots.{json,html}
10. modules/fuzzer.sh <scope> (-f)  -> reports/fuzz.json, fuzz_summary.json
11. python -m modules.forms.main (--forms) -> reports/forms.json; new endpoints appended to assets/crawled_urls.txt
12. modules/database.py ingest  -> database/recon.db  (DELETE + rebuild from reports/*.json)
13. modules/reporter.py         -> reports/summary.{md,json}, assets.csv
14. modules/triage.py           -> reports/triage.{json,md,html}
```

Note that forms (step 11) runs after the last extraction. The endpoints it appends to
`crawled_urls.txt` are not re-classified or re-extracted in the same run.

## Output directory layout

```
<out>/
  assets/  crawled_urls.txt seeds.txt subdomains*.txt portscan_hosts.txt services.txt webshot_targets.txt
           000001_<name> ... (downloaded bodies)   screenshots/   flows/ (listener --aggressive)
  database/recon.db
  logs/jsintel.log
  reports/ assets.json urls.json endpoints.json websocket.json imports.json frameworks.json
           findings.json errors.json security.json api_spec_endpoints.json ports.json
           fuzz.json fuzz_summary.json forms.json screenshots.{json,html} anomalies.json
           summary.{md,json} assets.csv triage.{json,md,html} diff.{json,md} .discovered.json
```

Mass sweep: `<out>/targets/<domain>/` holds one full tree per target, plus
`<out>/reports/sweep_summary.{json,md}`. Per-target `.sweep_status` and `sweep_target.log`.

## Design invariants (do not break them)

1. **Stages communicate only through files in `$OUTPUT_DIR`.** Shell stages get
   `OUTPUT_DIR`, `LOG_FILE`, `CONFIG`, `THREADS`, `VERBOSE` from the environment
   (`jsintel.sh` exports them). Every Python CLI takes `--output`.
2. **The reports are the source of truth. The DB is derived from them.** `ingest()`
   deletes and rebuilds the asset, fuzz, and services rows on every run. A re-run
   must never double-count.
3. **Scope anchoring.** `CRAWL_SCOPE` is computed before redirect resolution, so a
   redirect off-scope is never followed (`crawler.sh`). The scope match is equality
   or a dotted suffix (`host_in_scope`, awk filters, `fuzzer.scope.Scope.allows`). IP
   literals scope to the exact address (`reg_dom` passes IPv4/IPv6 through unchanged).
   An empty fuzzer scope allows nothing.
4. **Discovery never adds a host.** `discover.py` only builds URLs on hosts that are
   already in the manifest.
5. **One bad asset never aborts a scan.** Analyzer exceptions are logged to
   `errors.json`, reader failures are recorded, and the downloader bounds every asset
   (`max_seconds`, `max_bytes`, `raw.read1`).
6. **Output JSON stays backward compatible.** The extractor writes JSON arrays
   atomically (temp file, then rename). Field names in the reports are consumed by
   `database.py`, `diff.py`, `triage.py`, `fuzzer.engine`, `discover.py`, and
   `sweep_aggregate.py`, so grep all of them before renaming a field.
7. **External tools are optional with graceful fallback.** No katana means the seeds
   are treated as assets. No nmap or naabu means a pure-Python connect scan. No
   chromium means webshot and the forms browser are skipped. No tree-sitter means
   analyzers get `tree=None` and use their regex fallbacks.
8. **Close stdin for external tools.** Run them with `</dev/null`. katana blocks forever
   on an inherited pipe (Bug #2 in TESTING_PROGRESS).
9. **Never edit a bash script while a live sweep is running it.** bash reads scripts
   incrementally, so editing one mid-run corrupts the run.

## Two architectures co-exist

- **Phase 1 (live):** `jsintel.sh` + `modules/`. All real behaviour lives here.
- **Phase 2 (scaffold):** `src/jsintel/` (typed models, `Plugin` ABC with dependency-ordered
  `PluginRegistry`, `KnowledgeGraphStore`, `MigrationManager`) + `database/migrations/0001_platform.sql`.
  Only `tests/test_{models,plugins,storage,config}.py` import it. `docs/ARCHITECTURE.md` and
  `docs/PLUGINS.md` describe the target design. Do not route new pipeline features through
  Phase 2 unless the task is the migration itself. The extractor has its **own** plugin
  system (`modules/extractor/analyzer.py`), which is separate from `jsintel.plugins.Plugin`.

## Alternative entry points

- `python3 -m modules.listener` is a loopback daemon. It takes pushed captures
  (HAR, native JSON, or WebSocket) and runs classify, extract, passive live analysis,
  ingest, report, and triage for each site. It has no crawl and no download step. See listener.md.
- `integrations/mitmproxy/jsintel_mitm.py` is a mitmproxy addon that streams proxied
  flows into the listener.
- Each module is also a standalone CLI (see configuration.md).
