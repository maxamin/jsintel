# Data contracts: report JSON, DB, triage, diff, sweep

Report JSON files are consumed by several readers. Before renaming or removing a
field, grep all of `modules/`, `tests/`, and `integrations/`.

## Report records (`<out>/reports/`)

| File | Writer | Record shape |
|---|---|---|
| `assets.json` | classifier, then downloader, then discover | `{url, type, local_path?, sha256?, size_bytes?, mime_type?, status: discovered|downloaded|failed, error?}` |
| `urls.json` | extractor | `{asset_url, url, kind:"url"}` |
| `endpoints.json` | extractor | `{asset_url, endpoint, kind: api|form|...}` |
| `websocket.json` | extractor | `{asset_url, url, kind:"websocket"}` |
| `imports.json` | extractor | `{asset_url, module}` |
| `frameworks.json` | extractor | `{asset_url, technology, evidence}` |
| `findings.json` | extractor | `{asset_url, finding_type, severity, value, source, sink}`: security and recon signal only |
| `code_intel.json` | extractor | Same shape, holding `call_graph`, `class`, `export` and `cross_asset_*`. `SecurityFinding.__post_init__` routes `CODE_INTEL_TYPES` here. They were 95% of all "findings" in the sweep. Not ingested into the DB. |
| `stages.tsv` | jsintel.sh `stage` | `name<TAB>seconds<TAB>rc` per stage run; folded into `summary.json` `stages` |
| `summary.json` `pipeline`/`stages` | reporter | `crawl_kept`, `downloads` by status (`downloaded`/`failed`/`blocked`), `screenshots_attempted/captured`; per-stage `{seconds, rc, runs}` |
| `prefilter.json` (sweep) | sweep_prefilter | per-run counts, wildcard parents with their representative, `skipped: {target: reason}` |
| `errors.json` | extractor | `{asset_url, analyzer, message}` |
| `security.json` | liveanalysis | same shape as findings, `source:"live-service"`, `asset_url` = service URL |
| `api_spec_endpoints.json` | liveanalysis | endpoint records harvested from OpenAPI `paths` |
| `ports.json` | portscan | `{host, port, scheme, url, status, server, title, cdn?, mirror_of?}` |
| `fuzz.json` / `fuzz_summary.json` | fuzzer | see active-stages.md (interesting results first) |
| `forms.json` | forms | per-page forms, fill plans (masked), submit results, captured endpoints |
| `screenshots.json` | webshot | `{url, file, cluster, ...}` |
| `anomalies.json` | listener `--aggressive` | `{url, kind, severity, added_secrets?, ...}` |
| `summary.{md,json}`, `assets.csv` | reporter | headline counts |
| `triage.{json,md,html}` | triage | ranked hosts |
| `diff.{json,md}` | diff | added/removed hosts, services, endpoints, findings |

Severities are `critical`, `high`, `medium`, `low`, `info`, and every module orders
them that way.

## SQLite (`<out>/database/recon.db`, schema `database/schema.sql`)
Tables: `assets` (url UNIQUE, asset_type includes the synthetic `service`), `urls`,
`endpoints`, `technologies`, `findings` (FK to assets, ON DELETE CASCADE), `fuzz_results`
(url UNIQUE), `services` (url UNIQUE, mirror_of, screenshot_path, cluster).
`ingest()` is idempotent per output dir: it deletes and rebuilds the tables. There is
no run id or history yet (backlog: per-run provenance). Ad-hoc access:
`python3 modules/database.py --output OUT query "SQL"` prints JSON lines.

Schema changes: Phase 1 uses `CREATE TABLE IF NOT EXISTS` in `schema.sql`. Adding a
column to an existing table needs a guarded `ALTER`, because existing DBs will not
pick up the new column. Phase 2 uses append-only migrations (`database/migrations/`):
never edit a released migration.

## Triage scoring (`modules/triage.py`)
`score = Σ findings SEVERITY_WEIGHT{crit 100, high 40, med 10, low 3, info 0}
       + min(40, 4 × sensitive endpoints)          # SENSITIVE_ENDPOINT_PATTERNS: admin, auth, token, graphql, .git, config, debug...
       + min(30, 5 × non-standard-port services + 2 × open-200-no-auth)`
Hosts come from the asset URL host. Values are masked. Expected lab outcome:
`shop.vuln.lab` (Juice Shop) ranks critical.

## Diff and sweep
- `python3 -m modules.diff OLD NEW [-o OUT]` reads only report JSONs and tolerates
  missing or malformed files.
- `python3 -m modules.sweep_aggregate --output SWEEP_OUT t1 t2 ...` derives the
  directory names with `sanitize()` (`/` and `:` become `_`, as `sweep.sh` does).
