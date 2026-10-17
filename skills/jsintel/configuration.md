# Configuration: flags, environment, config.yaml

## `jsintel.sh` flags
`-i FILE|URL` seeds (required unless `-m`) · `-o DIR` (default `./output`) · `-t N` workers
(default `config threads`=50) · `-s SCOPE` subdomains · `-p SCOPE` port scan · `-w` screenshots ·
`-f SCOPE` fuzz · `-m FILE` mass sweep with `-S -P -W -F` per-target toggles · `-v` verbose ·
`--cookie "k=v; ..."` · `--jwt TOKEN` · `--forms` · `--proxychains [conf]` · `-h`.
A SCOPE value is a domain, a comma- or space-separated list, a file of domains, or
`@file`. The union of all scopes becomes `CRAWL_SCOPE`.

## Environment variables (`JSINTEL_*`)

| Var | Default | Effect |
|---|---|---|
| `JSINTEL_AUTH_COOKIE` / `JSINTEL_AUTH_BEARER` | – | Session sent by all stages (set by `--cookie`/`--jwt`) |
| `CRAWL_SCOPE` | derived | Crawl scope override; `off` disables filtering (dangerous) |
| `JSINTEL_DEPTH` | config `crawler.depth` (5) | katana depth |
| `JSINTEL_CRAWL_PAGES` | 1 | 0 = classic JS-only crawl (no server-rendered pages) |
| `JSINTEL_LOGOUT_RE` | `logout\|logoff\|signout\|...` | katana `-cos` exclude when authenticated |
| `JSINTEL_MAP_DISCOVERY` | 1 | Add `<bundle>.map` candidates |
| `JSINTEL_EXTRACT_WORKERS` | min(cpu, 8) | 1 = sequential extraction |
| `JSINTEL_SPLIT_BYTES` | 200000 | Big-bundle analyzer split threshold (0 = off) |
| `JSINTEL_DISCOVER_ROUNDS` / `JSINTEL_DISCOVER_LIMIT` | 3 / 200 | Feedback discovery loop |
| `JSINTEL_PORTS` | curated list | Port spec for `-p` |
| `JSINTEL_PORTSCAN_ARGS` / `JSINTEL_WEBSHOT_ARGS` / `JSINTEL_WEBSHOT_WORKERS` | – / – / 6 | Pass-through options |
| `JSINTEL_FUZZ_ARGS` | – | e.g. `--dry-run`, `--offline --delay 0.1` |
| `JSINTEL_FORMS_ARGS` | – | e.g. `--no-submit`, `--browser --settle 6`, `--deny term` |
| `JSINTEL_SWEEP_PARALLEL` | 3 | Concurrent targets in `-m` |
| `JSINTEL_UNDER_PROXYCHAINS` | – | Internal re-exec guard |
| `JSINTEL_LISTEN_TOKEN` | – | Listener shared-secret header |
| `JSINTEL_LISTEN_URL`, `JSINTEL_SCOPE` | – | mitmproxy addon target and scope |

Env vars the pipeline exports internally: `OUTPUT_DIR LOG_FILE CONFIG THREADS VERBOSE FORMS`,
and in sweep mode `SWEEP_SUBS/PORTS/FUZZ/WEBSHOT/THREADS`.

## `config/config.yaml`
```yaml
threads: 50
crawler: {depth: 5, javascript: true}
download: {timeout: 15, retries: 3, max_seconds: 90, max_bytes: 26214400}
database: {path: output/database/recon.db}   # ignored by database.py (always <out>/database/recon.db)
```
Optional top-level keys read by `subdomains.sh`: `subdomain_timeout`, `download_timeout`,
`timeout`. Shell code reads nested keys with inline awk, not a YAML parser. Keep the
file simple (two-space indentation, `key: value`, no flow style in nested blocks the
awk reads).

## Standalone CLIs
```
python3 -m modules.extractor.main --manifest M --output DIR [--verbose]
python3 -m modules.fuzzer --output OUT --scope S [--dry-run --offline ...]
python3 -m modules.portscan --output OUT --hosts F [--ports P --no-tools]
python3 -m modules.webshot --output OUT [--services F --cluster-threshold 10]
python3 -m modules.forms.main --output OUT --scope S [--url U --browser --no-submit --seed N]
python3 -m modules.listener --output OUT [--port 8799 --aggressive --fuzz --forms --token T --group host]
python3 modules/liveanalysis.py --output OUT --config C
python3 modules/discover.py --output OUT --config C --limit N
python3 modules/database.py --output OUT ingest | query "SQL"
python3 modules/reporter.py --output OUT ; python3 modules/triage.py --output OUT
python3 -m modules.diff OLD NEW ; python3 -m modules.sweep_aggregate --output OUT targets...
```
