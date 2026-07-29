# JSIntel Phase 1

JSIntel is a JavaScript Asset Intelligence and Recon Framework for **authorized security testing and asset inventory**. It crawls a supplied scope, identifies client-side assets, downloads them with integrity metadata, extracts useful inventory signals, and produces SQLite-backed reports.

> Phase 2 is an additive migration to a typed, plugin-based intelligence
> platform. The existing `jsintel.sh` workflow remains compatible while new
> collection, analysis, graph, and reporting capabilities move behind stable
> interfaces. See [Architecture](docs/ARCHITECTURE.md) and the
> [Plugin Guide](docs/PLUGINS.md).

## Features

- Katana-based JavaScript-aware crawling for `.js`, `.mjs`, maps, JSON, WebAssembly, workers, and manifests.
- URL normalization and type classification before parallel, resumable downloads.
- SHA-256, byte size, MIME type, failure status, timeout, and retry handling.
- Extraction of URLs, API/GraphQL-like paths, WebSocket URLs, imports/requires, and framework signatures.
- SQLite database with assets, URLs, endpoints, technologies, and findings tables.
- JSON, Markdown, and CSV reporting.

## Extraction engine

`modules/extractor.sh` remains the compatible pipeline entry point, but now
delegates to the streaming Python engine in `modules/extractor/`. The engine
uses independently discovered analyzer plugins and typed findings while
preserving the existing five report formats. It also produces `errors.json`;
one malformed or missing asset no longer aborts a scan.

## Installation

On Kali Linux or Debian, run:

```bash
chmod +x install.sh jsintel.sh modules/*.sh modules/*.py
./install.sh
```

The installer installs `katana` and `httpx` under `$(go env GOPATH)/bin`. Ensure that directory is on `PATH`. Playwright's optional browser runtime is not needed for Phase 1's Katana crawler; install it with `python3 -m playwright install` only if extending the project with browser automation.

## Usage

Create a scope file containing one authorized seed URL per line:

```text
https://app.example.test
https://api.example.test
```

Run the pipeline:

```bash
./jsintel.sh -i crawled_urls -o target_output -t 50
```

`-o` defaults to `./output`; `-t` defaults to `config/config.yaml` (50). A single `http(s)` URL can be passed to `-i` as well. Never run this tool outside a scope you are authorized to assess.

## Output

For an output directory named `target_output`, JSIntel writes:

```text
target_output/
├── assets/
│   ├── crawled_urls.txt
│   └── 000001_asset.js
├── database/recon.db
├── logs/jsintel.log
└── reports/
    ├── assets.json
    ├── urls.json
    ├── endpoints.json
    ├── websocket.json
    ├── imports.json
    ├── frameworks.json
    ├── assets.csv
    ├── summary.json
    └── summary.md
```

Use the database query interface for ad-hoc reports:

```bash
python3 modules/database.py --output target_output query 'SELECT endpoint FROM endpoints'
```

## Project layout

```text
jsintel-phase1/
├── jsintel.sh                 # Pipeline launcher
├── install.sh                 # Debian/Kali dependency installation
├── modules/                   # Crawl, classify, download, extract, database, report modules
├── database/schema.sql        # SQLite schema
├── config/config.yaml         # Runtime defaults
├── reports/                   # Placeholder for checked-in report exports
└── output/                    # Default runtime output root
```

## Notes

The crawler uses Katana when installed. If it is unavailable, it records supplied HTTP URLs as candidate assets, which is useful for offline or constrained environments but does not crawl pages. Downloads are deliberately limited to discovered HTTP(S) URLs and are saved using sanitized filenames.
