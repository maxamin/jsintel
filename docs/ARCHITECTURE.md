# Architecture

JSIntel Phase 2 is migrating incrementally from a shell pipeline to a layered
platform. The legacy `jsintel.sh` interface remains the supported entry point
while adapters are moved behind the platform contracts.

```text
Collection → Normalization → Asset Store → Analysis Engine
                                           ↓
Report Generator ← Risk Engine ← Knowledge Graph
```

Each layer communicates through typed domain models in `jsintel.models`.
Implementations are intentionally hidden behind narrow interfaces:

- Collection plugins produce normalized `Asset` models.
- The asset store owns persistence, cache metadata, and content addressing.
- Analysis plugins receive `Asset` models and emit models and relationships.
- `KnowledgeGraphStore` persists nodes and directed, evidence-bearing edges.
- Report generators read only SQLite; they do not read temporary plugin files.

The initial migration is additive. `database/schema.sql` remains the Phase 1
compatibility schema; `database/migrations/` adds scan provenance and graph
tables without removing existing assets, endpoints, or technology records.

## Extraction compatibility boundary

The shell pipeline continues to call `modules/extractor.sh`. That wrapper now
only invokes `python3 -m modules.extractor.main`; extraction implementation is
in a typed Python package. `JSONWriter` streams the legacy `urls.json`,
`endpoints.json`, `websocket.json`, `imports.json`, and `frameworks.json`
arrays directly to temporary files, then atomically publishes each report.
`errors.json` records isolated reader/plugin failures.

## Plugin lifecycle

Plugins implement `id`, `version`, `dependencies`, `initialize`, `run`,
`cleanup`, `supported_asset_types`, and `schema`. `PluginRegistry` resolves the
dependency graph before execution. Plugins must not import other plugin modules
or parse another plugin's output files.
