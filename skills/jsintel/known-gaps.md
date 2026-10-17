# Known gaps, drift, and where the roadmap lives

The roadmap is in `recommendations.md` (live backlog, grouped §1-§9) and
`problems/required-features.md`. The gaps below were **verified in code on 2026-10-15**
while this skill was written. They are not yet in the backlog. When you fix one,
remove it here and log it in TESTING_PROGRESS.

## Correctness / coverage
1. **The classifier never emits `typescript`, `tsx`, or `jsx`.** `classifier.sh` maps
   `.ts/.tsx/.jsx` to `other`, and crawler `ASSET_RE` does not keep them. So the
   TypeScript grammar paths and `TypesAnalyzer` only ever run in unit tests. If served
   TS/JSX sources matter (dev servers, source-map `sources`), add the extensions to
   both and to the listener's `classify`.
2. **Asset types with no analyzer:** `worker` (extensionless worker paths), `manifest`,
   and `webassembly` are downloaded but no analyzer lists them in
   `supported_asset_types`. A worker without `.js` gets no JS analysis. Consider
   mapping worker to the JS analyzers and adding a manifest analyzer (`start_url`,
   `scope`, related apps).
3. **Forms-discovered endpoints are not analyzed in the same run.** The forms stage runs
   after the last extraction and discovery round. It appends to `crawled_urls.txt`,
   which nothing re-reads. Either run forms before the discovery loop or feed its
   endpoints into `discover.py`.

## Config / docs drift
4. `config.yaml` `database.path` is ignored (`database.db_path` always uses
   `<out>/database/recon.db`). `reporter.py` accepts `--config` and ignores it.
   Document this or remove the key.
5. `docs/CONFIGURATION.md` lacks `download.max_seconds` and `download.max_bytes`, and
   it describes the Phase 2 typed loader (`src/jsintel/config.py`), which the pipeline
   does not use.
6. `JSIntel_Workflow_v4.md`, `JSIntel_Ultimate_Workflow_v5.md`, and `plan.md` are
   **historical** build protocols (Phases A-D: parser, AST analyzers, taint, code
   intelligence). They are all implemented. Their "file inventory" and "gap matrix"
   sections are stale, so trust the code over them. Section 0 ("absolute constraints")
   still reflects intent: backward-compatible reports and no aborting on a bad asset.
7. `docs/ARCHITECTURE.md` describes Phase 2 as the direction, but `src/jsintel/` has no
   production caller. Treat it as a scaffold.

## Tests / infrastructure
8. Two ReDoS tests rely on wall-clock bounds and fail under heavy load (see
   testing-and-lab.md). Consider measuring CPU time (`time.process_time`) or
   relative scaling instead.
9. No CI. The lab-driven regression assertions are still backlog §8.

## Highest-value backlog items (from recommendations.md, 2026-10-15)
- Wildcard-DNS collapse in mass sweeps (about 8k phantom hosts cost ~45 s each).
  **Edit `sweep.sh` only when no sweep is running.**
- Fuzzer WAF-wall early stop, budget weighting, recursion, and rate limiting.
- Inter-procedural (one-level) taint. Mark source-map secrets under `node_modules/`
  as `first_party: false`.
- Per-run provenance (run id) in the DB, plus a `run.json` manifest and resumable stages.
- A single `scope.yaml` consumed by every stage.
- CI with lab assertions. Real minified Juice Shop bundle fixtures.
