# Extraction engine (`modules/extractor/`)

## Flow

1. `main.iter_assets(manifest)` streams `reports/assets.json` with an incremental
   `JSONDecoder.raw_decode`, so the whole manifest is never held in memory. It raises
   on a non-array, a non-object entry, or truncated input.
2. `run()` uses the parallel path when `workers > 1` and there are at least 12 assets
   (`_PAR_MIN_ASSETS`). Workers = `JSINTEL_EXTRACT_WORKERS`, or `min(cpu, 8)`. Any
   parallel exception falls back to sequential.
3. `_analyze_asset`: `select()` the analyzers whose `supported_asset_types` contains
   `asset.asset_type`, then `read_asset`. Parse with tree-sitter only for downloaded
   javascript/jsx/typescript/tsx. Stash the tree on the frozen dataclass via
   `object.__setattr__(asset, "_tree", tree)`. Call `set_current_index(tree)` to build
   a shared node-type index, run each analyzer inside try/except (an exception becomes
   an `errors` record), then `clear_ast_cache()`. Output order: non-security findings
   first, then security findings sorted by severity.
4. Parallel path (`_plan_jobs`): assets are LPT bin-packed by file size. A bundle of at
   least `JSINTEL_SPLIT_BYTES` (200 KB) is **split by analyzer group**, but only when
   such bundles number at most `workers/2`. Blanket splitting measured 0.56× (it
   re-parses per group). Workers write JSONL shards to `reports/.shards/`. The main
   process stitches them into the final arrays and runs `cross_asset.finalize()` over
   the merged module map. It uses the `fork` context explicitly (Python 3.14 defaults
   to forkserver).
5. `JSONWriter` (sequential path) streams each report to `.<report>.json.tmp` and
   renames it on close. `JSONWriter.reports` = urls, endpoints, websocket, imports,
   frameworks, findings, errors. Adding a new report name means updating this tuple.

## Analyzer catalogue

| id | Class / file | Asset types | Emits |
|---|---|---|---|
| urls | URLAnalyzer / urls.py | js/jsx/ts/tsx | URLFinding (filtered by `_urlutil.is_plausible_url`) |
| endpoints | EndpointAnalyzer / endpoints.py | js* | EndpointFinding. `${...}` placeholders normalize to `{}` |
| websocket | WebSocketAnalyzer | js* | WebSocketFinding |
| imports | ImportAnalyzer | js* | ImportFinding |
| dependencies | DependencyAnalyzer | js* | ImportFinding (resolved relative imports) |
| frameworks | FrameworkAnalyzer / framework.py | js* | FrameworkFinding (React, Vue, Angular, Next, Nuxt, Svelte, Webpack, Vite, Rollup...) |
| tech_fingerprint | TechFingerprintAnalyzer | page | FrameworkFinding (server stacks: PHP, ASP.NET, JSP, Django...) |
| pages | PageAnalyzer / page_analyzer.py | page | URLs, endpoints (kinds incl. `form`), `html_form`, `form_without_csrf_token` (low), `reflected_param_candidate` (low, **same-site only**), `html_comment` |
| secrets | SecretsAnalyzer | js*, page | `hardcoded_secret` |
| security | SecurityAnalyzer | js* | `dangerous_eval` (high/low), `prototype_pollution` (low), `postmessage_missing_origin` (medium) |
| taint | TaintAnalyzer | js* | `taint_to_sink` (source, sink, severity) |
| sourcemap | SourceMapAnalyzer | source_map | `source_map` finding. Un-minifies `sourcesContent` and re-scans it with the full secret ruleset + URL/API regexes |
| cloud_storage | CloudStorageAnalyzer | js*, page, source_map, configuration | `cloud_bucket_reference` (S3/GCS/Azure/DO Spaces; a path-style host must start the hostname) |
| callgraph | CallGraphAnalyzer | js* | `call_graph` (info) |
| classes | ClassesAnalyzer | js* | `class` (info) |
| exports | ExportsAnalyzer | js* | `export` (info) |
| types | TypesAnalyzer | ts/tsx | `api_type` or `type_definition` (info) |
| cross_asset | CrossAssetAnalyzer (stateful; `finalize`) | js*, source_map | `cross_asset_call`, `cross_asset_dependency` |

Info-severity findings are code-structure inventory. The reporter separates them from
security findings.

## Adding an analyzer

1. Create `modules/extractor/analyzers/<name>.py` with a class that subclasses
   `ASTAnalyzer` (to receive `tree`) or `Analyzer`. Set a unique `id`, a `description`,
   and `supported_asset_types`. `registry.discover()` picks it up automatically. No
   registration step exists.
2. Handle `tree is None` (no tree-sitter, or a parse failure). Fall back to regex on
   `source` or yield nothing.
3. Yield typed findings from `findings.py`. Do not write files. A new report kind needs
   a new Finding subclass, a `JSONWriter.reports` entry, and an ingest in `database.py`.
4. Add the id and a cost weight to `_ANALYZER_COST` in `main.py` (only affects balance).
5. Tests: `tests/test_analyzers.py` helpers `make_asset(url, asset_type)` and
   `analyze(analyzer, source, url=, asset_type=)`. Add fixtures to `tests/fixtures/`.
   Cover positives, negatives, `tree=None`, and a large-input timing bound.

## Secrets detector (`secrets_analyzer.py`). Highest quality bar.

- Patterns come from vendored `token_patterns.json` (109 RE2-compatible provider
  regexes, from github.com/odomojuli/regextokens) **minus** the strategies `identifier`
  and `encoding`, plus a hand-written `credentials-in-url` pattern (scheme bounded to
  15 chars; userinfo excludes quotes, backslash, braces, `<>`, and `,`) and hex and
  entropy fallbacks.
- **Prefilter:** each pattern's required literal anchors (`_anchors_for`) go into one
  Aho-Corasick automaton (`_AhoCorasick`). Per literal, only the anchorless patterns
  plus the patterns whose anchor appears are run. First match wins, in matcher order.
- AST path: every `string` and `template_string` node. No-tree or page path: the
  `_QUOTED_LITERAL` regex (per-quote, unrolled-loop, linear).
- `_token_from` rejects blob slices: keyword-gated bodies must not have alphanumerics
  glued on either side and need entropy ≥ 3. Prefix tokens adjacent to `+`, `/`, or `=`,
  or containing a 6× repeated char, are rejected (base64 wasm, fonts, BIP39 word lists).
- Severity (`_severity_for`): public ids (Stripe `pk_`, Google OAuth client id,
  Braintree tokenization key) → info. `google-api-key` → low. `jwt` → low. PEM or
  service-account markers → high. Categories Cloud, Source/CI, and Payments → high.
  Everything else → medium. The entropy fallback is low and needs a secret-like name
  within ±80 chars, plus a token shape (`_looks_like_token`).
- Values are masked (`_mask`) except structural markers.
- `scan_text(text)` is a reusable entry point (no AST) that the listener's anomaly
  engine uses.

## Taint and security analyzers. Precision rules learned from the 2026-10-09 sweep.

- Taint sources are `location.{href,search,hash}`, `document.{URL,cookie}`,
  `window.name`, and localStorage, matched on the **trailing member pair**. Sinks and
  their severities are in `_SINK_SEVERITY`.
- Bindings resolve through `ScopeResolver`, keyed by the declaring function. Minified
  `t`/`e`/`n` must never be conflated across functions.
- A whole-URL source into a non-code sink is ignored. A localStorage flow is
  downgraded one level.
- `dangerous_eval` only fires on global eval/Function (bare, or on window, self,
  globalThis, or global) with a non-constant argument. `Function("return this")` is safe.
- `prototype_pollution` only fires on the `a[k1][k2]=v` shape (both keys non-literal)
  in a function with no `__proto__`/`constructor`/`hasOwnProperty` guard.
- `postmessage_missing_origin` resolves named handlers, requires that the handler reads
  `event.data`, and accepts an `origin` **or** `source` check.
- Intra-procedural only. Inter-procedural taint is in the backlog.

## False-positive workflow (how the last big pass was done)

1. Mine a real corpus already on disk (`sweep_*/targets/*/reports/findings.json`). Do not
   send new traffic. Rank `(finding_type, severity)` by count and sample values.
2. Trace each noisy class to its root cause in the detector. Never add a post-hoc filter
   in triage or the reporter.
3. Fix it, add a regression test that uses the real minimal sample (see
   `TestSecretFalsePositiveRegressions`), and re-measure on the same corpus.
4. Record the before/after table in `TESTING_PROGRESS.md`.
