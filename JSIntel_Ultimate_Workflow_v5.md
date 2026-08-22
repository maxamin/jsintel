# JSIntel Ultimate Engineering Protocol v5
## The definitive execution workflow — supersedes v2, v3, and v4
### Zero ambiguity. Zero guessing. Every rule derived from verified code inspection.

---

## HOW TO USE THIS DOCUMENT

This document is the single source of truth for executing JSIntel improvements under resource constraints. It consolidates and corrects all prior protocol versions.

**Read order for a first session**: 0 → 1 → 2 → 16 (startup checklist) → then the Phase section you are implementing.

**Read order for a returning session**: 0 → 16 → the Phase section you are implementing → 17 (change template) → 12 (testing).

| # | Section | Purpose | When to read |
|---|---------|---------|--------------|
| 0 | Absolute Constraints | Hard rules — violate = rollback | Before every session |
| 1 | Repository Snapshot | Verified file contents + gap matrix | Before first change |
| 2 | Target Architecture | Data flow + state machine + class hierarchy | Before design decisions |
| 3 | Phase A: Foundation | parser.py, ast_analyzer.py, main.py, findings.py, writer.py, database.py, reporter.py | First — blocking |
| 4 | Phase B: AST Refactor | urls.py, endpoints.py, imports.py, framework.py, websocket.py | After Phase A |
| 5 | Phase C: Security Engine | taint_analyzer.py, security_analyzer.py, secrets_analyzer.py | After Phase B |
| 6 | Phase D: Code Intelligence | callgraph_analyzer.py, dependency_analyzer.py, sourcemap_analyzer.py | After Phase C |
| 7 | tree-sitter Deep Reference | Installation, API, node types, patterns, queries, gotchas | When writing AST analyzers |
| 8 | Security Detection Matrix | Sources, sinks, sanitizers, severity rubric | When implementing detection |
| 9 | Taint Algorithm | Pseudocode, canonical finding types, limitations, roadmap | When writing taint_analyzer.py |
| 10 | Performance Targets | Benchmarks, memory limits, caching strategy | Before Phase A and after each phase |
| 11 | Error Handling | Graceful degradation, fallback chains, logging | When writing any parser/analyzer code |
| 12 | Testing Protocol | Baseline, fixtures, unit tests, verification, benchmarks | After every change |
| 13 | Decision Trees | Regex vs AST, new vs extend, when to touch shared files | When uncertain |
| 14 | Anti-Patterns | What NOT to do, with consequences | When stuck or before deviating |
| 15 | Troubleshooting | Common errors, causes, fixes, diagnostics | On any failure |
| 16 | Startup Checklist | First action every session | First action every session |
| 17 | Change Template | Mandatory format for every modification | Every modification |
| 18 | Code Review Checklist | Pre-submit verification | Before considering a change done |
| 19 | Configuration Reference | config.yaml options (current + proposed) | Before Phase 2 work |
| 20 | Phase 2 Roadmap | Knowledge graph, AI layer, API doc generation, CI/CD, enterprise | Reference only — not Phase 1 scope |
| 21 | Communication Rules | Response discipline for constrained execution | Before every response |
| 22 | Glossary | Terms and definitions | As needed |

---

## SECTION 0: ABSOLUTE CONSTRAINTS (VIOLATE = ROLLBACK)

```
[0.1]  NEVER modify a file without reading it first with cat/head.
[0.2]  NEVER add a dependency not in requirements.txt or stdlib.
[0.3]  NEVER change bash pipeline files: jsintel.sh, crawler.sh, classifier.sh, downloader.sh.
[0.4]  NEVER break the Analyzer ABC contract:
       analyze(self, asset: Asset, source: str) -> Iterable[Finding].
[0.5]  NEVER use regex to detect security vulnerabilities that depend on code structure
       (control flow, scope, calls). Regex IS permitted on extracted string literals
       (URLs, secret patterns, framework names).
[0.6]  ALWAYS preserve backward-compatible report JSON structure.
       Add fields only; never remove or rename existing fields.
[0.7]  ALWAYS verify after changes with:
       python3 -m modules.extractor.main --manifest X --output Y
[0.8]  ALWAYS use tree_sitter if available (it is in requirements.txt).
[0.9]  ALWAYS keep responses under 200 tokens of explanation per change block.
[0.10] ALWAYS emit one PROBLEM/CAUSE/SOLUTION/FILES/IMPACT block per change.
[0.11] NEVER store full source strings in findings — use snippets or line numbers.
[0.12] NEVER parse the same asset more than once per scan.
[0.13] ALWAYS handle tree-sitter parse failures gracefully (return None, fall back to regex).
[0.14] NEVER emit duplicate findings for the same asset + finding_type + line.
[0.15] ALWAYS sort findings by severity: critical > high > medium > low > info.
[0.16] NEVER log secret values or full source; log asset.url and finding_type only.
[0.17] NEVER say "I think" or "probably" — state facts from code inspection only.
       If a required fact cannot be verified (e.g., missing grammar), report it and stop.
```

---

## SECTION 1: VERIFIED REPOSITORY SNAPSHOT

### 1.1 File Inventory with Status

| File | Language | Status | Notes |
|------|----------|--------|-------|
| jsintel.sh | Bash | READ-ONLY | Pipeline launcher |
| install.sh | Bash | READ-ONLY | apt + pip + go deps |
| requirements.txt | Text | READ-ONLY | tree-sitter>=0.21.0 listed but never imported |
| config/config.yaml | YAML | READ-ONLY | threads, depth, timeout, retries |
| database/schema.sql | SQL | READ-ONLY | findings table exists, never written |
| modules/utils.sh | Bash | READ-ONLY | log helpers, config_value |
| modules/crawler.sh | Bash | READ-ONLY | Katana crawl or seed copy |
| modules/classifier.sh | Bash | READ-ONLY | URL -> type classifier |
| modules/downloader.sh | Bash | READ-ONLY | ThreadPoolExecutor downloads |
| modules/extractor.sh | Bash | READ-ONLY | Wrapper for `python3 -m modules.extractor.main --manifest X --output Y` |
| modules/database.py | Python | MODIFY | Add findings ingest |
| modules/reporter.py | Python | MODIFY | Add findings count to summary |
| modules/extractor/main.py | Python | MODIFY | Add AST caching (functions: iter_assets(), run(), main()) |
| modules/extractor/analyzer.py | Python | READ-ONLY | ABC contract — DO NOT CHANGE |
| modules/extractor/models.py | Python | READ-ONLY | Asset is a frozen dataclass |
| modules/extractor/findings.py | Python | EXTEND | Add SecurityFinding |
| modules/extractor/registry.py | Python | READ-ONLY | Plugin discovery via pkgutil (discover(), select()) |
| modules/extractor/utils.py | Python | READ-ONLY | read_asset(path) -> str |
| modules/extractor/writer.py | Python | MODIFY | Add "findings" to JSONWriter.reports tuple |
| modules/extractor/analyzers/urls.py | Python | REFACTOR | Regex -> AST hybrid |
| modules/extractor/analyzers/endpoints.py | Python | REFACTOR | Regex -> AST hybrid |
| modules/extractor/analyzers/imports.py | Python | REFACTOR | Regex -> AST hybrid |
| modules/extractor/analyzers/framework.py | Python | REFACTOR | Regex + AST hybrid (keep regex fast-path) |
| modules/extractor/analyzers/websocket.py | Python | REFACTOR | Regex -> AST hybrid |
| modules/extractor/parser.py | Python | CREATE | Singleton JS parser |
| modules/extractor/ast_analyzer.py | Python | CREATE | AST-aware analyzer base |
| modules/extractor/analyzers/taint_analyzer.py | Python | CREATE | Taint tracking |
| modules/extractor/analyzers/security_analyzer.py | Python | CREATE | Static bad patterns |
| modules/extractor/analyzers/secrets_analyzer.py | Python | CREATE | Hardcoded secrets |
| modules/extractor/analyzers/callgraph_analyzer.py | Python | CREATE | Call graph |
| modules/extractor/analyzers/dependency_analyzer.py | Python | CREATE | Import resolution |
| modules/extractor/analyzers/sourcemap_analyzer.py | Python | CREATE (D3, optional) | Source map -> original source mapping |
| tests/test_analyzers.py | Python | CREATE | Unit tests |
| tests/fixtures/*.js | JavaScript | CREATE | Test fixtures |

### 1.2 Verified File Contents (by inspection)

#### requirements.txt
```
requests>=2.31.0
PyYAML>=6.0.1
beautifulsoup4>=4.12.0
tree-sitter>=0.21.0
playwright>=1.42.0
rich>=13.7.0
```
**Key fact**: tree-sitter is listed but NEVER imported anywhere in the codebase.

#### database/schema.sql
```sql
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL UNIQUE,
    local_path TEXT,
    asset_type TEXT NOT NULL,
    sha256 TEXT,
    size_bytes INTEGER,
    mime_type TEXT,
    status TEXT DEFAULT 'discovered',
    discovered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'url',
    UNIQUE(asset_id, url, kind)
);
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    endpoint TEXT NOT NULL,
    method TEXT,
    kind TEXT NOT NULL DEFAULT 'api',
    UNIQUE(asset_id, endpoint, kind)
);
CREATE TABLE IF NOT EXISTS technologies (
    id INTEGER PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    evidence TEXT,
    UNIQUE(asset_id, name)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    value TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```
**Key fact**: The findings table has NEVER been written to by database.py.

#### modules/extractor/writer.py (critical line)
```python
reports = ("urls", "endpoints", "websocket", "imports", "frameworks", "errors")
```
**Key fact**: "findings" is MISSING from this tuple. Security findings will be silently dropped.

#### modules/extractor/analyzer.py (ABC contract — READ-ONLY)
```python
class Analyzer(ABC):
    id: str
    description: str
    supported_asset_types: tuple[str, ...] = ("javascript",)
    def initialize(self) -> None: ...
    @abstractmethod
    def analyze(self, asset: Asset, source: str) -> Iterable[Finding]: ...
    def finalize(self) -> Iterable[Finding]: ...
```

#### modules/extractor/models.py (Asset — READ-ONLY, frozen)
```python
@dataclass(frozen=True, slots=True)
class Asset:
    url: str
    asset_type: str
    local_path: Path | None
    status: str
    is_downloaded_javascript: bool
```

#### modules/extractor/main.py (run() structure — verified)
```python
def run(manifest: Path, output: Path) -> int:
    analyzers = discover()
    writer = JSONWriter(output)
    errors = 0
    try:
        for analyzer in analyzers:
            analyzer.initialize()
        for asset in iter_assets(manifest):
            if not asset.is_downloaded_javascript or asset.local_path is None:
                continue
            try:
                source = read_asset(asset.local_path)
            except OSError as error:
                writer.write_error(ExtractionError(asset.url, "reader", str(error)))
                errors += 1
                continue
            for analyzer in select(analyzers, asset.asset_type):
                try:
                    for finding in analyzer.analyze(asset, source):
                        writer.write(finding)
                except Exception as error:
                    LOGGER.exception("Analyzer %s failed for %s", analyzer.id, asset.url)
                    writer.write_error(ExtractionError(asset.url, analyzer.id, str(error)))
                    errors += 1
        for analyzer in analyzers:
            for finding in analyzer.finalize():
                writer.write(finding)
    finally:
        writer.close()
    return errors
```
**Key fact**: source is read once per asset, but EACH analyzer receives the raw string. No AST caching.

#### Existing analyzer regex baselines (to be refactored in Phase B)
```python
# urls.py
_URL_RE = re.compile(r'(?:(?:https?:)?//[^\s"\'\`<>\\]+)')
# endpoints.py
_PATH_RE = re.compile(r'(?<![\w/])/(?:api|graphql|v[0-9]+|rest)[A-Za-z0-9_./?=&${}:\-]*', re.I)
# imports.py
_IMPORT_RE = re.compile(r"(?:import\s*(?:[^'"()]*?\s+from\s*)?|require\s*\()["']([^"']+)["']")
# websocket.py
_WEBSOCKET_RE = re.compile(r'wss?://[^\s"\'\`<>\\]+', re.I)
# framework.py — fingerprints: React, Vue, Angular, Next.js, Nuxt, Svelte, Webpack, Vite, Rollup
```

### 1.3 Gap Matrix

| # | Gap | File / Evidence | Severity | Fix Priority | Impact if Fixed |
|---|-----|-----------------|----------|--------------|-----------------|
| 1 | tree-sitter installed but unused | requirements.txt line 4; zero imports in codebase | Critical | A1 | Enables all AST-based analysis |
| 2 | No AST caching | main.py run() passes raw source to each analyzer | Critical | A3 | 5x parse speedup for 5 analyzers |
| 3 | findings table unused | schema.sql defines it; database.py never ingests | Critical | A6 | Security findings persist in DB |
| 4 | findings missing from writer | writer.py reports tuple lacks findings | Critical | A5 | Findings silently dropped |
| 5 | All analyzers regex-only | Every analyzer uses re.compile + findall | Critical | B1–B5 | Eliminates false positives from comments/variables |
| 6 | No taint engine | No source-to-sink tracking anywhere | Critical | C1 | Catches real DOM XSS, eval injection, SSRF |
| 7 | No security findings class | findings.py has no SecurityFinding | High | A4 | Enables structured security reporting |
| 8 | No symbol resolution | No variable scope tracking | Medium | D2 | Cross-file intelligence |
| 9 | No call graph | No function relationship mapping | Medium | D1 | Code intelligence |
| 10 | No source map parsing | .map files classified but not parsed | Low | D3 | Original source mapping |
| 11 | No incremental analysis | Every scan re-parses all assets | Medium | P2 (Roadmap) | Faster re-runs |
| 12 | No memory limits | Large JS files could OOM | Medium | P2 (Roadmap) | Stability |
| 13 | No duplicate suppression | Same finding emitted multiple times | Low | Enforced via [0.14] | Cleaner output |

---

## SECTION 2: TARGET ARCHITECTURE

### 2.1 Data Flow Diagram

```
INPUT: seed URLs / local JS bundles
    |
    v
[BASH PIPELINE — UNCHANGED]
    jsintel.sh -> crawler.sh -> classifier.sh -> downloader.sh
    |
    v
OUTPUT: manifest.json (streaming JSON array of Asset objects)
    |
    v
[EXTRACTOR MAIN — MODIFY]
    main.py::iter_assets() — streaming parser, UNCHANGED
    main.py::run() — MODIFY: add parse + cache
    |
    v
+-------------------------------------------+
| Asset (frozen dataclass)                  |
|  - url: str                               |
|  - asset_type: str                        |
|  - local_path: Path | None                |
|  - status: str                            |
|  - _tree: Tree | None [NEW, attached via  |
|          object.__setattr__]              |
+-------------------------------------------+
    |
    v
+-------------------------------------------+
| Parser Layer (modules/extractor/parser.py)|
|  - Singleton JSParser                     |
|  - parse(source) -> Tree | None           |
|  - Graceful fallback on any error         |
+-------------------------------------------+
    |
    v
+-------------------------------------------+
| Analysis Pipeline (main.py::run())        |
|  - For each asset:                        |
|    1. read_asset(path) -> source str      |
|    2. parse_js(source) -> tree            |
|    3. object.__setattr__(asset,'_tree',tree)
|    4. For each analyzer:                  |
|       - ASTAnalyzer: reads asset._tree    |
|       - Analyzer: ignores tree            |
|    5. finalize() -> aggregate findings    |
+-------------------------------------------+
    |
    v
+-------------------------------------------+
| Analyzer Registry                         |
|  - discover(): pkgutil + inspect          |
|  - select(): filter by asset_type         |
|  - Existing analyzers: regex/AST hybrid   |
|  - NEW analyzers: AST-only                |
+-------------------------------------------+
    |
    v
+-------------------------------------------+
| Findings (findings.py)                    |
|  - URLFinding       -> urls.json          |
|  - EndpointFinding  -> endpoints.json     |
|  - WebSocketFinding -> websocket.json     |
|  - ImportFinding    -> imports.json       |
|  - FrameworkFinding -> frameworks.json    |
|  - SecurityFinding  -> findings.json [NEW]|
|  - ExtractionError  -> errors.json        |
+-------------------------------------------+
    |
    v
+-------------------------------------------+
| Writer (writer.py)                        |
|  - Streaming JSON array output            |
|  - Temp files -> atomic rename            |
|  - reports tuple includes findings [NEW]  |
+-------------------------------------------+
    |
    v
+-------------------------------------------+
| Database (database.py)                    |
|  - ingest(): assets, urls, endpoints      |
|  - ingest(): technologies                 |
|  - ingest(): findings [NEW]               |
|  - query(): ad-hoc SQL                    |
+-------------------------------------------+
    |
    v
+-------------------------------------------+
| Reporter (reporter.py)                    |
|  - summary.json                           |
|  - summary.md (includes findings count)   |
|  - assets.csv                             |
+-------------------------------------------+
```

### 2.2 State Machine for Asset Processing

```
[ASSET_READ] -> read_asset() succeeds?
    |--NO--> [WRITE_ERROR] -> [NEXT_ASSET]
    |--YES-> [PARSE_JS] -> parse_js() succeeds?
              |--NO--> [SKIP_TREE] -> analyzers use regex fallback
              |--YES-> [ATTACH_TREE] -> object.__setattr__(asset, '_tree', tree)
              |
              v
         [RUN_ANALYZERS] -> for each analyzer in select(analyzers, asset_type):
              |--ASTAnalyzer subclass--> reads asset._tree
              |--Analyzer base class--> ignores tree, uses source string
              |
              v
         [DEDUPE + WRITE] -> skip if (asset.url, finding_type, line) already seen
              |
              v
         [WRITE_FINDINGS] -> writer.write(finding) for each finding
              |
              v
         [NEXT_ASSET]  (asset._tree is garbage-collected here)
```

### 2.3 Class Hierarchy

```
Analyzer (ABC) [modules/extractor/analyzer.py]
  | id: str
  | description: str
  | supported_asset_types: tuple[str, ...] = ('javascript',)
  | initialize(self) -> None
  | analyze(self, asset: Asset, source: str) -> Iterable[Finding]
  | finalize(self) -> Iterable[Finding]
  |
  +-- URLAnalyzer       [REFACTORED: AST + regex hybrid]
  +-- EndpointAnalyzer  [REFACTORED: AST + regex hybrid]
  +-- ImportAnalyzer    [REFACTORED: AST + regex hybrid]
  +-- FrameworkAnalyzer [REFACTORED: AST + regex hybrid]
  +-- WebSocketAnalyzer [REFACTORED: AST + regex hybrid]
  |
  +-- ASTAnalyzer (NEW) [modules/extractor/ast_analyzer.py]
        | analyze() reads asset._tree, calls analyze_ast()
        | analyze_ast(self, asset, source, tree) -> Iterable[Finding]
        |
        +-- TaintAnalyzer (NEW)
        +-- SecurityAnalyzer (NEW)
        +-- SecretsAnalyzer (NEW)
        +-- CallGraphAnalyzer (NEW)
        +-- DependencyAnalyzer (NEW)
        +-- SourceMapAnalyzer (NEW, D3 — optional)
```

**Rule**: Existing analyzers do NOT need to inherit ASTAnalyzer.
Only NEW analyzers that need AST should inherit ASTAnalyzer.
Existing analyzers continue working via the base Analyzer class.

---

## SECTION 3: PHASE A — FOUNDATION (BLOCKING — must complete first)

> Phase A is the critical path. Nothing in Phases B–D works without it.
> Complete A1–A7 in order. Verify after each step (Section 12.4).

#### A1. CREATE modules/extractor/parser.py
**Purpose**: Single parse point. Singleton pattern. Error-tolerant.
**Depends on**: tree-sitter and tree-sitter-javascript being importable.
**If tree-sitter-javascript is missing**: parser returns None for all inputs. Analyzers fall back to regex.
**Code**:
```python
"""JavaScript parser using tree-sitter with graceful fallback."""
from __future__ import annotations
from typing import Any

try:
    from tree_sitter import Language, Parser, Tree
    _HAS_TS = True
except ImportError:
    _HAS_TS = False
    Tree = Any  # type: ignore


class JSParser:
    """Singleton JS parser. Returns None on any failure."""

    _instance: JSParser | None = None
    _parser: Parser | None = None

    def __new__(cls) -> JSParser:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_parser()
        return cls._instance

    def _init_parser(self) -> None:
        if not _HAS_TS:
            self._parser = None
            return
        try:
            import tree_sitter_javascript as ts_js
            lang = Language(ts_js.language())
            self._parser = Parser(lang)
        except Exception:
            self._parser = None

    def parse(self, source: str) -> Tree | None:
        if self._parser is None:
            return None
        try:
            return self._parser.parse(source.encode("utf-8", errors="ignore"))
        except Exception:
            return None


def parse_js(source: str) -> Tree | None:
    """Convenience function."""
    return JSParser().parse(source)
```
**Test**: `python3 -c "from modules.extractor.parser import parse_js; t=parse_js('var x=1;'); print(t is not None)"`

#### A2. CREATE modules/extractor/ast_analyzer.py
**Purpose**: Base class for analyzers that need AST. Does NOT modify the Analyzer ABC.
**Contract**: main.py attaches the tree to asset._tree before calling analyze().
**Code**:
```python
"""AST-aware analyzer base class."""
from __future__ import annotations
from abc import abstractmethod
from collections.abc import Iterable
from typing import Any

from .analyzer import Analyzer
from .findings import Finding
from .models import Asset


class ASTAnalyzer(Analyzer):
    """Analyzer that reads a pre-parsed AST from asset._tree."""

    def analyze(self, asset: Asset, source: str) -> Iterable[Finding]:
        tree = getattr(asset, "_tree", None)
        return self.analyze_ast(asset, source, tree)

    @abstractmethod
    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        """Override in subclasses. tree may be None."""
        ...
```

#### A3. MODIFY modules/extractor/main.py
**Insertion point**: After `source = read_asset(asset.local_path)`, before `for analyzer in select(...)`.
**Code insertion**:
```python
from .parser import parse_js
# ... existing code ...
            try:
                source = read_asset(asset.local_path)
            except OSError as error:
                writer.write_error(ExtractionError(asset.url, "reader", str(error)))
                errors += 1
                continue
            # >>> INSERT BEGIN
            tree = parse_js(source) if asset.is_downloaded_javascript else None
            if tree is not None:
                object.__setattr__(asset, "_tree", tree)
            # >>> INSERT END
            for analyzer in select(analyzers, asset.asset_type):
```
**Why object.__setattr__?** Asset is a frozen dataclass. Normal assignment raises FrozenInstanceError.
**Performance impact**: Parse once per asset, not once per analyzer. 5x speedup for 5 analyzers.

#### A4. EXTEND modules/extractor/findings.py
**Add after ExtractionError class** (requires `from dataclasses import dataclass, field` — already implied by the existing file):
```python
@dataclass(frozen=True, slots=True)
class SecurityFinding(Finding):
    finding_type: str
    severity: str
    value: str
    source: str = ""
    sink: str = ""
    report: str = field(init=False, default="findings")

    def to_record(self) -> dict[str, Any]:
        return {
            "asset_url": self.asset_url,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "value": self.value,
            "source": self.source,
            "sink": self.sink,
        }
```
**Why separate from generic Finding?** The findings table schema has finding_type, severity, value columns. This maps 1:1.

#### A5. MODIFY modules/extractor/writer.py
**Change line**:
```python
reports = ("urls", "endpoints", "websocket", "imports", "frameworks", "errors")
```
**To**:
```python
reports = ("urls", "endpoints", "websocket", "imports", "frameworks", "findings", "errors")
```
**Why this order?** findings is inserted before errors so the error report is always last (convention).

#### A6. MODIFY modules/extractor/database.py
**Add inside ingest(), after the technologies loop, before con.commit()**:
```python
    for r in records(output / "reports/findings.json"):
        aid = ids.get(r.get("asset_url"))
        if aid:
            cur.execute(
                "INSERT INTO findings(asset_id,finding_type,severity,value) VALUES(?,?,?,?)",
                (aid, r['finding_type'], r['severity'], r['value']),
            )
```

#### A7. MODIFY modules/extractor/reporter.py
**Add after the technologies scalar**:
```python
    findings = scalar("SELECT COUNT(*) FROM findings")
```
**Add to summary dict**:
```python
    "finding_count": findings,  # NEW
```
**Add to markdown lines**:
```python
    f"- Security findings: {findings}",  # NEW
```

**Phase A exit criteria**: `./jsintel.sh` runs end-to-end; `findings.json` exists (may be an empty array); `findings` table is queryable; `summary.md` includes the findings line; zero regressions in the baseline reports.

---

## SECTION 4: PHASE B — AST-BASED ANALYZERS (refactor existing)

> Strategy for all of Phase B: hybrid. AST for structure-aware extraction; regex ONLY on
> extracted string literals. Every refactor must preserve a regex fallback when tree is None.

#### B1. REFACTOR modules/extractor/analyzers/urls.py
**Strategy**: Use AST to extract string literals, then apply `_URL_RE` ONLY on those strings.
**Why**: Eliminates false positives from URLs in comments and variable names.
**Key function**:
```python
def _extract_string_literals(tree: Any) -> list[str]:
    """Walk AST and return all string node texts."""
    results = []
    if tree is None:
        return results
    def walk(node):
        if node.type in ("string", "template_string"):
            text = node.text.decode("utf-8", errors="ignore") if isinstance(node.text, bytes) else str(node.text)
            results.append(text)
        for child in node.children:
            walk(child)
    walk(tree.root_node)
    return results
```
**Class change**: Inherit from ASTAnalyzer. In analyze_ast, if tree is not None, extract strings then regex; else fall back to full-source regex.
**Backward compatibility**: If tree is None, behavior is identical to the original analyzer.
**Enhancement**: Also walk `call_expression` nodes with callee `fetch` / `XMLHttpRequest` / `WebSocket` and extract the first string argument.

#### B2. REFACTOR modules/extractor/analyzers/endpoints.py
**Strategy**: AST to find fetch/axios/ajax calls, extract first string arg. Regex on strings as fallback.
**Key functions**:
```python
def _get_call_identifier(node: Any) -> str:
    """Return identifier text for a call expression callee."""
    func = node.child_by_field_name("function")
    if func is None:
        return ""
    if func.type == "identifier":
        return func.text.decode("utf-8", errors="ignore") if isinstance(func.text, bytes) else str(func.text)
    if func.type == "member_expression":
        prop = func.child_by_field_name("property")
        if prop:
            return prop.text.decode("utf-8", errors="ignore") if isinstance(prop.text, bytes) else str(prop.text)
    return ""

def _get_first_string_arg(node: Any) -> str:
    """Return first string argument of a call expression."""
    args = node.child_by_field_name("arguments")
    if args is None:
        return ""
    for child in args.children:
        if child.type == "string":
            text = child.text.decode("utf-8", errors="ignore") if isinstance(child.text, bytes) else str(child.text)
            return text.strip(chr(39)+chr(34))  # strip quotes
    return ""
```
**Class change**: Inherit from ASTAnalyzer. Walk tree for call_expressions with callee in HTTP_METHODS or (fetch, ajax, request). Extract the first string arg if it starts with `/` or `http`.

#### B3. REFACTOR modules/extractor/analyzers/imports.py
**Strategy**: AST to find import_statement, import_require, and dynamic import().
**Key function**:
```python
def _extract_imports(tree: Any) -> set[str]:
    """Walk AST and extract all module specifiers."""
    results = set()
    if tree is None:
        return results
    def walk(node):
        if node.type == "import_statement":
            source_node = node.child_by_field_name("source")
            if source_node and source_node.type == "string":
                text = source_node.text.decode("utf-8", errors="ignore") if isinstance(source_node.text, bytes) else str(source_node.text)
                results.add(text.strip(chr(39)+chr(34)))
        elif node.type == "import_require":
            args = node.child_by_field_name("arguments")
            if args:
                for child in args.children:
                    if child.type == "string":
                        text = child.text.decode("utf-8", errors="ignore") if isinstance(child.text, bytes) else str(child.text)
                        results.add(text.strip(chr(39)+chr(34)))
        elif node.type == "call_expression":
            func = node.child_by_field_name("function")
            if func and func.type == "import":
                args = node.child_by_field_name("arguments")
                if args:
                    for child in args.children:
                        if child.type == "string":
                            text = child.text.decode("utf-8", errors="ignore") if isinstance(child.text, bytes) else str(child.text)
                            results.add(text.strip(chr(39)+chr(34)))
        for child in node.children:
            walk(child)
    walk(tree.root_node)
    return results
```

#### B4. REFACTOR modules/extractor/analyzers/framework.py
**Strategy**: Keep regex as fast-path fallback. Add AST detection for imports and specific calls.
**AST detection dicts**:
```python
_IMPORT_FRAMEWORKS = {
    "react": "React",
    "vue": "Vue",
    "@angular/core": "Angular",
    "next": "Next.js",
    "nuxt": "Nuxt",
    "svelte": "Svelte",
}
_CALL_FRAMEWORKS = {
    "createApp": "Vue",
    "createElement": "React",
    "useState": "React",
    "defineComponent": "Vue",
    "__webpack_require__": "Webpack",
}
```
**Walk function**: Check import_statement source strings against `_IMPORT_FRAMEWORKS` keys. Check call_expression callee identifiers against `_CALL_FRAMEWORKS` keys.

#### B5. REFACTOR modules/extractor/analyzers/websocket.py
**Strategy**: Same as urls.py — extract strings from AST, then apply `_WEBSOCKET_RE`.
**Reuse**: `_extract_string_literals` from urls.py (or duplicate it).

**Phase B exit criteria**: All five analyzers produce identical-or-better output vs baseline on the fixture corpus; URL false positives from comments are eliminated; unit tests for each refactored analyzer pass.

---

## SECTION 5: PHASE C — SECURITY DETECTION ENGINE (new analyzers)

#### C1. CREATE modules/extractor/analyzers/taint_analyzer.py
**Purpose**: Intra-procedural taint tracking. Sources -> transformations -> sinks.
**Scope v1**: Single function, direct assignments + one-level propagation.

**Core algorithm**:
1. Walk AST. For each variable_declarator or assignment_expression:
   - If RHS is a taint source (location.href, document.cookie, etc.), mark LHS as tainted.
   - If RHS is a tainted identifier, propagate taint to LHS.
2. Walk AST again. For each sink call (eval, innerHTML=, fetch, etc.):
   - Check if any argument is a tainted identifier or member_expression.
   - If yes, emit SecurityFinding with `finding_type="taint_to_sink"` (canonical type — see Section 9).

**Taint sources to track**:
- member_expression: location.href, location.search, location.hash
- member_expression: document.URL, document.cookie
- member_expression: window.name
- member_expression: event.data (heuristic: inside a message listener)
- call_expression: prompt(), localStorage.getItem()

**Taint sinks to flag**:
- call_expression: eval, Function, setTimeout, setInterval, fetch, WebSocket, JSON.parse
- call_expression: document.write, location.replace, window.open
- assignment_expression: .innerHTML =, .outerHTML =, .src =, .href =

**Limitations v1** (documented; do NOT attempt in v1):
- No cross-function tracking.
- No array/object property taint.
- No sanitizer detection.
- No conditional taint (if/else branches not distinguished).

#### C2. CREATE modules/extractor/analyzers/security_analyzer.py
**Purpose**: Detect dangerous patterns that do NOT require taint tracking.

**Patterns to detect**:
| Pattern | AST Signal | Finding Type | Severity |
|---------|-----------|--------------|----------|
| eval(...) | call_expression callee identifier 'eval' | dangerous_eval | critical |
| new Function(...) | call_expression callee identifier 'Function' | dangerous_eval | critical |
| setTimeout(string, ...) | call_expression callee 'setTimeout' + first arg is string | dangerous_eval | high |
| setInterval(string, ...) | call_expression callee 'setInterval' + first arg is string | dangerous_eval | high |
| obj[key] = value | assignment_expression left is subscript_expression | prototype_pollution | medium |
| window.addEventListener('message', handler) without origin check | call_expression + handler body missing 'origin' | postmessage_missing_origin | medium |

**Scope note**: Taint-conditioned patterns (e.g., `JSON.parse(tainted)`, `fetch(tainted_url)`) are NOT in
SecurityAnalyzer's scope — they are emitted by TaintAnalyzer (C1) per the sink matrix in Section 8.2.
SecurityAnalyzer detects only structure-only patterns that need no dataflow.

#### C3. CREATE modules/extractor/analyzers/secrets_analyzer.py
**Purpose**: Detect hardcoded secrets in string literals.

**Detection strategy**:
1. Walk AST, collect all string and template_string nodes.
2. For each string:
   a. Check against known secret patterns (Stripe keys, GitHub tokens, AWS keys, JWTs).
   b. If no pattern match, check Shannon entropy > 4.5 AND length >= 20.
   c. If high entropy, check if the surrounding source line contains a secret-like variable name (password, api_key, token, secret, auth, credential).
3. Emit SecurityFinding with masked value (first 4 + ... + last 4 chars). NEVER store the full secret (see [0.11], [0.16]).

**Known patterns** (regex on extracted literals is permitted here per [0.5]):
- `sk-[a-zA-Z0-9]{20,}` -> stripe_key
- `ghp_[a-zA-Z0-9]{30,}` -> github_token
- `AKIA[0-9A-Z]{16}` -> aws_access_key
- `eyJ...` -> jwt_token
- `[0-9a-f]{32}` -> md5_hash_or_api_key
- `[0-9a-f]{40}` -> sha1_hash_or_api_key
- `[0-9a-f]{64}` -> sha256_hash_or_api_key

**Phase C exit criteria**: The three security analyzers emit findings on their fixtures (Section 12.2); no false positive on `safe_eval.js`; findings.json validates; all Phase C unit tests pass.

---

## SECTION 6: PHASE D — CODE INTELLIGENCE (new analyzers)

#### D1. CREATE modules/extractor/analyzers/callgraph_analyzer.py
**Purpose**: Build function call relationships.

**Algorithm**:
1. First pass: walk tree, collect all function_declaration, function_expression, arrow_function.
   - Record function name (or `anonymous@line` for unnamed).
2. Second pass: walk tree, track current function scope.
   - For each call_expression, record caller -> callee.
   - Emit SecurityFinding with `finding_type='call_graph'`, `severity='info'`, and record fields: caller, callee, line, column.

#### D2. CREATE modules/extractor/analyzers/dependency_analyzer.py
**Purpose**: Enhanced import resolution with relative path mapping.

**Algorithm**:
1. Walk tree for import_statement, import_require, dynamic import().
2. Extract module specifier string.
3. If specifier starts with `./` or `../`, resolve against the asset URL base.
4. Emit ImportFinding with the resolved URL.

#### D3. CREATE modules/extractor/analyzers/sourcemap_analyzer.py (optional)
**Purpose**: Parse .map files to map minified names to original sources.
**When asset_type == 'source_map':**
1. Parse JSON from the source string.
2. Extract the `sources` array.
3. Emit findings mapping minified -> original.
**Set** `supported_asset_types = ("source_map",)` so registry.select() routes .map assets to it.

**Phase D exit criteria**: Call graph and dependency edges appear in findings.json/imports.json; source map assets (when present) produce mapping findings; no regression in earlier phases.

---

## SECTION 7: TREE-SITTER DEEP REFERENCE

### 7.1 Installation Verification

```bash
# Check tree-sitter core
python3 -c "import tree_sitter; print(tree_sitter.__version__)"

# Check JavaScript grammar
python3 -c "import tree_sitter_javascript; print('OK')"

# If tree_sitter_javascript is missing, install it:
pip install tree-sitter-javascript

# Test parse
python3 -c "
from tree_sitter import Language, Parser
import tree_sitter_javascript as ts_js
lang = Language(ts_js.language())
p = Parser(lang)
tree = p.parse(b'const x = 1;')
print(tree.root_node.type)  # program
"
```
**Bootstrap exception**: `tree-sitter-javascript` is a grammar package companion to the already-listed `tree-sitter` dependency; installing it once is the single sanctioned exception to [0.2]. Any other new dependency remains forbidden.
**Hard rule** (from [0.17]): if the grammar cannot be verified after attempting the documented install, report it as a problem and STOP. Do not guess installation steps.

### 7.2 Node API Reference

| Property/Method | Type | Description |
|-----------------|------|-------------|
| node.type | str | Node type string |
| node.text | bytes | Raw source bytes |
| node.start_byte | int | Start offset in source |
| node.end_byte | int | End offset in source |
| node.start_point | (row, col) | Start position |
| node.end_point | (row, col) | End position |
| node.children | list[Node] | Child nodes |
| node.child_count | int | Number of children |
| node.named_child_count | int | Number of named children |
| node.child_by_field_name(name) | Node | Get child by grammar field |
| node.parent | Node | Parent node |
| node.next_sibling | Node | Next sibling |
| node.prev_sibling | Node | Previous sibling |

### 7.3 JavaScript Grammar Node Types (complete)

**Declarations:**
- function_declaration, function_expression, arrow_function, generator_function, generator_function_declaration
- class_declaration, class_expression, class_heritage
- method_definition, pair (object property)
- variable_declaration, lexical_declaration (const/let)

**Statements:**
- expression_statement, return_statement, if_statement, switch_statement
- while_statement, do_statement, for_statement, for_in_statement
- try_statement, throw_statement, with_statement
- break_statement, continue_statement, debugger_statement
- labeled_statement

**Expressions:**
- call_expression, member_expression, subscript_expression (computed property)
- assignment_expression, augmented_assignment_expression
- binary_expression, unary_expression, update_expression
- ternary_expression (conditional), sequence_expression (comma operator)
- parenthesized_expression

**Literals:**
- string, template_string, template_substitution
- number, true, false, null, undefined
- regex, comment

**Import/Export:**
- import_statement, import_require, import_clause, namespace_import, named_imports
- export_statement, export_clause

**Other:**
- identifier, property_identifier, shorthand_property_identifier
- statement_block, object, array, arguments
- spread_element, rest_pattern
- program (root)

### 7.4 Common AST Patterns

**Pattern: Find all function declarations**
```python
def find_functions(node):
    if node.type == "function_declaration":
        yield node
    for child in node.children:
        yield from find_functions(child)
```

**Pattern: Find all call expressions**
```python
def find_calls(node):
    if node.type == "call_expression":
        yield node
    for child in node.children:
        yield from find_calls(child)
```

**Pattern: Get callee identifier**
```python
def get_callee(node):
    func = node.child_by_field_name("function")
    if func.type == "identifier":
        return func.text.decode("utf-8")
    if func.type == "member_expression":
        prop = func.child_by_field_name("property")
        return prop.text.decode("utf-8")
    return None
```

**Pattern: Get all string arguments**
```python
def get_string_args(node):
    args = node.child_by_field_name("arguments")
    for child in args.children:
        if child.type == "string":
            yield child.text.decode("utf-8").strip(chr(39)+chr(34))
```

**Pattern: Check if member expression is computed (obj[key])**
```python
def is_computed(node):
    # In tree-sitter JS, computed member expressions use subscript_expression
    return node.type == "subscript_expression"
```

**Pattern: Tree-sitter Query**
```python
from tree_sitter import Query

# Find all fetch calls with string URL
query = Query(lang, """
(call_expression
  function: (identifier) @func_name (#eq? @func_name "fetch")
  arguments: (arguments . (string) @url))
""")
captures = query.captures(tree.root_node)
for capture in captures:
    node, name = capture
    print(f'{name}: {node.text.decode("utf-8")}')
```

### 7.5 Common Gotchas

| Gotcha | Explanation | Fix |
|--------|-------------|-----|
| node.text is bytes, not str | tree-sitter returns bytes | Always decode: `node.text.decode('utf-8', errors='ignore')` |
| Missing child_by_field_name | Some nodes don't have grammar fields | Check for None before using |
| Comma nodes in arguments | arguments.children includes ',' separators | Skip nodes where type == ',' |
| Template strings have substitutions | template_string contains template_substitution children | Handle separately or treat as single string |
| Arrow functions lack names | arrow_function has no name field | Use line number: `f'arrow@{node.start_point[0]}'` |
| import() is call_expression | dynamic import is call_expression with function.type == 'import' | Check func.type == 'import' |
| require() is import_require | CJS require has special node type | Check node.type == 'import_require' |
| Comments are separate nodes | Comments are not part of the main AST | They appear as children but can be skipped |
| Deep recursion on huge bundles | Python recursion limit on very deep ASTs | Use an explicit iterative stack for the walk |

---

## SECTION 8: SECURITY DETECTION MATRIX

### 8.1 Taint Sources (always track)

| Source | AST Pattern | Notes |
|--------|-------------|-------|
| location.href | member_expression object='location' property='href' | |
| location.search | member_expression object='location' property='search' | |
| location.hash | member_expression object='location' property='hash' | |
| document.URL | member_expression object='document' property='URL' | |
| document.cookie | member_expression object='document' property='cookie' | |
| window.name | member_expression object='window' property='name' | |
| event.data (postMessage) | member_expression object='event'/'e' property='data' | heuristic: inside message listener |
| prompt() | call_expression callee='prompt' | |
| localStorage.getItem(x) | call_expression callee member_expression 'localStorage.getItem' | |

### 8.2 Taint Sinks (always flag if tainted)

| Sink | AST Pattern | Vulnerability | Severity |
|------|-------------|---------------|----------|
| eval(arg) | call_expression callee='eval' | Code injection | critical |
| Function(arg) | call_expression callee='Function' | Code injection | critical |
| setTimeout(arg, delay) where arg is string | call_expression callee='setTimeout' | Code injection | high |
| setInterval(arg, delay) where arg is string | call_expression callee='setInterval' | Code injection | high |
| document.write(arg) | call_expression callee member_expression 'document.write' | DOM XSS | high |
| element.innerHTML = arg | assignment_expression left member_expression property='innerHTML' | DOM XSS | high |
| element.outerHTML = arg | assignment_expression left member_expression property='outerHTML' | DOM XSS | high |
| script.src = arg | assignment_expression left member_expression property='src' on 'script' | DOM XSS | medium |
| location.href = arg | assignment_expression left member_expression property='href' on 'location' | Open redirect / DOM XSS | medium |
| location.replace(arg) | call_expression callee member_expression 'location.replace' | Open redirect | medium |
| window.open(arg) | call_expression callee='window.open' | Open redirect / SSRF | medium |
| fetch(arg) | call_expression callee='fetch' | SSRF | medium |
| XMLHttpRequest.open(method, arg) | call_expression callee member_expression 'XMLHttpRequest.open' | SSRF | medium |
| new WebSocket(arg) | call_expression callee='WebSocket' | SSRF | medium |
| obj[arg] = val where arg is tainted | assignment_expression left computed property | Prototype pollution | medium |
| JSON.parse(arg) where arg is tainted | call_expression callee='JSON.parse' | Insecure deserialization | low |

### 8.3 Sanitizers (reduce severity if detected — v2 feature)

| Sanitizer | Effect |
|-----------|--------|
| DOMPurify.sanitize() | Safe for innerHTML |
| encodeURIComponent() | Safe for URL construction |
| escape() | Partial (deprecated) |
| JSON.stringify() | Partial (not for HTML) |

**v1 rule**: Do NOT implement sanitizer detection. Document as a Phase 2 improvement.

### 8.4 Severity Scoring Rubric

| Severity | Criteria | Examples |
|----------|----------|----------|
| critical | Direct code execution, no user interaction required | eval(tainted), Function(tainted), document.write(tainted) |
| high | DOM XSS, code injection with some preconditions | innerHTML = tainted, setTimeout(string) |
| medium | SSRF, open redirect, prototype pollution, postMessage issues | fetch(tainted), location.href = tainted, obj[key] = val |
| low | Information disclosure, insecure deserialization | JSON.parse(tainted), hardcoded secrets |
| info | Code intelligence, non-security findings | call graph, framework detection |

Sort order for output (enforced by [0.15]): critical > high > medium > low > info.

---

## SECTION 9: TAINT ALGORITHM (Pseudocode)

### 9.1 Pseudocode

```
function build_taint_map(tree):
    map = {}
    for each assignment in tree:
        if RHS is source(location.href, document.cookie, etc.):
            map[LHS_name] = source_name
        elif RHS is identifier and RHS_name in map:
            map[LHS_name] = map[RHS_name]
    return map

function check_sinks(tree, taint_map):
    for each node in tree:
        if node is sink_call(eval, fetch, JSON.parse, etc.):
            for each arg in node.arguments:
                if arg is identifier and arg.name in taint_map:
                    emit Finding(source=map[arg.name], sink=sink_name)
        if node is sink_assignment(innerHTML=, src=, etc.):
            if RHS is identifier and RHS.name in taint_map:
                emit Finding(source=map[RHS.name], sink=sink_name)
```

### 9.2 Canonical finding_type naming (RESOLVED — supersedes v2/v3/v4 conflict)

Prior protocol versions disagreed (v2 tests expected `dom_xss`; v4 tests expected `taint_to_sink`). The canonical rule for v5:

- **TaintAnalyzer** emits `finding_type="taint_to_sink"` for every source-to-sink flow.
  - The vulnerability class implied by the sink (DOM XSS, code injection, SSRF, …) is recorded via the sink name and the severity assigned per Section 8.2 — NOT via a per-vulnerability finding_type.
  - Fields: `source=<source expr>`, `sink=<sink expr>`, `severity` per Section 8.2, `value="<source> -> <sink> @line N"` (truncated; never full source).
- **SecurityAnalyzer** emits structural finding types directly: `dangerous_eval`, `prototype_pollution`, `postmessage_missing_origin`, `ssrf`, `insecure_deserialization`.
- **SecretsAnalyzer** emits `hardcoded_secret` with the pattern name in `value` (masked).
- **CallGraphAnalyzer** emits `call_graph` at severity `info`.

All tests in Section 12 use these canonical names. Do not invent new finding_type strings without adding them here first.

### 9.3 v1 Limitations (documented for Phase 2)
- No cross-function tracking.
- No array/object property taint.
- No sanitizer detection.
- No branch sensitivity (if/else not distinguished).
- No loop sensitivity.
- No inter-procedural analysis.

### 9.4 Phase 2 Taint Roadmap
- Cross-function taint via call graph.
- Object property tracking.
- Array index tracking.
- Sanitizer-aware analysis.
- Branch-sensitive analysis.
- Inter-procedural dataflow.

---

## SECTION 10: PERFORMANCE TARGETS

### 10.1 Benchmarks

| Metric | Baseline (pre-AST) | Target (post-AST) | Measurement |
|--------|--------------------|--------------------|-------------|
| Parse time per asset | N/A (not parsing) | <50ms per 100KB JS | `time python3 -c 'from modules.extractor.parser import parse_js; parse_js(open("asset.js").read())'` |
| Analysis time per asset | ~10ms (regex only) | <100ms per 100KB JS | `time ./jsintel.sh -i seeds.txt -o out` |
| Memory per asset | ~2x source size | <3x source size | `psutil.Process().memory_info().rss` |
| Total scan time (100 assets) | Baseline | <1.2x baseline | `time ./jsintel.sh` |
| False positive rate (URLs) | High (regex on comments) | <5% | Manual review of 100 findings |
| Finding duplication | 0% | 0% | DISTINCT count vs total count |
| Wall-time regression | — | Must not regress >10% | Before/after `time ./jsintel.sh` on identical seeds |

### 10.2 Caching Strategy

| Cache Level | Key | Value | TTL |
|-------------|-----|-------|-----|
| Asset-level AST | asset.url + asset.sha256 | Tree object | Session |
| Parser instance | N/A (singleton) | JSParser._instance | Process lifetime |
| Taint map | asset.url | dict[str, str] | Per-asset analysis |

**Current implementation**: Parse once per asset in main.py, attach tree to asset._tree.
**Phase 2**: Persistent AST cache on disk (pickle or msgpack) keyed by SHA-256; incremental analysis that re-parses only changed assets.

### 10.3 Memory Management

| Concern | Mitigation |
|---------|------------|
| Large JS files (>1MB) | Parse still works; tree object is proportional to source size |
| Many assets (>10K) | Streaming processing in main.py; no list kept in memory |
| Deep recursion in AST walk | Use an iterative stack instead of recursion for very deep trees |
| Tree object retention | asset._tree is garbage-collected after the asset loop iteration |

---

## SECTION 11: ERROR HANDLING

### 11.1 Graceful Degradation Chain

```
[tree-sitter import fails]
    |--YES--> parser.py returns None for all inputs
    |          |--ALL analyzers fall back to regex
    |          |--No crash, reduced accuracy
    |--NO---> [tree-sitter-javascript import fails]
    |          |--Same as above
    |--NO---> [parse() throws exception]
               |--parser.py catches ALL exceptions, returns None
               |--Analyzers fall back to regex
```

### 11.2 Analyzer Failure Handling

```
[analyzer.analyze() raises Exception]
    |--YES--> main.py catches exception
    |          |--Logs error via LOGGER.exception()
    |          |--Writes ExtractionError to errors.json
    |          |--Continues to next analyzer (NOT next asset)
    |--NO---> [analyzer yields finding]
               |--writer.write(finding) succeeds or fails
               |--If writer fails, exception propagates to main.py run()
```

### 11.3 Logging Standards

| Level | When to use | Example |
|-------|-------------|---------|
| DEBUG | Internal state, AST node counts | `LOGGER.debug('Parsed %d nodes', len(nodes))` |
| INFO | Major milestones | `LOGGER.info('Analyzer %s completed', analyzer.id)` |
| WARNING | Recoverable issues | `LOGGER.warning('Parse failed for %s, falling back', asset.url)` |
| ERROR | Analyzer failures | `LOGGER.error('Analyzer %s crashed: %s', analyzer.id, exc)` |
| EXCEPTION | Uncaught exceptions | `LOGGER.exception('Unexpected error')` |

**Rule** (enforced by [0.16]): Never log full source strings. Never log sensitive findings (secrets). Use asset.url and finding_type only.

---

## SECTION 12: TESTING PROTOCOL

### 12.1 Pre-Change Baseline

Run this command and record output:
```bash
cd /path/to/jsintel
mkdir -p test_output
echo "https://example.com/app.js" > test_seeds.txt
./jsintel.sh -i test_seeds.txt -o test_output -t 4
ls test_output/reports/
# Expected: urls.json, endpoints.json, websocket.json, imports.json, frameworks.json,
#           summary.json, summary.md, assets.csv
# Post-Phase A also expected: findings.json
time ./jsintel.sh -i test_seeds.txt -o test_output -t 4   # record baseline wall time
```

### 12.2 Unit Test Fixtures

Create `tests/fixtures/` with sample JS files:

| Fixture | Contents | Tests |
|---------|----------|-------|
| dom_xss.js | `var x = location.href; eval(x);` | TaintAnalyzer |
| safe_eval.js | `eval('1+1');` | TaintAnalyzer: no finding (no taint). SecurityAnalyzer: still flags `dangerous_eval` — eval usage is flagged regardless of argument literalness |
| secrets.js | `var key = 'sk-abc123...';` | SecretsAnalyzer |
| imports.js | `import React from 'react'; import('./lazy.js');` | ImportAnalyzer |
| framework.js | `createApp({}); __webpack_require__(1);` | FrameworkAnalyzer |
| endpoints.js | `fetch('/api/v1/users');` | EndpointAnalyzer |
| websocket.js | `new WebSocket('wss://example.com');` | WebSocketAnalyzer |
| postmessage.js | `window.addEventListener('message', e => { console.log(e.data) });` | SecurityAnalyzer |
| prototype.js | `obj[key] = value;` | SecurityAnalyzer |

### 12.3 Unit Test File

Create `tests/test_analyzers.py`:
```python
import unittest
from pathlib import Path
from modules.extractor.analyzers.taint_analyzer import TaintAnalyzer
from modules.extractor.analyzers.security_analyzer import SecurityAnalyzer
from modules.extractor.analyzers.secrets_analyzer import SecretsAnalyzer
from modules.extractor.models import Asset

def make_asset():
    return Asset(url="http://test", asset_type="javascript", local_path=None,
                 status="downloaded", is_downloaded_javascript=True)

class TestTaintAnalyzer(unittest.TestCase):
    def test_eval_location_href(self):
        src = "var x = location.href; eval(x);"
        analyzer = TaintAnalyzer()
        asset = make_asset()
        findings = list(analyzer.analyze(asset, src))
        self.assertTrue(any(f.finding_type == "taint_to_sink" for f in findings))

    def test_no_false_positive_on_safe_literal(self):
        src = "eval(\"1+1\");"
        analyzer = TaintAnalyzer()
        asset = make_asset()
        findings = list(analyzer.analyze(asset, src))
        self.assertEqual(len(findings), 0)

class TestSecurityAnalyzer(unittest.TestCase):
    def test_eval_detected(self):
        src = "eval(userInput);"
        analyzer = SecurityAnalyzer()
        asset = make_asset()
        findings = list(analyzer.analyze(asset, src))
        self.assertTrue(any(f.finding_type == "dangerous_eval" for f in findings))

    def test_postmessage_missing_origin(self):
        src = "window.addEventListener(\"message\", function(e) { console.log(e.data) });"
        analyzer = SecurityAnalyzer()
        asset = make_asset()
        findings = list(analyzer.analyze(asset, src))
        self.assertTrue(any(f.finding_type == "postmessage_missing_origin" for f in findings))

if __name__ == "__main__":
    unittest.main()
```

Run: `python3 -m pytest tests/test_analyzers.py -v`

**Note**: finding_type values in tests MUST match the canonical names in Section 9.2.

### 12.4 Post-Change Verification

After every change, run:
1. `python3 -m modules.extractor.main --manifest test_output/reports/assets.json --output test_output/reports`
2. Verify `findings.json` exists and contains a valid JSON array.
3. Verify `database.py ingest` populates the `findings` table.
4. Verify `reporter.py` includes the findings count in `summary.md`.
5. Run unit tests: `python3 -m pytest tests/ -v`
6. Verify zero duplicate findings for the same asset + finding_type + line ([0.14]).

### 12.5 Performance Benchmark

```bash
time ./jsintel.sh -i large_seed_list.txt -o bench_output -t 50
# Compare wall time before/after. Must not regress >10% (Section 10.1).
```

---

## SECTION 13: DECISION TREES

### 13.1 Regex vs AST

```
Does the pattern involve control flow, variable scope, or function calls?
    |--YES--> MUST use AST (taint, call graph, prototype pollution)
    |--NO---> Is it a literal string match (URL, secret prefix, framework name)?
              |--YES--> Regex on extracted string nodes is OK
              |--NO---> Reconsider — maybe AST is still needed
```

### 13.2 New Analyzer vs Extend Existing

```
Does the detection logic share state with existing analyzers?
    |--YES--> Extend existing (e.g., add endpoint detection to urls.py)
    |--NO---> Create new file in analyzers/
              |--Needs AST?--> Inherit from ASTAnalyzer
              |--No AST?-----> Inherit from Analyzer
```

### 13.3 When to Modify database.py / reporter.py / writer.py

```
Does the new analyzer emit a new Finding subclass?
    |--YES--> Modify:
              |--writer.py: add report name to reports tuple
              |--database.py: add ingest logic for new report JSON
              |--reporter.py: add count to summary
    |--NO---> Only modify writer.py if report name changed
```

### 13.4 When to Modify main.py

```
Does the change affect how ALL analyzers receive data?
    |--YES--> Modify main.py (e.g., AST caching, parallel execution)
    |--NO---> Do NOT modify main.py (analyzer-specific logic belongs in the analyzer)
```

### 13.5 Backward Compatibility

```
Does the change modify existing report JSON structure?
    |--YES--> Add new fields ONLY, never remove or rename existing fields
    |--NO---> Safe to proceed
```

---

## SECTION 14: ANTI-PATTERNS

| Anti-Pattern | Why Bad | Correct Approach | Consequence if Wrong |
|--------------|---------|------------------|---------------------|
| Regex for control flow | Misses real vulnerabilities, high false positives | AST traversal | Missed DOM XSS, false prototype pollution |
| Parsing per analyzer | O(N*A) waste, slow | Parse once, cache tree | 5x slower on 5 analyzers |
| Modifying Analyzer ABC | Breaks all existing plugins | Create ASTAnalyzer subclass | All analyzers crash |
| Ignoring tree-sitter errors | Crashes on malformed JS | Graceful fallback to regex | Pipeline halt on bad JS file |
| Storing findings in memory | OOM on large scans | Streaming writer | Memory exhaustion |
| Cross-function taint v1 | Too complex, error-prone | Intra-procedural only for v1 | Incorrect findings, performance loss |
| Logging full source strings | Leaks sensitive code in logs | Log only asset.url and finding_type | Information disclosure |
| Logging secret values | Exposes hardcoded secrets | Mask values: first4 + ... + last4 | Credential leak in logs |
| Duplicate findings | Clutters output, wastes storage | Use seen-set per asset ([0.14]) | Unusable reports |
| Modifying frozen dataclass | Runtime error | Use object.__setattr__ | FrozenInstanceError |
| Adding heavy framework | Increases install time, conflicts | Use stdlib or existing deps | Dependency hell |
| Changing bash pipeline | Breaks existing workflows | Keep bash files read-only | Users can't run jsintel.sh |
| Guessing when facts are missing | Propagates errors | Report the gap and stop ([0.17]) | Compounding wrong changes |

---

## SECTION 15: TROUBLESHOOTING

| Symptom | Cause | Fix |
|---------|-------|-----|
| FrozenInstanceError on Asset | Tried to set attribute on frozen dataclass | Use `object.__setattr__(asset, '_tree', tree)` |
| ModuleNotFoundError: tree_sitter | tree-sitter not installed | `pip install tree-sitter tree-sitter-javascript` |
| Parse returns None for all files | tree-sitter-javascript grammar missing | `pip install tree-sitter-javascript`; if still failing, STOP and report ([0.17]) |
| Analyzer not discovered | File not in analyzers/ or missing __init__.py | Verify file is in modules/extractor/analyzers/ |
| findings.json missing | writer.py reports tuple lacks 'findings' | Add 'findings' to reports tuple (A5) |
| findings table empty | database.py doesn't ingest findings.json | Add ingest loop for findings (A6) |
| summary.md missing findings count | reporter.py doesn't query findings table | Add findings scalar and markdown line (A7) |
| TypeError: analyze() takes 3 args, 4 given | Modified Analyzer ABC signature | Revert ABC; use ASTAnalyzer subclass instead |
| High memory usage | Keeping all trees in memory | Trees are per-asset and GC'd; check for leaks |
| Slow performance | Parsing per analyzer | Ensure parse happens once in main.py (A3) |
| False positives in URLs | Regex scanning comments/variables | Use AST string extraction before regex (B1) |
| Missing import findings | Regex doesn't handle multiline imports | Use AST import_statement detection (B3) |
| RecursionError on huge bundle | Recursive AST walk exceeded limit | Switch walk to iterative stack (Section 7.5) |

---

## SECTION 16: STARTUP CHECKLIST

Before the first change of every session, verify ALL of these:

- [ ] `cat requirements.txt` — confirm tree-sitter>=0.21.0 is present
- [ ] `python3 -c "import tree_sitter; print(tree_sitter.__version__)"` — confirm import works
- [ ] `python3 -c "import tree_sitter_javascript; print('ok')"` — confirm grammar installed
- [ ] `cat modules/extractor/writer.py` — confirm reports tuple contents
- [ ] `cat modules/extractor/database.py` — confirm ingest() function structure
- [ ] `cat modules/extractor/reporter.py` — confirm main() function structure
- [ ] `cat modules/extractor/main.py` — confirm run() loop structure
- [ ] `cat modules/extractor/analyzer.py` — confirm ABC signature
- [ ] `cat modules/extractor/models.py` — confirm Asset is a frozen dataclass
- [ ] `ls modules/extractor/analyzers/` — confirm analyzer file list
- [ ] `cat modules/extractor/analyzers/urls.py` — confirm regex-based implementation
- [ ] `cat modules/extractor/findings.py` — confirm no SecurityFinding exists (or confirm it does, post-A4)
- [ ] Create `tests/` directory if missing
- [ ] Create `tests/fixtures/` directory if missing
- [ ] Run baseline: `./jsintel.sh -i test_seeds.txt -o test_output`
- [ ] Record baseline timing: `time ./jsintel.sh -i test_seeds.txt -o test_output`
- [ ] Record baseline output files: `ls test_output/reports/`

---

## SECTION 17: CHANGE TEMPLATE (MANDATORY)

Every modification MUST follow this exact format:

```
PROBLEM: <one sentence describing what is wrong>
CAUSE: <one sentence root cause>
SOLUTION: <one sentence fix>
FILES: <comma-separated relative paths>
IMPACT: <quantitative expected improvement>
```

Then provide the diff or full file content.

**Rules**:
- One block per change. If a change requires >3 files, split it into multiple changes.
- No explanations of basic concepts — assume the reader knows Python, AST, tree-sitter, XSS, SSRF, prototype pollution.
- Code comments only for non-obvious heuristics.

**Example:**
```
PROBLEM: Security findings are silently dropped because writer.py does not include 'findings' in reports tuple.
CAUSE: writer.py reports tuple only has ('urls', 'endpoints', 'websocket', 'imports', 'frameworks', 'errors').
SOLUTION: Add 'findings' to reports tuple before 'errors'.
FILES: modules/extractor/writer.py
IMPACT: Security findings will now be written to findings.json instead of being discarded.
```

---

## SECTION 18: CODE REVIEW CHECKLIST

Before considering any change complete, verify ALL of these:

### 18.1 Correctness
- [ ] The change addresses exactly one problem from the gap matrix.
- [ ] No files were modified without being read first.
- [ ] The Analyzer ABC signature is unchanged.
- [ ] ASTAnalyzer subclass correctly handles tree=None (fallback behavior).
- [ ] No regex is used for security vulnerability detection ([0.5]).
- [ ] No full source strings are stored in findings ([0.11]).
- [ ] Secret values are masked in findings ([0.16]).
- [ ] finding_type values match the canonical names in Section 9.2.

### 18.2 Performance
- [ ] Each asset is parsed at most once ([0.12]).
- [ ] No unnecessary AST traversals (cache results if needed).
- [ ] No memory leaks (trees are not held beyond the asset loop).
- [ ] Benchmark shows <10% regression vs baseline.

### 18.3 Testing
- [ ] Unit tests exist for new analyzers.
- [ ] Unit tests cover both positive (finding detected) and negative (no false positive) cases.
- [ ] Existing pipeline end-to-end test still passes.
- [ ] findings.json is generated and valid.
- [ ] findings table is populated in SQLite.
- [ ] reporter summary includes findings count.

### 18.4 Compatibility
- [ ] Existing report JSON structure is preserved (no removed/renamed fields).
- [ ] Existing analyzers still load via registry.discover().
- [ ] Bash pipeline files are untouched.
- [ ] No new dependencies added.

### 18.5 Documentation
- [ ] PROBLEM/CAUSE/SOLUTION/FILES/IMPACT block is present.
- [ ] Code comments explain non-obvious heuristics only.
- [ ] No basic programming concept explanations.
- [ ] No common security concept lectures.

---

## SECTION 19: CONFIGURATION REFERENCE

### 19.1 Current config.yaml (READ-ONLY)

```yaml
threads: 50
crawler:
  depth: 2
downloader:
  timeout: 30
  retries: 3
```

### 19.2 Proposed Phase 2 Additions (DO NOT ADD YET)

```yaml
analysis:
  enable_taint: true
  enable_secrets: true
  enable_callgraph: false  # info-only, may be noisy
  max_file_size_mb: 5      # skip files larger than this
  severity_threshold: low  # only report >= this severity
parser:
  fallback_to_regex: true  # always fall back if AST fails
  cache_ast: false         # persistent AST cache on disk
```

**Rule**: Do NOT modify config.yaml in Phase 1. All features must work with defaults.

---

## SECTION 20: PHASE 2 ROADMAP (reference only — NOT Phase 1 scope)

> This section captures the platform evolution vision. None of it may be implemented
> during Phase 1 execution. It exists to keep Phase 1 design decisions forward-compatible.
> Source: JSIntel platform white paper requirements.

### 20.1 Multi-Language AST Intelligence
Extend the parser layer beyond JavaScript to TypeScript, JSX, and TSX grammars. Extraction targets widen to exports, classes, and typed API construction patterns. Constraint: any new grammar must be optional — the graceful degradation chain (Section 11.1) applies per-language.

### 20.2 Cross-Asset Symbol Resolution
Build module graphs, dependency graphs, chunk graphs, and call graphs so that multiple JavaScript files become ONE application model:
`Asset -> Module -> Function -> Network Call -> Endpoint`
Phase 1's dependency_analyzer (D2) and callgraph_analyzer (D1) are the seeds of this graph.

### 20.3 Knowledge Graph
Entities: assets, modules, functions, endpoints, dependencies, runtime requests, findings.
Relationships: `Asset contains Module`, `Module calls Function`, `Function reaches Endpoint`.
Enables graph-based intelligence queries over the whole scan.

### 20.4 Source Map Intelligence
Recover the original source tree from shipped bundles:
```
bundle.js -> bundle.js.map -> original source tree
```
Recovered artifacts: original filenames, function names, comments, TypeScript sources, and
architecture information (directory layout, module boundaries). Phase 1's optional
sourcemap_analyzer (D3) is the seed — it extracts the `sources` array. Phase 2 deepens this
to full source reconstruction and feeds recovered structure into the knowledge graph (20.3)
and confidence model (20.6).

### 20.5 Historical Diff Engine
- First-appearance tracking for endpoints and assets.
- Endpoint history and dependency change tracking.
- Asset evolution and security posture changes across scans.
- Feeds diff-aware analysis: previous scan + changed AST nodes + changed assets = targeted analysis (reduced cost, faster continuous monitoring).

### 20.6 Confidence Model
Layered evidence confidence:
```
Regex detection -> AST confirmation -> Runtime confirmation -> AI correlation
```
Each layer raises confidence; findings carry evidence provenance.

### 20.7 AI Intelligence Layer
- Diff-aware AI analysis: only changed assets/AST nodes are sent for semantic analysis.
- Structured AI findings MUST follow plugin schemas, e.g.:
  `{ "type": "endpoint", "confidence": 0.96, "source": "AST+AI", "value": "/api/users" }`
- Integration points: plugin engine, risk scoring, reporting.

### 20.8 Automatic API Documentation Generation
- **Endpoint reconstruction**: recover paths, HTTP methods, parameters, headers, authentication hints, request structures from recovered JS intelligence.
- **OpenAPI generation**: emit `openapi.yaml` from discovered API intelligence.
- **Insomnia collection generation**:
  ```
  Recovered Endpoints -> Endpoint Normalizer -> Schema Builder
      -> Insomnia Export Generator -> insomnia.json
  ```
  Generate workspaces, folders, requests, environments, variables, authentication templates, headers, parameters. Must scale to thousands/millions of endpoints with duplicate elimination, automatic grouping, version tracking, and environment generation.

### 20.9 REST and GraphQL API Layer
```
Dashboard -> REST/GraphQL API -> Repository Layer -> SQLite/PostgreSQL
```
Benefits: integrations, automation, CI/CD, external tools.

### 20.10 CI/CD Integration
- SARIF export.
- GitHub Actions, GitLab CI, Jenkins.
- Pull-request security workflows.

### 20.11 Enterprise Roadmap
- Multi-tenancy.
- Distributed workers.
- PostgreSQL backend.
- Cloud deployment.
- Continuous monitoring.

### 20.12 Runtime Intelligence
Playwright-driven (already in requirements.txt) runtime confirmation: execute pages, capture live network requests, and feed runtime requests into the knowledge graph and confidence model.

### 20.13 Taint Engine Deepening
See Section 9.4: cross-function taint via call graph, object/array property tracking,
sanitizer-aware analysis, branch-sensitive analysis, inter-procedural dataflow, and
evidence chains feeding the confidence model (20.6).

### 20.14 Forward-Compatibility Rules for Phase 1
1. SecurityFinding schema (A4) must stay extensible — Phase 2 adds `confidence` and `evidence` fields via [0.6]-compliant additions only.
2. findings.json records must keep `asset_url` as the join key — the knowledge graph builds on it.
3. finding_type strings are an enum-like contract (Section 9.2) — Phase 2 layers (AI, runtime) reuse them rather than inventing parallel vocabularies.
4. Keep analyzers stateless per asset where possible — distributed workers (20.11) depend on it.

---

## SECTION 21: COMMUNICATION RULES

1. **No explanations of basic concepts.** Assume the reader knows Python, AST, tree-sitter.
2. **No security lectures.** Assume the reader knows XSS, SSRF, prototype pollution.
3. **No code comments explaining the obvious.** Comments only for non-obvious heuristics.
4. **Every response must contain at least one PROBLEM/CAUSE/SOLUTION/FILES/IMPACT block.**
5. **If a change requires >3 files, split it into multiple changes.** One block per change.
6. **Never say "I think" or "probably".** State facts from code inspection only.
7. **If the tree-sitter grammar is missing, report it as a problem and stop.** Do not guess installation steps.
8. **Keep explanations under 200 tokens per change block** ([0.9]).

---

## SECTION 22: GLOSSARY

| Term | Definition |
|------|------------|
| AST | Abstract Syntax Tree — structured representation of source code |
| Taint | Untrusted data that flows from a source to a sink |
| Source | Point where untrusted data enters the program (e.g., location.href) |
| Sink | Dangerous function/assignment where tainted data causes harm (e.g., eval) |
| Sanitizer | Function that makes tainted data safe (e.g., DOMPurify.sanitize) |
| Intra-procedural | Within a single function scope |
| Inter-procedural | Across multiple function calls |
| DOM XSS | Cross-site scripting via DOM manipulation (innerHTML, document.write) |
| SSRF | Server-side request forgery — making requests to unintended targets |
| Prototype Pollution | Modifying Object.prototype via dynamic property assignment |
| tree-sitter | Incremental parsing library with grammar support |
| Singleton | Design pattern ensuring only one instance exists |
| Frozen dataclass | Immutable Python dataclass (cannot modify fields after creation) |
| Streaming parser | Processes data as it arrives, without loading all into memory |
| Plugin architecture | System where analyzers are discovered dynamically via registry |
| Knowledge graph | Graph of assets, modules, functions, endpoints and their relationships (Phase 2) |
| SARIF | Static Analysis Results Interchange Format — CI/CD findings standard (Phase 2) |
| Source map | .map file linking minified code back to original sources |

---

## VERSION HISTORY

| Version | Change |
|---------|--------|
| v2 | Initial improvement protocol: constraints, snapshot, phases A–D, change template, testing, decision trees |
| v3 | Added document map, verified file contents, gap matrix; truncated — reference sections missing |
| v4 | Added state machine, tree-sitter deep reference, performance targets, error handling, troubleshooting, review checklist, config reference, glossary |
| **v5 (this document)** | Unified all versions; fixed section numbering; resolved the finding_type naming conflict (Section 9.2); clarified regex scope ([0.5]); restored v2 communication rules (Section 21); added duplicate-suppression and logging constraints; added Phase 2 roadmap with forward-compatibility rules (Section 20) |

---

## END OF PROTOCOL

Version: 5.0 (Ultimate)
Supersedes: v2, v3, v4
Repository: https://github.com/maxamin/jsintel
Status: Phase 1 implementation guide + Phase 2 forward-compatible roadmap
