# Index of every markdown file in the repository

`project-docs/` in this skill holds **relative symlinks** to each file below, so the
skill directory contains all project docs while the originals remain the single source
of truth. Edit the originals, never a copy. If you add a new `.md` file to the repo,
add a symlink here too:
`ln -s ../../../<path> skills/jsintel/project-docs/<path with / replaced by _>`.

| File (symlink name) | Status | What it is |
|---|---|---|
| `README.md` | current | User-facing overview: features, install, flags, auth, output tree. |
| `TESTING_PROGRESS.md` (≈1.7k lines) | **live log** | Every milestone, bug (symptom/cause/fix), benchmark, and suite count since 2026-09-25. Read the tail for recent state. Append new milestones here. |
| `recommendations.md` | **live backlog** | Outstanding work §1-§9. Delete items when they ship. |
| `problems/problems.md` | live | Hidden positives and false negatives found against the lab, with evidence and FIXED/OPEN status. |
| `problems/required-features.md` | live | Feature backlog derived from problems.md (most items shipped). |
| `problems/README.md` | current | Explains the problems folder. |
| `test.md` | current | "Ultra-aggressive test prompt": full-range discovery, unauth/cookie/JWT passes, proxychains, coverage of every line, safety assertions. |
| `BENCHMARKS.md` | current | Extraction parallelism and split numbers, discovery loop, listener throughput. |
| `enhancements/ENHANCEMENTS.md` | current | Notes behind the perf work (pairs with `enhancements/bench.py`). |
| `docs/ARCHITECTURE.md` | partly aspirational | Phase 2 layered platform plus the extractor compatibility boundary. |
| `docs/PLUGINS.md` | aspirational | Phase 2 `jsintel.plugins.Plugin` guide (not the extractor's analyzer API). |
| `docs/CONFIGURATION.md` | slightly stale | config.yaml keys (missing `max_seconds`/`max_bytes`). |
| `docs/DEVELOPMENT.md` | current | venv, `pip install -e .[dev]`, pytest, ruff, mypy, and change discipline. |
| `docs/FUZZING.md` | current | Fuzzer design, wordlist catalog, calibration, CLI. |
| `integrations/mitmproxy/README.md` | current | Using the mitmproxy addon with the listener. |
| `tests/lab/README.md` | current | Vulnerable lab estate, usage, Docker constraints. |
| `JSIntel_Workflow_v4.md` | historical | Original engineering protocol for the AST extractor rebuild. |
| `JSIntel_Ultimate_Workflow_v5.md` | historical | Merged v2-v4 protocol (Phases A-D, tree-sitter reference, taint pseudocode, detection matrix). Useful as a tree-sitter and taint reference. Its inventory is stale. |
| `plan.md` | historical | Plan used to synthesize v5 from the v2-v4 docs. |

The ignored `.pytest_cache/README.md` is not relevant.
