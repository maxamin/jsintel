# Operator rules and the working loop

These rules come from the operator's standing instructions, recorded in their Claude
memory and in TESTING_PROGRESS. Follow them in every session.

## Safety and authorization
- JSIntel is for **authorized** testing. Every active stage stays inside the supplied
  scope. Any change must keep scope enforcement at the point of sending, and add a test
  showing that out-of-scope input is refused.
- The agent does **not** run active, state-changing scans against third-party targets
  (for example gala.com or ether.fi), and does not log in as the operator through
  SSO. The operator runs those themselves. Earlier sessions confirmed that a harness
  classifier blocks this regardless of claimed authorization or local permission
  rules. Do not try to route around it, and do not edit permission settings. Instead,
  build the feature, validate it on the lab, and hand over exact commands with
  `--cookie`/`--jwt` placeholders.
- Never put a vulnerable lab app on a non-loopback interface.

## Files that must survive
Never delete or overwrite `domains.txt`, `urls`, `seeds.txt`, `howhold`, `output*/`,
`sweep_*/`, `ether_fi_runs/`, any `reports/`, `assets/`, or `database/` dirs, or
`tests/lab/runtime/`. A fresh run gets a new directory. Do not "tidy up" any of these.

## Progress tracking (required)
- `TESTING_PROGRESS.md`: append a `## MILESTONE — <title> (YYYY-MM-DD)` section with
  what changed (file and function), the root cause, how it was tested, measured
  numbers, and the suite count change (`Suite: N → M passed`). Bugs get symptom, cause,
  and fix.
- `recommendations.md` is a **live backlog**. When an item ships, delete it (do not
  mark it done) and log it in TESTING_PROGRESS. Add any new ideas found while testing.
- `problems/required-features.md` holds false-negative-driven features.
- Write TODOs as self-contained prompts to a future session.

## Quality bars
- **ReDoS:** bounded quantifiers everywhere. Time each pattern on multi-MB single-line
  input. Prefer literal-anchor prefilters.
- **Secret patterns:** test a realistic positive, adversarial negatives (glued
  characters, wrong length, missing parts), and boundaries.
- **Truthful findings and anomalies:** suppress volatile noise and fix false positives
  at the detector. Measure on real corpora.
- **Classifiers:** test mislabels aggressively, because a wrongly typed asset goes to the wrong analyzer.
- **Mine the whole HTTP stream:** headers and decoded query values as well as bodies.
- New stages are wired into every applicable entry point: `jsintel.sh` (plus `usage()`
  and README flags), the listener (`--<stage>` + `--<stage>-arg`), and the standalone CLI.

## Engineering conventions
- Python ≥ 3.10 (the box runs 3.14). `from __future__ import annotations`. Typed
  dataclasses with `frozen=True, slots=True`. Stdlib first: the project deliberately
  avoids new runtime dependencies (the forms driver hand-rolls CDP over WebSocket rather
  than using Playwright). ruff line length 100.
- Shell: `set -Eeuo pipefail`, source `utils.sh`, log through `log_info`/`log_warn`,
  quote arrays as `${arr[@]+"${arr[@]}"}`, and run external tools with `</dev/null`.
- Comments explain *why*, often citing the incident that motivated the code (for
  example "ether.fi reported ~11.9k bogus 403s"). Keep that style.
- Make one coherent change per subsystem, with a regression test and a doc update in
  the same commit.

## Git
- Branch off `main` (`feat/...`, `fix/...`). Use conventional commit subjects
  (`fix(extractor): ...`, `feat(forms,proxychains): ...`) with a body explaining the
  root cause. Commit and push when the operator asks. At the end of a feature they
  usually want it committed and pushed. Remote: `github.com/maxamin/jsintel`.
- Never commit run outputs, target lists, `.claude/`, or `tests/lab/runtime/` (all are
  in `.gitignore`).

## Default work loop
1. Read `recommendations.md`, `TESTING_PROGRESS.md` (tail), and known-gaps.md, then pick an item.
2. Trace the code path (this skill's modules.md) and find the owning layer.
3. Implement it at the root cause and add tests (`pytest -q` stays green).
4. Validate on the lab (unauthenticated, cookie, and JWT) or on an existing real corpus, read-only.
5. Update TESTING_PROGRESS (milestone), recommendations (remove, then add new ideas),
   the docs, README flags, **and this skill** (`skills/jsintel/*.md`: module
   reference, flags/env table, known-gaps) so the next model starts from accurate facts.
6. Commit on a branch, then push if asked.
