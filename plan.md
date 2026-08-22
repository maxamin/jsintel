# Plan: JSIntel Ultimate Workflow (v5)

## Inputs (verified)
- `JSIntel_Workflow_v2.md` (630 lines) — improvement protocol; has Communication Rules + full decision trees + testing protocol
- `JSIntel_Workflow_v3.md` (625 lines) — complete protocol; truncated after Phase D2; promised sections 4–11 missing; has Document Map + Gap Matrix
- `JSIntel_Workflow_v3 (1).md` — byte-identical duplicate of v3 (md5 match)
- `JSIntel_Workflow_v4.md` (1329 lines) — most complete; 21 sections; adds state machine, performance targets, error handling, troubleshooting, review checklist, config reference, glossary
- `JSIntel_Whitepaper_Generation_Prompt.md` — Phase 2 vision (knowledge graph, AI layer, source maps, OpenAPI/Insomnia, CI/CD, diff engine, confidence model)

## Goal
Synthesize the best of all versions into ONE definitive "ultimate" workflow document:
`JSIntel_Ultimate_Workflow_v5.md` in /mnt/agents/output/.

## Known defects to fix in synthesis
1. v4 section numbering jump (Section 3 contains Phases A–D, then jumps to Section 7) → renumber cleanly.
2. Test-code inconsistency: v2 expects finding_type "dom_xss", v4 expects "taint_to_sink" → standardize to one canonical naming.
3. Constraint tension: "NEVER use regex for security detection" vs secrets analyzer using regex on literals → clarify scoping.
4. v3's truncated/missing sections → restored from v4.
5. Whitepaper Phase 2 vision not present in any workflow → add as forward roadmap section (clearly marked, not Phase 1 scope).

## Stages
1. **Synthesize (main agent)**: Write `JSIntel_Ultimate_Workflow_v5.md` in /mnt/agents/output/ — v4 as backbone, merge v2/v3-unique content, fix defects, add Phase 2 roadmap from whitepaper prompt. Write in multiple appends (size ~60–75KB).
2. **Review (reviewer subagent)**: Independent review against source files — completeness, consistency, numbering, contradictions.
3. **Fix & deliver**: Apply fixes, final KIMI_REF delivery of the .md.

## Deliverable
- `/mnt/agents/output/JSIntel_Ultimate_Workflow_v5.md` (primary; markdown is the native format of all source workflows, consumed by agents)
