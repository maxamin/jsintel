# Problematique — testing JSIntel against real vulnerable labs

This folder is the running log of **what JSIntel misses** when driven against a broad
set of intentionally-vulnerable apps, and the **features required** to close those
gaps. It is the feedback loop that turns "the pipeline runs" into "the pipeline finds
what a competent operator would".

- `problems.md` — the master log: per-lab install status, what JSIntel detected vs.
  what it *should* have (the **false negatives / hidden positives**), and bugs.
- `required-features.md` — deduplicated, prioritized feature backlog derived from the
  false negatives (candidates to graduate into `recommendations.md` and then ship).

Method per lab: install (loopback-only), run the full chain (`-p -w -f`, plus
`--cookie/--jwt` where auth applies), then compare JSIntel's reports against the
app's *known* vulnerability classes and recon signals. Anything a good recon tool
would surface that JSIntel does not = a documented hidden positive.
