"""CLI entry point for the active form stage.

Discovers forms on one or more pages, synthesizes spec-valid data, submits them
(static engine) and — when Chromium is available — drives the page so its client
JavaScript fires and its XHR/fetch endpoints are captured (the driver). Results,
including every newly discovered endpoint, are written to ``reports/forms.json``
and the discovered endpoints are appended to ``assets/crawled_urls.txt`` so the
rest of the pipeline can pick them up.

Sources of pages to probe (in priority order):
  --url URL            one or more explicit page URLs (repeatable)
  --urls-file FILE     a file of page URLs (one per line)
  --output DIR         reuse a prior run: read HTML pages already downloaded under
                       DIR/assets (classified as page/other in reports/assets.json)

Auth (``JSINTEL_AUTH_COOKIE``/``JSINTEL_AUTH_BEARER`` from ``jsintel.sh``'s
``--cookie``/``--jwt``) is honoured for both fetching pages and submitting forms.
Submission is ON by default; a destructive-endpoint guard is applied unless
``--no-safe-denylist`` is given. ``--proxychains`` sends all outbound traffic (page
fetch, submissions, Chromium) through a proxy chain.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

try:
    import requests
except ImportError:
    requests = None  # type: ignore

# Support running both as ``python3 -m modules.forms.main`` and via a path import.
if __package__:
    from ..authutil import auth_headers
    from ..proxyutil import maybe_reexec_proxychains
    from .driver import drive_page, find_chromium
    from .engine import submit_form
    from .parser import parse_forms
    from .safety import _DESTRUCTIVE
    from .synth import Synthesizer
else:  # pragma: no cover
    from modules.authutil import auth_headers
    from modules.proxyutil import maybe_reexec_proxychains
    from modules.forms.driver import drive_page, find_chromium
    from modules.forms.engine import submit_form
    from modules.forms.parser import parse_forms
    from modules.forms.safety import _DESTRUCTIVE
    from modules.forms.synth import Synthesizer

_DENY_JS_SOURCE = "|".join(_DESTRUCTIVE)


def _fetch_html(url: str, headers: dict, timeout: float) -> str:
    if requests is None:
        return ""
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        ctype = r.headers.get("Content-Type", "")
        if "html" in ctype or "<form" in r.text[:5000].lower():
            return r.text
    except Exception:
        return ""
    return ""


def _pages_from_output(output: Path) -> list[tuple[str, str]]:
    """Return (url, html) pairs for page-type assets already downloaded under output."""
    manifest = output / "reports" / "assets.json"
    pairs: list[tuple[str, str]] = []
    if not manifest.is_file():
        return pairs
    try:
        items = json.loads(manifest.read_text())
    except (OSError, json.JSONDecodeError):
        return pairs
    for it in items:
        if it.get("type") not in ("page", "other"):
            continue
        lp = it.get("local_path")
        if not lp or not Path(lp).is_file():
            continue
        try:
            html = Path(lp).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "<form" in html.lower() or "<input" in html.lower():
            pairs.append((it.get("url", ""), html))
    return pairs


def _in_scope(url: str, scope: list[str]) -> bool:
    if not scope:
        return True
    host = (urlsplit(url).hostname or "").lower()
    return any(host == s or host.endswith("." + s) for s in scope)


def run(pages: list[tuple[str, str]], *, submit: bool, use_browser: bool,
        headers: dict, chromium: str, seed: int | str | None,
        extra_denylist: list[str], timeout: float, apply_guard: bool = True,
        settle: float = 2.5) -> dict:
    """Probe each (url, html) page; return the aggregated report dict."""
    forms_report: list[dict] = []
    endpoints: dict[tuple[str, str], dict] = {}
    n_forms = n_submitted = 0
    for url, html in pages:
        page_forms = parse_forms(html, url)
        # NOTE: do NOT skip a page with no *static* forms — a single-page app renders
        # its forms client-side, so the browser (AJAX-spider) path below is precisely
        # what discovers them and their XHR. Only the static form loop is conditional.
        synth = Synthesizer(seed)
        page_rec = {"url": url, "forms": []}
        for form in page_forms:
            if not form.submitable_fields():
                continue
            n_forms += 1
            result = submit_form(form, synth, submit=submit, headers=headers,
                                 timeout=timeout, extra_denylist=extra_denylist,
                                 apply_guard=apply_guard)
            if result.submitted:
                n_submitted += 1
            page_rec["forms"].append({
                "action": form.resolved_action(),
                "method": form.method,
                "enctype": form.enctype,
                "fields": [f.name for f in form.submitable_fields()],
                "result": result.to_record(),
            })
        if use_browser:
            fill_map = {f.name: Synthesizer(seed).value_for(f)
                        for pf in page_forms for f in pf.submitable_fields() if f.name}
            drv = drive_page(url, fill_map, submit=submit, headers=headers,
                             chromium=chromium, deny_source=_DENY_JS_SOURCE,
                             timeout=timeout, settle=settle)
            page_rec["browser"] = drv.to_record()
            for ep in drv.endpoints:
                endpoints[(ep["method"], ep["url"])] = ep
        if page_rec["forms"] or page_rec.get("browser"):
            forms_report.append(page_rec)
    return {
        "pages_probed": len(pages),
        "forms_found": n_forms,
        "forms_submitted": n_submitted,
        "discovered_endpoints": list(endpoints.values()),
        "pages": forms_report,
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="JSIntel active form filler / AJAX-spider stage.")
    p.add_argument("--url", action="append", default=[], help="page URL to probe (repeatable)")
    p.add_argument("--urls-file", type=Path, help="file of page URLs (one per line)")
    p.add_argument("--output", type=Path, default=Path("output"),
                   help="run output dir: reused pages are read from here and forms.json is written here")
    p.add_argument("--scope", action="append", default=[],
                   help="restrict probing to this host/domain (repeatable); authorization anchor")
    p.add_argument("--no-submit", action="store_true", help="fill and report only; never submit")
    p.add_argument("--browser", action="store_true",
                   help="also drive headless Chromium to trigger client-side JS and capture XHR")
    p.add_argument("--chromium", default="", help="Chromium/Chrome binary (default: autodetect)")
    p.add_argument("--seed", default=None, help="RNG seed for reproducible synthetic data")
    p.add_argument("--deny", action="append", default=[],
                   help="extra substring that marks an action as destructive (skip submit)")
    p.add_argument("--no-safe-denylist", action="store_true",
                   help="DISABLE the built-in destructive-endpoint guard (dangerous)")
    p.add_argument("--timeout", type=float, default=20.0)
    p.add_argument("--settle", type=float, default=2.5,
                   help="seconds to wait after load and after fill for XHR to fire "
                        "(raise for heavy SPAs, e.g. 6)")
    p.add_argument("--proxychains", nargs="?", const="1", default=None,
                   help="route all outbound traffic through proxychains4 (optional config path)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    # Re-exec under proxychains first so page fetches / submissions / Chromium all
    # inherit the proxy chain. No-op if already wrapped or proxychains is absent.
    maybe_reexec_proxychains(args.proxychains)

    headers = auth_headers()
    seed = args.seed
    if seed is not None:
        try:
            seed = int(seed)
        except ValueError:
            pass

    # Assemble the pages to probe.
    pages: list[tuple[str, str]] = []
    urls: list[str] = list(args.url)
    if args.urls_file and args.urls_file.is_file():
        urls += [ln.strip() for ln in args.urls_file.read_text().splitlines()
                 if ln.strip() and not ln.startswith("#")]
    for u in urls:
        if not _in_scope(u, args.scope):
            print(f"[jsintel.forms] skipping out-of-scope url: {u}", file=sys.stderr)
            continue
        html = _fetch_html(u, headers, args.timeout)
        if html:
            pages.append((u, html))
    # Reuse already-downloaded pages from a prior run.
    if not urls:
        pages += [(u, h) for (u, h) in _pages_from_output(args.output) if _in_scope(u, args.scope)]

    chromium = find_chromium(args.chromium) if args.browser else ""
    if args.browser and not chromium:
        print("[jsintel.forms] --browser requested but no Chromium found; static engine only",
              file=sys.stderr)

    report = run(
        pages,
        submit=not args.no_submit,
        use_browser=bool(chromium),
        headers=headers,
        chromium=chromium,
        seed=seed,
        extra_denylist=args.deny,
        timeout=args.timeout,
        apply_guard=not args.no_safe_denylist,
        settle=args.settle,
    )

    out_reports = args.output / "reports"
    out_reports.mkdir(parents=True, exist_ok=True)
    (out_reports / "forms.json").write_text(json.dumps(report, indent=2) + "\n")

    # Feed discovered endpoints back into the crawl list for downstream stages.
    if report["discovered_endpoints"]:
        crawled = args.output / "assets" / "crawled_urls.txt"
        crawled.parent.mkdir(parents=True, exist_ok=True)
        existing = set()
        if crawled.is_file():
            existing = set(crawled.read_text().splitlines())
        new = [ep["url"] for ep in report["discovered_endpoints"]
               if ep["url"] not in existing and _in_scope(ep["url"], args.scope)]
        if new:
            with crawled.open("a") as fh:
                fh.write("\n".join(new) + "\n")

    print(json.dumps({k: report[k] for k in
                      ("pages_probed", "forms_found", "forms_submitted")} |
                     {"discovered_endpoints": len(report["discovered_endpoints"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
