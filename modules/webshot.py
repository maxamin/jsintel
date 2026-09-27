#!/usr/bin/env python3
"""Screenshot discovered web services for fast visual triage.

A port scan on a real target yields dozens-to-hundreds of live services; reading
JSON to tell "login panel" from "default nginx" from "CDN block page" is slow. This
stage renders each *distinct* service (the port scanner already collapses CDN
port-mirrors, so we never shoot the same site ten times) to a PNG and builds a
self-contained HTML gallery.

Two things make the gallery a triage tool rather than a wall of images:

* **Perceptual clustering.** Each screenshot gets a dHash; near-identical looks
  (the same SPA shell or login page served by many subdomains) are grouped, so the
  gallery shows "6 distinct looks across N hosts" instead of N separate thumbnails.
* **Finding cross-reference.** When ``reports/findings.json`` is present, a service
  whose host already yielded a critical/high finding is flagged in the gallery.

Rendering uses headless Chromium (no extra Python deps); screenshotting sends a
page load to each service, so -- like the scan and the fuzz -- it runs only against
the authorized, in-scope services the caller supplies.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

LOGGER = logging.getLogger("jsintel.webshot")

CHROMIUM_CANDIDATES = ("chromium", "chromium-browser", "google-chrome", "chrome", "google-chrome-stable")


def find_chromium(explicit: str = "") -> str:
    """Return a usable Chromium/Chrome binary path, or '' if none is installed."""
    if explicit:
        return explicit if shutil.which(explicit) or Path(explicit).is_file() else ""
    for name in CHROMIUM_CANDIDATES:
        found = shutil.which(name)
        if found:
            return found
    return ""


def _safe_name(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or "host"
    port = parts.port or ("443" if parts.scheme == "https" else "80")
    return f"{host}_{port}".replace(":", "_").replace("/", "_")


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render_screenshot(
    url: str,
    out_path: Path,
    *,
    chromium: str,
    width: int = 1440,
    height: int = 900,
    timeout: float = 30.0,
) -> bool:
    """Render ``url`` to ``out_path`` with headless Chromium. Return success."""
    # A unique profile dir per call avoids "profile already in use" clashes when
    # several Chromium instances run concurrently.
    profile = Path(tempfile.mkdtemp(prefix="jsintel-chrome-"))
    cmd = [
        chromium, "--headless", "--no-sandbox", "--disable-gpu",
        "--disable-dev-shm-usage", "--ignore-certificate-errors",
        "--hide-scrollbars", "--no-first-run", "--no-default-browser-check",
        f"--user-data-dir={profile}",
        f"--window-size={width},{height}",
        "--virtual-time-budget=8000",
        f"--screenshot={out_path}",
        url,
    ]
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return False
    finally:
        shutil.rmtree(profile, ignore_errors=True)
    if not (out_path.is_file() and out_path.stat().st_size > 0):
        return False
    return not _is_blank(out_path)


def _is_blank(path: Path) -> bool:
    """True if the PNG is a single uniform colour (a failed/empty render).

    A heavy SPA that didn't finish rendering can yield an all-white/all-blank
    image; treating that as a failure lets the serial-retry pass try again.
    """
    try:
        from PIL import Image
        lo, hi = Image.open(path).convert("L").getextrema()
        return lo == hi
    except Exception:  # noqa: BLE001 - if PIL is absent, accept the render
        return False


# --------------------------------------------------------------------------- #
# Perceptual hashing + clustering
# --------------------------------------------------------------------------- #
def perceptual_hash(path: Path) -> str:
    """Return a 64-bit dHash as 16 hex chars, or '' if the image can't be read.

    dHash compares each pixel to its right neighbour on a 9x8 grayscale thumbnail;
    it is robust to minor rendering differences while still separating genuinely
    different pages.
    """
    try:
        from PIL import Image
    except ImportError:
        return ""
    try:
        img = Image.open(path).convert("L").resize((9, 8))
    except Exception:  # noqa: BLE001 - any decode failure -> no hash
        return ""
    px = list(img.tobytes())  # 72 grayscale bytes, row-major (9 wide x 8 tall)
    bits = 0
    for row in range(8):
        for col in range(8):
            bits = (bits << 1) | (1 if px[row * 9 + col] > px[row * 9 + col + 1] else 0)
    return f"{bits:016x}"


def hamming(a: str, b: str) -> int:
    """Hamming distance between two hex hashes; large if either is missing/empty."""
    if not a or not b or len(a) != len(b):
        return 64
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def cluster_by_phash(records: list[dict], threshold: int = 10) -> int:
    """Assign a ``cluster`` id to each record by dHash similarity. Return count.

    Greedy: a record joins the first existing cluster whose representative hash is
    within ``threshold`` bits, else starts a new one. Records without a hash each
    get their own cluster (they cannot be shown to match anything).
    """
    reps: list[tuple[int, str]] = []  # (cluster_id, representative_hash)
    next_id = 0
    for rec in records:
        h = rec.get("phash", "")
        assigned = None
        if h:
            for cluster_id, rep in reps:
                if hamming(h, rep) <= threshold:
                    assigned = cluster_id
                    break
        if assigned is None:
            assigned = next_id
            reps.append((assigned, h))
            next_id += 1
        rec["cluster"] = assigned
    return next_id


# --------------------------------------------------------------------------- #
# Metadata + gallery
# --------------------------------------------------------------------------- #
def _load_service_meta(reports_dir: Path) -> dict[str, dict]:
    """Map url -> {status,title,server} from ports.json, when available."""
    meta: dict[str, dict] = {}
    ports = reports_dir / "ports.json"
    if ports.is_file():
        try:
            for s in json.loads(ports.read_text(encoding="utf-8")):
                if isinstance(s, dict) and s.get("url"):
                    meta[s["url"]] = s
        except (OSError, json.JSONDecodeError):
            pass
    return meta


def _hosts_with_high_findings(reports_dir: Path) -> set[str]:
    """Hosts that already yielded a critical/high finding (for cross-reference)."""
    hosts: set[str] = set()
    findings = reports_dir / "findings.json"
    if not findings.is_file():
        return hosts
    try:
        data = json.loads(findings.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return hosts
    for f in data if isinstance(data, list) else []:
        if isinstance(f, dict) and f.get("severity") in ("critical", "high"):
            host = urlsplit(str(f.get("asset_url", ""))).hostname
            if host:
                hosts.add(host)
    return hosts


def _html_escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def write_gallery(html_path: Path, records: list[dict], clusters: int) -> None:
    """Write a self-contained HTML gallery, grouped by visual cluster."""
    shots = [r for r in records if r.get("file")]
    by_cluster: dict[int, list[dict]] = {}
    for r in shots:
        by_cluster.setdefault(r.get("cluster", -1), []).append(r)
    # Largest clusters first -- the "many hosts, one look" groups are the least
    # interesting to click into, but seeing their size up front is the point.
    order = sorted(by_cluster.items(), key=lambda kv: (-len(kv[1]), kv[0]))

    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        "<title>JSIntel Screenshots</title>",
        "<style>",
        ":root{--bg:#0f1115;--card:#1a1d24;--fg:#e6e6e6;--muted:#9aa4b2;--flag:#ff5c5c;--line:#2a2f3a}",
        "@media(prefers-color-scheme:light){:root{--bg:#f6f7f9;--card:#fff;--fg:#1a1a1a;--muted:#666;--line:#e2e5ea}}",
        "*{box-sizing:border-box}body{margin:0;padding:24px;background:var(--bg);color:var(--fg);"
        "font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}",
        "h1{font-size:20px;margin:0 0 4px}.sub{color:var(--muted);margin-bottom:24px}",
        ".cluster{margin:0 0 28px}.chead{color:var(--muted);font-size:13px;margin:0 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}",
        ".grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}",
        ".card{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}",
        ".card img{width:100%;height:190px;object-fit:cover;object-position:top;display:block;background:#000}",
        ".meta{padding:10px 12px}.u{font-weight:600;word-break:break-all}.u a{color:inherit;text-decoration:none}",
        ".row{color:var(--muted);font-size:12px;margin-top:4px;word-break:break-all}",
        ".flag{color:var(--flag);font-weight:700}",
        "</style></head><body>",
        f"<h1>JSIntel Screenshots</h1><div class='sub'>{len(shots)} screenshot(s) · "
        f"{clusters} distinct visual cluster(s)</div>",
    ]
    for cluster_id, recs in order:
        rep = recs[0]
        title = _html_escape(rep.get("title") or "")
        parts.append("<section class='cluster'>")
        parts.append(f"<div class='chead'>Cluster {cluster_id} — {len(recs)} host(s)"
                     + (f" · “{title}”" if title else "") + "</div>")
        parts.append("<div class='grid'>")
        for r in recs:
            img_rel = "../assets/screenshots/" + Path(r["file"]).name
            url = _html_escape(r["url"])
            status = r.get("status", "?")
            server = _html_escape(r.get("server") or "")
            t = _html_escape(r.get("title") or "")
            flag = " <span class='flag'>● high-severity finding on host</span>" if r.get("flagged") else ""
            parts.append(
                f"<div class='card'><a href='{img_rel}' target='_blank'>"
                f"<img loading='lazy' src='{img_rel}' alt='{url}'></a><div class='meta'>"
                f"<div class='u'><a href='{url}' target='_blank'>{url}</a></div>"
                f"<div class='row'>HTTP {status}{(' · ' + server) if server else ''}{flag}</div>"
                + (f"<div class='row'>{t}</div>" if t else "")
                + "</div></div>"
            )
        parts.append("</div></section>")
    parts.append("</body></html>")
    html_path.write_text("".join(parts), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def _read_urls(path: Path) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and line not in seen:
            seen.add(line)
            urls.append(line)
    return urls


def run(
    output: Path,
    services_file: Path,
    *,
    chromium: str = "",
    workers: int = 6,
    timeout: float = 30.0,
    width: int = 1440,
    height: int = 900,
    cluster_threshold: int = 10,
    renderer=None,
) -> dict:
    """Screenshot each service, cluster, and write the gallery. Return a summary.

    ``renderer`` is injectable for testing; it defaults to headless Chromium.
    """
    reports_dir = output / "reports"
    shots_dir = output / "assets" / "screenshots"
    shots_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    urls = _read_urls(services_file) if services_file.is_file() else []
    if not urls:
        (reports_dir / "screenshots.json").write_text("[]\n", encoding="utf-8")
        return {"services": 0, "captured": 0, "clusters": 0, "engine": "none"}

    if renderer is None:
        binary = find_chromium(chromium)
        if not binary:
            LOGGER.warning("No Chromium/Chrome found; skipping screenshots")
            (reports_dir / "screenshots.json").write_text("[]\n", encoding="utf-8")
            return {"services": len(urls), "captured": 0, "clusters": 0, "engine": "none"}
        engine = binary

        def renderer(url, out_path):  # noqa: ANN001
            return render_screenshot(url, out_path, chromium=binary,
                                     width=width, height=height, timeout=timeout)
    else:
        engine = "injected"

    meta = _load_service_meta(reports_dir)
    flagged_hosts = _hosts_with_high_findings(reports_dir)

    def capture(url: str) -> dict:
        out = shots_dir / (_safe_name(url) + ".png")
        ok = bool(renderer(url, out))
        host = urlsplit(url).hostname or ""
        m = meta.get(url, {})
        rec = {
            "url": url,
            "file": str(out) if ok else "",
            "status": m.get("status", ""),
            "title": m.get("title", ""),
            "server": m.get("server", ""),
            "flagged": host in flagged_hosts,
            "phash": perceptual_hash(out) if ok else "",
        }
        return rec

    records: list[dict] = []
    max_workers = max(1, min(workers, len(urls)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for rec in pool.map(capture, urls):
            records.append(rec)

    # Retry failures SERIALLY. Heavy SPAs (e.g. an Angular app like Juice Shop)
    # commonly fail under concurrent rendering -- several headless Chromium
    # instances loading a large bundle at once exhaust memory/time and produce no
    # file. A single render of the same page succeeds, so a one-at-a-time retry
    # pass recovers exactly those, without slowing the common (light-page) case.
    failed = [r for r in records if not r["file"]]
    if failed:
        LOGGER.info("Retrying %d failed render(s) serially", len(failed))
        by_url = {r["url"]: r for r in records}
        for rec in failed:
            by_url[rec["url"]] = capture(rec["url"])
        records = list(by_url.values())

    records.sort(key=lambda r: r["url"])
    clusters = cluster_by_phash(records, threshold=cluster_threshold)
    (reports_dir / "screenshots.json").write_text(
        json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    captured = sum(1 for r in records if r["file"])
    if captured:
        write_gallery(reports_dir / "screenshots.html", records, clusters)
    return {
        "services": len(urls),
        "captured": captured,
        "clusters": clusters,
        "engine": engine,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m modules.webshot",
        description="Screenshot discovered web services and build a triage gallery.",
    )
    parser.add_argument("--output", required=True, type=Path, help="JSIntel output directory.")
    parser.add_argument("--services", type=Path, default=None,
                        help="File of service URLs (default: <output>/assets/services.txt).")
    parser.add_argument("--chromium", default="", help="Chromium/Chrome binary (default: autodetect).")
    parser.add_argument("--workers", type=int, default=6, help="Concurrent renders (default: 6).")
    parser.add_argument("--timeout", type=float, default=30.0, help="Per-page timeout seconds.")
    parser.add_argument("--cluster-threshold", type=int, default=10, help="dHash Hamming threshold.")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
    services = args.services or (args.output / "assets" / "services.txt")
    summary = run(
        args.output, services, chromium=args.chromium, workers=max(1, args.workers),
        timeout=args.timeout, cluster_threshold=args.cluster_threshold,
    )
    LOGGER.info(
        "Screenshotted %d/%d service(s) into %d visual cluster(s) [engine: %s].",
        summary["captured"], summary["services"], summary["clusters"], summary["engine"],
    )
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
