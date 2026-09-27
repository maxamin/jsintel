#!/usr/bin/env python3
"""Feedback discovery: fetch newly-discovered in-scope assets and merge them into the
manifest, so the extractor→fuzzer/crawler cycle can find assets that are only referenced
from other extracted assets (an endpoint/URL/spec path pointing at a JS bundle the crawler
never saw). Run AFTER extraction; the pipeline then re-extracts the enlarged manifest.

Scope safety: candidates are only ever built on **hosts already present in the manifest**
(hosts already fetched in-scope). A site-relative endpoint is resolved against those known
hosts; an absolute URL is kept only if its host is already in scope. Discovery therefore
finds new *paths on known hosts* and can never introduce a new host. Budget-capped
(``--limit``) and de-duplicated across rounds via ``reports/.discovered.json``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

_PAGE_EXT = ('.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.html', '.htm', '.xhtml',
             '.shtml', '.asp', '.aspx', '.ashx', '.jsp', '.jspx', '.do', '.action', '.cfm',
             '.cgi', '.pl', '.py', '.rb')
# Endpoints/paths we must NOT try to fetch: templated/placeholder routes, wildcards, or
# obvious non-assets. Fetching these is noise (and a templated path is not a real URL).
_SKIP = re.compile(r"[{}$*<>\s]|\.\.|%7[bBdD]|:\w+")


def _classify(url: str) -> str:
    path = url.split('?', 1)[0].split('#', 1)[0].lower()
    name = path.rsplit('/', 1)[-1]
    if path.endswith(('.js', '.mjs')):
        return 'javascript'
    if path.endswith('.map'):
        return 'source_map'
    if path.endswith('.wasm'):
        return 'webassembly'
    if name in ('manifest.json', 'manifest.webmanifest') or path.endswith('.webmanifest'):
        return 'manifest'
    if re.search(r'(^|[._/-])(service-)?worker([._/-]|$)', path):
        return 'worker'
    if path.endswith('.json'):
        return 'configuration'
    if path.endswith(_PAGE_EXT) or name == '' or '.' not in name:
        return 'page'
    return 'other'


def _records(path: Path):
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _candidates(reports: Path, in_scope: dict[str, str], existing: set[str], limit: int) -> list[str]:
    """Build fetchable candidate URLs from the extracted reports, restricted to in-scope
    hosts. ``in_scope`` maps netloc -> scheme (from already-fetched assets)."""
    out: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        if url and url not in existing and url not in seen and url not in out:
            seen.add(url)
            out.append(url)

    # site-relative endpoints -> resolved against every known in-scope host
    for src in ('endpoints.json', 'api_spec_endpoints.json'):
        for r in _records(reports / src):
            ep = (r.get('endpoint') or '').strip()
            if not ep or _SKIP.search(ep):
                continue
            if ep.startswith(('http://', 'https://')):
                sp = urlsplit(ep)
                if sp.netloc in in_scope:
                    add(ep)
            elif ep.startswith('/'):
                for netloc, scheme in in_scope.items():
                    add(urlunsplit((scheme, netloc, ep.split('?', 1)[0].split('#', 1)[0], '', '')))
    # absolute URLs, kept only if their host is already in scope
    for r in _records(reports / 'urls.json'):
        u = (r.get('url') or '').strip()
        if u.startswith('//'):
            u = 'https:' + u
        if u.startswith(('http://', 'https://')) and not _SKIP.search(u):
            if urlsplit(u).netloc in in_scope:
                add(u)
    return out[:limit]


def _download(url: str, dest: Path, auth: dict, timeout: int, retries: int):
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    session = requests.Session()
    retry = Retry(total=retries, connect=retries, read=retries, backoff_factor=.4,
                  status_forcelist=(429, 500, 502, 503, 504), allowed_methods=frozenset(['GET']))
    session.mount('http://', HTTPAdapter(max_retries=retry))
    session.mount('https://', HTTPAdapter(max_retries=retry))
    with session.get(url, headers=dict(auth), stream=True, timeout=(5, timeout)) as r:
        r.raise_for_status()
        data = r.content
        dest.write_bytes(data)
        ctype = r.headers.get('Content-Type', '').split(';')[0] or mimetypes.guess_type(dest.name)[0]
        return {'local_path': str(dest), 'sha256': hashlib.sha256(data).hexdigest(),
                'size_bytes': len(data), 'mime_type': ctype, 'status': 'downloaded'}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Feedback discovery: fetch newly-referenced in-scope assets.")
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--config', type=Path, default=Path('config/config.yaml'))
    p.add_argument('--limit', type=int, default=200, help="max new assets to fetch this round")
    a = p.parse_args(argv)
    reports = a.output / 'reports'
    asset_dir = a.output / 'assets'
    manifest = reports / 'assets.json'
    items = _records(manifest)
    if not items:
        print(0)
        return 0
    existing = {it['url'] for it in items if it.get('url')}
    in_scope: dict[str, str] = {}
    for it in items:
        sp = urlsplit(it.get('url', ''))
        if sp.netloc and sp.scheme in ('http', 'https'):
            in_scope.setdefault(sp.netloc, sp.scheme)
    state_file = reports / '.discovered.json'
    attempted = set(_records(state_file))
    cands = [u for u in _candidates(reports, in_scope, existing, a.limit * 4) if u not in attempted][:a.limit]
    if not cands:
        print(0)
        return 0
    auth = {}
    if os.environ.get('JSINTEL_AUTH_COOKIE', '').strip():
        auth['Cookie'] = os.environ['JSINTEL_AUTH_COOKIE'].strip()
    if os.environ.get('JSINTEL_AUTH_BEARER', '').strip():
        auth['Authorization'] = 'Bearer ' + os.environ['JSINTEL_AUTH_BEARER'].strip()
    added = 0
    base = len(items)
    for i, url in enumerate(cands):
        attempted.add(url)
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', urlsplit(url).path.rsplit('/', 1)[-1] or 'asset')[:120]
        dest = asset_dir / f'disc_{base + i:06d}_{safe}'
        try:
            meta = _download(url, dest, auth, 15, 2)
        except Exception:
            continue
        rec = {'url': url, 'type': _classify(url)}
        rec.update(meta)
        items.append(rec)
        added += 1
    manifest.write_text(json.dumps(items, indent=2) + '\n')
    state_file.write_text(json.dumps(sorted(attempted)))
    print(added)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
