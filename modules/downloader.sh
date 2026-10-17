#!/usr/bin/env bash
# Concurrent, resumable downloads. Metadata is merged into reports/assets.json.
set -Eeuo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$BASE_DIR/modules/utils.sh"
MANIFEST="${1:?assets.json manifest required}"; ASSET_DIR="$OUTPUT_DIR/assets"
TIMEOUT=$(awk '/^download:/ {p=1; next} p && /^[[:space:]]+timeout:/ {print $2; exit}' "$CONFIG" 2>/dev/null || true); TIMEOUT="${TIMEOUT:-15}"
RETRIES=$(awk '/^download:/ {p=1; next} p && /^[[:space:]]+retries:/ {print $2; exit}' "$CONFIG" 2>/dev/null || true); RETRIES="${RETRIES:-3}"
# Hard per-asset ceilings. `timeout` above is only a per-read-chunk (socket) timeout;
# an endpoint that trickles bytes forever (SSE / long-poll / chunked keep-alive — the
# manifest includes API/monitor roots classified as `page`) never trips it and would
# otherwise block its worker permanently, wedging the whole pipeline. These bound the
# total wall-clock time and byte count of every single download so each task always
# terminates.
MAX_SECONDS=$(awk '/^download:/ {p=1; next} p && /^[[:space:]]+max_seconds:/ {print $2; exit}' "$CONFIG" 2>/dev/null || true); MAX_SECONDS="${MAX_SECONDS:-90}"
MAX_BYTES=$(awk '/^download:/ {p=1; next} p && /^[[:space:]]+max_bytes:/ {print $2; exit}' "$CONFIG" 2>/dev/null || true); MAX_BYTES="${MAX_BYTES:-26214400}"
# Per-host circuit breaker: after this many consecutive 403/429 answers from one host
# with no success in between, the rest of that host's assets are recorded as
# "blocked" without a request. In the 2026-10-09 sweep, 37k JS/source-map fetches
# hit Cloudflare walls and 95% of all failures came from 10 hosts, every one of them
# fetched to the end. 0 disables the breaker.
BLOCK_AFTER="${JSINTEL_DOWNLOAD_BLOCK_AFTER:-25}"; [[ "$BLOCK_AFTER" =~ ^[0-9]+$ ]] || BLOCK_AFTER=25
export MANIFEST ASSET_DIR TIMEOUT RETRIES THREADS MAX_SECONDS MAX_BYTES BLOCK_AFTER
python3 - <<'PY'
import concurrent.futures, hashlib, json, mimetypes, os, pathlib, re, threading, time, urllib.parse
import requests, urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
manifest=pathlib.Path(os.environ['MANIFEST']); asset_dir=pathlib.Path(os.environ['ASSET_DIR']); asset_dir.mkdir(parents=True,exist_ok=True)
items=json.loads(manifest.read_text())
MAX_SECONDS=float(os.environ.get('MAX_SECONDS') or 90); MAX_BYTES=int(os.environ.get('MAX_BYTES') or 26214400)
BLOCK_AFTER=int(os.environ.get('BLOCK_AFTER') or 0)
_walls={}; _walls_lock=threading.Lock()  # host -> consecutive 403/429 count, or None once blocked
def _wall(host, status):
    """Record one response for ``host``; return True when the host is now blocked."""
    if not BLOCK_AFTER: return False
    with _walls_lock:
        if _walls.get(host, 0) is None: return True
        if status in (403, 429):
            _walls[host]=_walls.get(host, 0)+1
            if _walls[host]>=BLOCK_AFTER: _walls[host]=None; return True
        else:
            _walls[host]=0
        return False
def _blocked(host):
    with _walls_lock: return BLOCK_AFTER>0 and host in _walls and _walls[host] is None
class DownloadAborted(Exception):
    """A download that hit the per-asset time or size ceiling (e.g. a streaming endpoint)."""
# Authenticated downloads: send the operator-supplied session (--cookie/--jwt) so
# assets behind auth download correctly. Only in-scope assets are ever fetched.
_AUTH={}
if os.environ.get('JSINTEL_AUTH_COOKIE','').strip(): _AUTH['Cookie']=os.environ['JSINTEL_AUTH_COOKIE'].strip()
if os.environ.get('JSINTEL_AUTH_BEARER','').strip(): _AUTH['Authorization']='Bearer '+os.environ['JSINTEL_AUTH_BEARER'].strip()
def fetch(index, item):
    url=item['url']; parsed=urllib.parse.urlsplit(url); base=pathlib.Path(parsed.path).name or 'asset'
    safe=re.sub(r'[^A-Za-z0-9._-]', '_', base)[:120]
    path=asset_dir / f'{index:06d}_{safe}'
    part=path.with_suffix(path.suffix+'.part'); headers=dict(_AUTH)
    if part.exists(): headers['Range']=f'bytes={part.stat().st_size}-'
    host=(parsed.hostname or '').lower()
    if _blocked(host):
        return index, {'status':'blocked','error':f'host blocked after {BLOCK_AFTER} consecutive 403/429 responses; not requested'}
    try:
        session=requests.Session()
        retry=Retry(total=int(os.environ['RETRIES']), connect=int(os.environ['RETRIES']), read=int(os.environ['RETRIES']), backoff_factor=.4, status_forcelist=(429,500,502,503,504), allowed_methods=frozenset(['GET']))
        session.mount('http://',HTTPAdapter(max_retries=retry)); session.mount('https://',HTTPAdapter(max_retries=retry))
        start=time.monotonic()
        with session.get(url, headers=headers, stream=True, timeout=(5,int(os.environ['TIMEOUT']))) as r:
            _wall(host, r.status_code)
            r.raise_for_status(); resumed=r.status_code==206 and part.exists()
            mode='ab' if resumed else 'wb'
            written=part.stat().st_size if resumed else 0
            # Read via raw.read1(): one socket read per call, returning whatever bytes are
            # already available (decoded) instead of blocking until a full 64 KiB chunk.
            # That hands control back after each recv so the deadline/size ceilings below
            # can actually fire — even against an endpoint that trickles bytes forever,
            # which iter_content() would buffer on indefinitely, hanging the worker.
            with part.open(mode) as f:
                while True:
                    chunk=r.raw.read1(65536, decode_content=True)
                    if not chunk: break
                    f.write(chunk); written+=len(chunk)
                    if written>MAX_BYTES: raise DownloadAborted(f'exceeded max_bytes ({MAX_BYTES})')
                    if time.monotonic()-start>MAX_SECONDS: raise DownloadAborted(f'exceeded max_seconds ({MAX_SECONDS:g}s)')
            part.replace(path)
            data=path.read_bytes()
            return index, {'local_path':str(path), 'sha256':hashlib.sha256(data).hexdigest(), 'size_bytes':len(data), 'mime_type':r.headers.get('Content-Type','').split(';')[0] or mimetypes.guess_type(path.name)[0], 'status':'downloaded'}
    # urllib3.exceptions.HTTPError covers read-timeout / protocol errors raised by the
    # raw.read1() reads, which are not requests.RequestException; OSError covers socket.timeout.
    except (requests.RequestException, urllib3.exceptions.HTTPError, DownloadAborted, OSError) as e:
        # A 429 that outlived urllib3's retries surfaces as RetryError, not a response.
        if isinstance(e, requests.exceptions.RetryError) and 'too many 429' in str(e): _wall(host, 429)
        # Drop the partial so a later resume can't re-trigger an unbounded stream.
        try: part.unlink()
        except OSError: pass
        return index, {'status':'failed','error':str(e)}
with concurrent.futures.ThreadPoolExecutor(max_workers=int(os.environ['THREADS'])) as ex:
    futures=[]
    for i,item in enumerate(items):
        # requests retries are done at task level to avoid malformed partial files.
        futures.append(ex.submit(fetch,i,item))
    for fut in concurrent.futures.as_completed(futures):
        i, fields=fut.result(); items[i].update(fields)
manifest.write_text(json.dumps(items,indent=2)+'\n')
PY
log_info "Download manifest updated: $MANIFEST"
