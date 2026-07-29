#!/usr/bin/env bash
# Concurrent, resumable downloads. Metadata is merged into reports/assets.json.
set -Eeuo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$BASE_DIR/modules/utils.sh"
MANIFEST="${1:?assets.json manifest required}"; ASSET_DIR="$OUTPUT_DIR/assets"
TIMEOUT=$(awk '/^download:/ {p=1; next} p && /^[[:space:]]+timeout:/ {print $2; exit}' "$CONFIG" 2>/dev/null || true); TIMEOUT="${TIMEOUT:-15}"
RETRIES=$(awk '/^download:/ {p=1; next} p && /^[[:space:]]+retries:/ {print $2; exit}' "$CONFIG" 2>/dev/null || true); RETRIES="${RETRIES:-3}"
export MANIFEST ASSET_DIR TIMEOUT RETRIES THREADS
python3 - <<'PY'
import concurrent.futures, hashlib, json, mimetypes, os, pathlib, re, urllib.parse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
manifest=pathlib.Path(os.environ['MANIFEST']); asset_dir=pathlib.Path(os.environ['ASSET_DIR']); asset_dir.mkdir(parents=True,exist_ok=True)
items=json.loads(manifest.read_text())
def fetch(index, item):
    url=item['url']; parsed=urllib.parse.urlsplit(url); base=pathlib.Path(parsed.path).name or 'asset'
    safe=re.sub(r'[^A-Za-z0-9._-]', '_', base)[:120]
    path=asset_dir / f'{index:06d}_{safe}'
    part=path.with_suffix(path.suffix+'.part'); headers={}
    if part.exists(): headers['Range']=f'bytes={part.stat().st_size}-'
    try:
        session=requests.Session()
        retry=Retry(total=int(os.environ['RETRIES']), connect=int(os.environ['RETRIES']), read=int(os.environ['RETRIES']), backoff_factor=.4, status_forcelist=(429,500,502,503,504), allowed_methods=frozenset(['GET']))
        session.mount('http://',HTTPAdapter(max_retries=retry)); session.mount('https://',HTTPAdapter(max_retries=retry))
        with session.get(url, headers=headers, stream=True, timeout=(5,int(os.environ['TIMEOUT']))) as r:
            r.raise_for_status(); mode='ab' if r.status_code==206 and part.exists() else 'wb'
            with part.open(mode) as f:
                for chunk in r.iter_content(65536):
                    if chunk: f.write(chunk)
            part.replace(path)
            data=path.read_bytes()
            return index, {'local_path':str(path), 'sha256':hashlib.sha256(data).hexdigest(), 'size_bytes':len(data), 'mime_type':r.headers.get('Content-Type','').split(';')[0] or mimetypes.guess_type(path.name)[0], 'status':'downloaded'}
    except requests.RequestException as e: return index, {'status':'failed','error':str(e)}
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
