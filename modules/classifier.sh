#!/usr/bin/env bash
# Classify asset URLs before download, producing a JSON manifest for later stages.
set -Eeuo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$BASE_DIR/modules/utils.sh"
INPUT="${1:?Crawled URL list required}"; REPORT="$OUTPUT_DIR/reports/assets.json"
python3 - "$INPUT" "$REPORT" <<'PY'
import json, pathlib, re, sys
src, dest = map(pathlib.Path, sys.argv[1:])
def classify(url):
    path = url.split('?',1)[0].split('#',1)[0].lower()
    name = path.rsplit('/',1)[-1]
    if path.endswith(('.js','.mjs')): return 'javascript'
    if path.endswith('.map'): return 'source_map'
    if path.endswith('.wasm'): return 'webassembly'
    if name in ('manifest.json','manifest.webmanifest') or path.endswith('.webmanifest'): return 'manifest'
    if re.search(r'(^|[._/-])(service-)?worker([._/-]|$)', path): return 'worker'
    if path.endswith('.json'): return 'configuration'
    return 'other'
urls = []
seen = set()
for line in src.read_text(encoding='utf-8', errors='ignore').splitlines():
    url=line.strip()
    if url.startswith(('http://','https://')) and url not in seen:
        urls.append({'url':url, 'type':classify(url)}); seen.add(url)
dest.parent.mkdir(parents=True, exist_ok=True)
dest.write_text(json.dumps(urls, indent=2)+'\n', encoding='utf-8')
PY
count=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$REPORT")
log_info "Classified $count assets"
