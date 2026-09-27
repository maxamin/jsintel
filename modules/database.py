#!/usr/bin/env python3
"""SQLite storage and query interface for JSIntel reports."""
from __future__ import annotations
import argparse, json, sqlite3
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
def db_path(output: Path, config: Path) -> Path:
    # Output is authoritative, avoiding accidental writes to the project directory.
    return output / 'database' / 'recon.db'
def connect(output: Path, config: Path) -> sqlite3.Connection:
    path=db_path(output,config); path.parent.mkdir(parents=True,exist_ok=True)
    con=sqlite3.connect(path); con.row_factory=sqlite3.Row
    con.executescript((ROOT/'database'/'schema.sql').read_text()); return con
def records(path: Path):
    return json.loads(path.read_text()) if path.exists() else []
def ingest(output: Path, config: Path) -> None:
    con=connect(output,config); cur=con.cursor(); ids={}
    # Rebuild from the current reports rather than accumulating. The pipeline
    # overwrites reports/*.json every run, so re-running into the same output dir
    # must not leave stale rows behind: without this, `findings` (plain INSERT)
    # doubled on every re-run and `fuzz_results`/`urls`/`endpoints` retained a prior
    # run's rows -- including now out-of-scope hosts -- inflating the reports. The
    # reports/*.json remain the durable source of truth; the DB is derived from them.
    cur.execute('PRAGMA foreign_keys = ON')
    cur.execute('DELETE FROM assets')  # cascades to urls/endpoints/technologies/findings
    cur.execute('DELETE FROM fuzz_results')
    # Assets: table was just cleared, so every insert is fresh -> cur.lastrowid is
    # the new id (no per-row SELECT round-trip needed).
    for a in records(output/'reports/assets.json'):
        cur.execute('''INSERT INTO assets(url,local_path,asset_type,sha256,size_bytes,mime_type,status)
          VALUES(?,?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET local_path=excluded.local_path, asset_type=excluded.asset_type,
          sha256=excluded.sha256,size_bytes=excluded.size_bytes,mime_type=excluded.mime_type,status=excluded.status''',
          (a['url'],a.get('local_path'),a['type'],a.get('sha256'),a.get('size_bytes'),a.get('mime_type'),a.get('status','discovered')))
        if a['url'] not in ids:
            ids[a['url']]=cur.lastrowid
    # Register discovered live services as 'service' assets so that live-service
    # findings (reports/security.json) can attach to them and surface per host in
    # triage. These are excluded from the JS/asset counts in the reporter.
    for s in records(output/'reports/ports.json'):
        if not isinstance(s,dict) or s.get('mirror_of'): continue
        surl=s.get('url')
        if not surl or surl in ids: continue
        cur.execute('''INSERT INTO assets(url,local_path,asset_type,sha256,size_bytes,mime_type,status)
          VALUES(?,?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET asset_type=excluded.asset_type,status=excluded.status''',
          (surl,None,'service',None,None,None,str(s.get('status','')) or 'discovered'))
        ids[surl]=cur.lastrowid
    # Bulk-insert the per-asset tables with executemany (one C call per table rather
    # than one per row; findings alone can be tens of thousands of rows).
    for f, table, field, kind in [('urls.json','urls','url','url'),('websocket.json','urls','url','websocket'),('endpoints.json','endpoints','endpoint','api'),('api_spec_endpoints.json','endpoints','endpoint','api')]:
        rows=[(aid,r[field],r.get('kind',kind)) for r in records(output/'reports'/f)
              if (aid:=ids.get(r.get('asset_url'))) is not None and r.get(field) is not None]
        if rows: cur.executemany(f'INSERT OR IGNORE INTO {table}(asset_id,{field},kind) VALUES(?,?,?)',rows)
    tech=[(aid,r['technology'],r.get('evidence')) for r in records(output/'reports/frameworks.json')
          if (aid:=ids.get(r.get('asset_url'))) is not None and r.get('technology')]
    if tech: cur.executemany('INSERT OR IGNORE INTO technologies(asset_id,name,evidence) VALUES(?,?,?)',tech)
    # Static (extractor) findings + live-service (security.json) findings, both
    # attached to their asset (a downloaded file, or a 'service' asset above).
    finds=[(aid,r['finding_type'],r['severity'],r['value'])
           for src in ('findings.json','security.json') for r in records(output/'reports'/src)
           if (aid:=ids.get(r.get('asset_url'))) is not None]
    if finds: cur.executemany('INSERT INTO findings(asset_id,finding_type,severity,value) VALUES(?,?,?,?)',finds)
    # Response anomalies (listener --aggressive): a known flow whose response changed.
    # Surfaced as findings so they rank per host in triage; a NEW secret in a changed
    # response is high severity. Attaches to the captured asset by its URL.
    anoms=[(aid,'response_anomaly',{'info':'low'}.get(r.get('severity'),r.get('severity','low')),
            f"{r.get('kind','change')}: {r.get('url','')}"+
            (f" [+secrets: {', '.join(r['added_secrets'])}]" if r.get('added_secrets') else ''))
           for r in records(output/'reports/anomalies.json')
           if (aid:=ids.get(r.get('url'))) is not None]
    if anoms: cur.executemany('INSERT INTO findings(asset_id,finding_type,severity,value) VALUES(?,?,?,?)',anoms)
    # Fuzz results are keyed by target URL and independent of the asset table;
    # only actually-probed rows are stored (planning/skipped rows are omitted).
    fuzz=[(r['url'],r.get('category',''),r.get('origin'),r.get('word'),r.get('status'),r.get('length'),
           1 if r.get('interesting') else 0,r.get('note'))
          for r in records(output/'reports/fuzz.json') if r.get('note') not in ('dry-run','out-of-scope')]
    if fuzz:
        cur.executemany(
            '''INSERT INTO fuzz_results(url,category,origin,word,status,length,interesting,note)
               VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET
               status=excluded.status,length=excluded.length,interesting=excluded.interesting,note=excluded.note''',
            fuzz)
    # Web services (reports/ports.json), joined to their screenshot (by URL) when
    # the webshot stage produced reports/screenshots.json. Rebuilt each run like the
    # rest; the file reports stay the source of truth. CDN port-mirrors are kept
    # (annotated via mirror_of) so the DB mirrors ports.json exactly; the triage
    # report and reporter are what collapse them for headline counts.
    cur.execute('DELETE FROM services')
    shots_by_url = {}
    for r in records(output/'reports/screenshots.json'):
        if isinstance(r, dict) and r.get('url'):
            shots_by_url[r['url']] = r
    svc=[(s.get('host',''), s.get('port'), s.get('scheme'), s['url'], s.get('status'),
          s.get('server'), s.get('title'), s.get('mirror_of'),
          (shots_by_url.get(s['url'], {}).get('file') or None), shots_by_url.get(s['url'], {}).get('cluster'))
         for s in records(output/'reports/ports.json') if isinstance(s, dict) and s.get('url')]
    if svc:
        cur.executemany(
            '''INSERT INTO services(host,port,scheme,url,status,server,title,mirror_of,screenshot_path,cluster)
               VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET
               host=excluded.host,port=excluded.port,scheme=excluded.scheme,status=excluded.status,
               server=excluded.server,title=excluded.title,mirror_of=excluded.mirror_of,
               screenshot_path=excluded.screenshot_path,cluster=excluded.cluster''',
            svc)
    con.commit(); con.close()
def query(output: Path, config: Path, sql: str) -> None:
    con=connect(output,config)
    for row in con.execute(sql): print(json.dumps(dict(row)))
if __name__ == '__main__':
    p=argparse.ArgumentParser(); p.add_argument('--output',required=True,type=Path); p.add_argument('--config',default=ROOT/'config/config.yaml',type=Path)
    sub=p.add_subparsers(dest='command',required=True); sub.add_parser('ingest'); q=sub.add_parser('query'); q.add_argument('sql')
    a=p.parse_args(); ingest(a.output,a.config) if a.command=='ingest' else query(a.output,a.config,a.sql)
