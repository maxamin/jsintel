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
    for a in records(output/'reports/assets.json'):
        cur.execute('''INSERT INTO assets(url,local_path,asset_type,sha256,size_bytes,mime_type,status)
          VALUES(?,?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET local_path=excluded.local_path, asset_type=excluded.asset_type,
          sha256=excluded.sha256,size_bytes=excluded.size_bytes,mime_type=excluded.mime_type,status=excluded.status''',
          (a['url'],a.get('local_path'),a['type'],a.get('sha256'),a.get('size_bytes'),a.get('mime_type'),a.get('status','discovered')))
        ids[a['url']]=cur.execute('SELECT id FROM assets WHERE url=?',(a['url'],)).fetchone()[0]
    for f, table, field, kind in [('urls.json','urls','url','url'),('websocket.json','urls','url','websocket'),('endpoints.json','endpoints','endpoint','api')]:
        for r in records(output/'reports'/f):
            aid=ids.get(r.get('asset_url'))
            if aid: cur.execute(f'INSERT OR IGNORE INTO {table}(asset_id,{field},kind) VALUES(?,?,?)',(aid,r[field],r.get('kind',kind)))
    for r in records(output/'reports/frameworks.json'):
        aid=ids.get(r.get('asset_url'))
        if aid: cur.execute('INSERT OR IGNORE INTO technologies(asset_id,name,evidence) VALUES(?,?,?)',(aid,r['technology'],r.get('evidence')))
    con.commit(); con.close()
def query(output: Path, config: Path, sql: str) -> None:
    con=connect(output,config)
    for row in con.execute(sql): print(json.dumps(dict(row)))
if __name__ == '__main__':
    p=argparse.ArgumentParser(); p.add_argument('--output',required=True,type=Path); p.add_argument('--config',default=ROOT/'config/config.yaml',type=Path)
    sub=p.add_subparsers(dest='command',required=True); sub.add_parser('ingest'); q=sub.add_parser('query'); q.add_argument('sql')
    a=p.parse_args(); ingest(a.output,a.config) if a.command=='ingest' else query(a.output,a.config,a.sql)
