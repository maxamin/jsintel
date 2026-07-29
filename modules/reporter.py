#!/usr/bin/env python3
"""Create Markdown, JSON, and CSV reports from the SQLite database."""
from __future__ import annotations
import argparse, csv, json, sqlite3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main(output: Path) -> None:
    reports=output/'reports'; reports.mkdir(parents=True,exist_ok=True); db=output/'database'/'recon.db'
    con=sqlite3.connect(db); con.row_factory=sqlite3.Row
    scalar=lambda sql: con.execute(sql).fetchone()[0]
    total=scalar('SELECT COUNT(*) FROM assets'); javascript=scalar("SELECT COUNT(*) FROM assets WHERE asset_type='javascript'")
    endpoints=scalar('SELECT COUNT(*) FROM endpoints'); technologies=scalar('SELECT COUNT(DISTINCT name) FROM technologies')
    by_type={r['asset_type']:r['count'] for r in con.execute('SELECT asset_type,COUNT(*) count FROM assets GROUP BY asset_type')}
    summary={'total_assets':total,'javascript_count':javascript,'endpoint_count':endpoints,'technology_count':technologies,'file_statistics':by_type}
    (reports/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    lines=['# JSIntel Phase 1 Summary','',f'- Total assets: {total}',f'- JavaScript assets: {javascript}',f'- Endpoints: {endpoints}',f'- Technologies: {technologies}','', '## File statistics','']
    lines += [f'- {name}: {count}' for name,count in sorted(by_type.items())]
    (reports/'summary.md').write_text('\n'.join(lines)+'\n')
    cols=['url','local_path','asset_type','sha256','size_bytes','mime_type','status','discovered_at']
    with (reports/'assets.csv').open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=cols); writer.writeheader(); writer.writerows(map(dict,con.execute('SELECT '+','.join(cols)+' FROM assets ORDER BY id')))
    con.close()
if __name__=='__main__':
    ap=argparse.ArgumentParser(); ap.add_argument('--output',required=True,type=Path); ap.add_argument('--config',type=Path); args=ap.parse_args(); main(args.output)
