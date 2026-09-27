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
    has_table=lambda name: con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone() is not None
    # 'service' assets are live web services (carriers for live-service findings),
    # not downloaded files, so they are excluded from the asset counts here.
    total=scalar("SELECT COUNT(*) FROM assets WHERE asset_type!='service'"); javascript=scalar("SELECT COUNT(*) FROM assets WHERE asset_type='javascript'")
    endpoints=scalar('SELECT COUNT(*) FROM endpoints'); technologies=scalar('SELECT COUNT(DISTINCT name) FROM technologies'); findings=scalar('SELECT COUNT(*) FROM findings')
    # Findings include structural/inventory rows (e.g. call_graph, class) recorded
    # at 'info' severity. Those are code-structure metadata, not security issues,
    # so report them separately instead of labelling the raw total "security".
    by_severity={r['severity']:r['count'] for r in con.execute('SELECT severity,COUNT(*) count FROM findings GROUP BY severity')}
    security_findings=sum(c for sev,c in by_severity.items() if sev!='info')
    fuzz_probed=fuzz_hits=0
    if has_table('fuzz_results'):
        fuzz_probed=scalar('SELECT COUNT(*) FROM fuzz_results'); fuzz_hits=scalar('SELECT COUNT(*) FROM fuzz_results WHERE interesting=1')
    by_type={r['asset_type']:r['count'] for r in con.execute('SELECT asset_type,COUNT(*) count FROM assets GROUP BY asset_type')}
    # Web services discovered by the port scanner (reports/ports.json). Read from
    # file rather than the DB so the section appears even when ingest skipped it.
    web_services=[]
    ports_file=reports/'ports.json'
    if ports_file.is_file():
        try:
            data=json.loads(ports_file.read_text(encoding='utf-8'))
            web_services=[s for s in data if isinstance(s,dict)] if isinstance(data,list) else []
        except (OSError,json.JSONDecodeError):
            web_services=[]
    # Exclude CDN port-mirrors (same site echoed across a host's alternate ports)
    # from the headline counts; they are annotated in ports.json for transparency.
    distinct_services=[s for s in web_services if not s.get('mirror_of') and s.get('status')!=400]
    services_total=len(distinct_services)
    services_alt=sum(1 for s in distinct_services if s.get('port') not in (80,443))
    services_mirrors=len(web_services)-len(distinct_services)
    # Screenshots (reports/screenshots.json), when the webshot stage ran.
    shots=[]
    shots_file=reports/'screenshots.json'
    if shots_file.is_file():
        try:
            data=json.loads(shots_file.read_text(encoding='utf-8'))
            shots=[s for s in data if isinstance(s,dict)] if isinstance(data,list) else []
        except (OSError,json.JSONDecodeError):
            shots=[]
    shots_captured=sum(1 for s in shots if s.get('file'))
    shots_clusters=len({s.get('cluster') for s in shots if s.get('file')})
    summary={'total_assets':total,'javascript_count':javascript,'endpoint_count':endpoints,'technology_count':technologies,'finding_count':findings,'security_finding_count':security_findings,'findings_by_severity':by_severity,'fuzz_probed':fuzz_probed,'fuzz_interesting':fuzz_hits,'web_services':services_total,'web_services_nonstandard_port':services_alt,'screenshots':shots_captured,'screenshot_clusters':shots_clusters,'file_statistics':by_type}
    (reports/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    sev_order=['critical','high','medium','low','info']
    sev_line=', '.join(f'{sev} {by_severity[sev]}' for sev in sev_order if sev in by_severity) or 'none'
    lines=['# JSIntel Phase 1 Summary','',f'- Total assets: {total}',f'- JavaScript assets: {javascript}',f'- Endpoints: {endpoints}',f'- Technologies: {technologies}',f'- Security findings (low+): {security_findings}',f'- All findings: {findings} ({sev_line})',f'- Fuzz probes: {fuzz_probed} ({fuzz_hits} interesting)',f'- Web services: {services_total} ({services_alt} on non-standard ports)']
    if shots_captured: lines.append(f'- Screenshots: {shots_captured} ({shots_clusters} distinct visual clusters) — see reports/screenshots.html')
    lines += ['', '## File statistics','']
    lines += [f'- {name}: {count}' for name,count in sorted(by_type.items())]
    if distinct_services:
        heading='## Web services (port scan)'
        if services_mirrors:
            heading+=f' — {services_mirrors} CDN port-mirror(s) collapsed'
        lines += ['',heading,'']
        for s in sorted(distinct_services,key=lambda r:(r.get('host',''),r.get('port',0))):
            title=(' — '+s['title']) if s.get('title') else ''
            server=(f" [{s['server']}]") if s.get('server') else ''
            lines.append(f"- {s.get('url','')} ({s.get('status','?')}){server}{title}")
    (reports/'summary.md').write_text('\n'.join(lines)+'\n')
    cols=['url','local_path','asset_type','sha256','size_bytes','mime_type','status','discovered_at']
    with (reports/'assets.csv').open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=cols); writer.writeheader(); writer.writerows(map(dict,con.execute('SELECT '+','.join(cols)+' FROM assets ORDER BY id')))
    con.close()
if __name__=='__main__':
    ap=argparse.ArgumentParser(); ap.add_argument('--output',required=True,type=Path); ap.add_argument('--config',type=Path); args=ap.parse_args(); main(args.output)
