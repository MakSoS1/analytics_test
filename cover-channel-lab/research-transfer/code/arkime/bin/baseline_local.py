"""Original office extraction, with local Parquet only. Never calls publish."""
import json,os,subprocess,sys
from pathlib import Path
R=Path(__file__).resolve().parents[1];OFFICE=R.parent

def command(log,*args):
 with log.open('ab') as f:subprocess.run([sys.executable,*map(str,args)],stdout=f,stderr=f,check=True)

def process(pcaps,out,interval=2):
 sys.path.insert(0,str(OFFICE));from export_full_packets import export_with_payload
 out.mkdir(parents=True,exist_ok=False);rows=out/'rows';rows.mkdir();salt=out/'packet-salt';salt.write_bytes(os.urandom(32));salt.chmod(0o600)
 journal=out/'consumed.jsonl';log=out/'steps.log'
 with journal.open('w') as jf:
  for p in pcaps:
   p=Path(p)
   with (rows/(p.stem+'.pkts')).open('wb') as f,(rows/(p.stem+'.pay')).open('wb') as pay:
    stats=export_with_payload(p,f,pay,salt.read_bytes().strip())
    for h in [f,pay]:h.flush();os.fsync(h.fileno())
   if stats.get('truncated',0):raise RuntimeError('baseline truncated input; retain pcap')
   jf.write(json.dumps(dict(pcap=p.name,status='ok',pcap_bytes=p.stat().st_size,**stats))+'\n')
  jf.flush();os.fsync(jf.fileno())
 command(log,OFFICE/'extract_office_sessions.py','--pcap-dir',rows,'--glob','*.pkts','--min-packets','1','--finalize','--out-sessions',out/'_sessions_raw.csv','--out-lots-conns',out/'_lots_raw.csv','--session-index',out/'session_index.csv','--stats-json',out/'sessions.stats.json')
 (out/'live.csv').write_text('ip_a,port_a,ip_b,port_b,proto,seg_start\n')
 command(log,OFFICE/'merge_payload_sidecars.py','--sidecar-dir',rows,'--interval-seconds',interval,'--session-index',out/'session_index.csv','--out-csv',out/'_payload.csv','--stats-json',out/'payload.stats.json','--live',out/'live.csv','--pending-out',out/'pending_records.pkl')
 command(log,OFFICE/'finalize_tables.py','--sessions',out/'_sessions_raw.csv','--payload',out/'_payload.csv','--lots-conns-in',out/'_lots_raw.csv','--out-sessions',out/'office_sessions.csv','--out-lots-conns',out/'office_lots_conns.csv','--stats-json',out/'join.stats.json')
 command(log,OFFICE/'host_minutes.py','--rows-dir',rows,'--out-csv',out/'office_host_minutes.csv')
 command(log,OFFICE/'office_to_parquet.py','--batch-dir',out,'--out-dir',out/'parquet','--run-id',out.name,'--journal',journal,'--rotate-seconds',interval)
 import pyarrow.parquet as pq
 manifest=json.loads((out/'parquet/manifest.json').read_text())
 stats=json.loads((out/'sessions.stats.json').read_text())
 return dict(rows=int(stats['rows_written']),packets=int(stats['packets']),manifest=manifest)
