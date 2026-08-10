from __future__ import annotations

import argparse,hashlib,json
from collections import defaultdict
from pathlib import Path

REQUIRED={1200:5,3600:4}


def sha256(p:Path)->str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for c in iter(lambda:f.read(1024*1024),b''):h.update(c)
    return h.hexdigest()


def validate(root:Path)->dict:
    m=root/'long_timing_evidence.jsonl'
    if not m.exists():return {'validated':False,'records':0,'reason':'long_timing_evidence.jsonl missing','required_intervals_seconds':sorted(REQUIRED)}
    rows=[json.loads(x) for x in m.read_text().splitlines() if x.strip()];errors=[];by=defaultdict(list)
    for i,r in enumerate(rows):
        try:interval=int(r.get('real_interval_seconds',0));events=int(r.get('event_count',r.get('event_count_target',0)) or 0)
        except Exception:errors.append(f'row {i}: invalid timing fields');continue
        if interval not in REQUIRED:errors.append(f'row {i}: unexpected interval {interval}')
        if int(r.get('timing_acceleration',1) or 1)!=1:errors.append(f'row {i}: accelerated timing forbidden')
        if r.get('wire_real') is not True or r.get('isolated_lab') is not True:errors.append(f'row {i}: wire_real isolated_lab required')
        if interval in REQUIRED and events<REQUIRED[interval]:errors.append(f'row {i}: interval {interval} requires >= {REQUIRED[interval]} events')
        rel=str(r.get('pcap_file',''));p=root/rel
        if not rel or not p.is_file():errors.append(f'row {i}: pcap missing')
        elif sha256(p)!=r.get('pcap_sha256'):errors.append(f'row {i}: pcap sha mismatch')
        by[interval].append(r)
    coverage={}
    for interval,min_events in REQUIRED.items():
        rr=by.get(interval,[]);labels={int(x.get('label_binary',-1)) for x in rr};coverage[str(interval)]={'campaigns':len(rr),'labels':sorted(labels),'min_events':min((int(x.get('event_count',x.get('event_count_target',0)) or 0) for x in rr),default=0),'ready':len(rr)>=2 and {0,1}.issubset(labels)}
    ready=all(v['ready'] for v in coverage.values())
    return {'validated':bool(rows) and not errors and ready,'records':len(rows),'errors':errors,'coverage':coverage,'required_intervals_seconds':sorted(REQUIRED),'dataset_role':'external_long_timing_challenge','training_eligible':False}


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',required=True);ap.add_argument('--out',required=True);a=ap.parse_args();r=validate(Path(a.root));p=Path(a.out);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');print(json.dumps(r,sort_keys=True))

if __name__=='__main__':main()
