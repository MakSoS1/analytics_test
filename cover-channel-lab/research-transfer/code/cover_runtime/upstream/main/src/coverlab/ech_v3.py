from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import defaultdict
from pathlib import Path

from .research_contract_v3 import ECH_MODES, validate_ech_record


def curl_ech_capability()->dict:
    cp=subprocess.run(['curl','--version'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=False);help_cp=subprocess.run(['curl','--help','all'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=False)
    return {'curl_version':cp.stdout.splitlines()[0] if cp.stdout else '','ech_option':'--ech' in help_cp.stdout,'version_rc':cp.returncode}


def sha256(path:Path)->str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def _model_metrics(rows:list[dict])->dict:
    scored=[r for r in rows if r.get('model_score') is not None and r.get('label_binary') in (0,1)]
    if not scored:return {'ready':False,'reason':'model_score/label_binary not present on ECH evidence'}
    thresholds=[float(r.get('decision_threshold',.5)) for r in scored];threshold=thresholds[0]
    def cell(label:int):
        subset=[r for r in scored if int(r.get('label_binary'))==label];alerts=sum(float(r['model_score'])>=float(r.get('decision_threshold',threshold)) for r in subset)
        if label==1:return {'rows':len(subset),'positives':len(subset),'recall':alerts/max(1,len(subset)),'fpr':0.0,'precision':1.0 if alerts else 0.0}
        return {'rows':len(subset),'positives':0,'recall':0.0,'fpr':alerts/max(1,len(subset)),'precision':0.0,'false_alerts':alerts}
    pairs=defaultdict(dict)
    for r in scored:
        pair=str(r.get('pair_id',''))
        enabled=r.get('ech_enabled')
        if pair and enabled in (True,False):pairs[pair][bool(enabled)]=float(r['model_score'])
    deltas=[abs(v[True]-v[False]) for v in pairs.values() if True in v and False in v]
    benign=cell(0);suspicious=cell(1)
    return {'ready':bool(benign['rows'] and suspicious['rows']),'threshold':threshold,'benign':benign,'suspicious':suspicious,'paired_on_off_pairs':len(deltas),'paired_on_off_mean_abs_delta':sum(deltas)/len(deltas) if deltas else 999.0,'max_allowed_pair_delta':.10}


def validate_ech_import(root:Path)->dict:
    manifest=root/'ech_holdout.jsonl'
    if not manifest.exists():return {'available':False,'validated':False,'reason':'ech_holdout.jsonl missing','records':0,'model_evaluation_ready':False}
    rows=[json.loads(x) for x in manifest.read_text().splitlines() if x.strip()];errors=[]
    for i,r in enumerate(rows):
        errors += [f'row {i}: {e}' for e in validate_ech_record(r)]
        p=root/str(r.get('pcap_file',''))
        if not p.is_file():errors.append(f'row {i}: pcap missing')
        elif sha256(p)!=r.get('pcap_sha256'):errors.append(f'row {i}: pcap sha mismatch')
    modes={r.get('ech_mode') for r in rows};required={'grease','accepted_h2','accepted_h3','rejected','shared_frontend_benign','shared_frontend_suspicious'};missing=sorted(required-modes)
    if missing:errors.append('missing ECH modes: '+','.join(missing))
    metrics=_model_metrics(rows)
    return {'available':bool(rows),'validated':not errors,'records':len(rows),'modes':sorted(m for m in modes if m in ECH_MODES),'errors':errors,'model_evaluation_ready':bool(metrics.get('ready')),'model_metrics':metrics}


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--import-root');ap.add_argument('--out',required=True);a=ap.parse_args();report={'local_capability':curl_ech_capability()}
    if a.import_root:report['external_wire_real']=validate_ech_import(Path(a.import_root))
    p=Path(a.out);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
