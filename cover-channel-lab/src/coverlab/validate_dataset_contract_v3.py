from __future__ import annotations

import argparse
import json
from pathlib import Path

from .validate_dataset_contract import validate as validate_v2


def _read(path: Path):
    if not path.exists(): return []
    return [json.loads(x) for x in path.read_text(errors='replace').splitlines() if x.strip()]


def validate(stage_dir: Path) -> dict:
    report=validate_v2(stage_dir); errors=list(report.get('errors',[])); warnings=list(report.get('warnings',[]))
    p=stage_dir/'manifests'/'campaigns.jsonl'
    if not p.exists(): p=stage_dir/'campaigns.jsonl'
    for r in _read(p):
        cid=str(r.get('campaign_id','')); stage=str(r.get('experiment_stage','')); label=int(r.get('label_binary') or 0)
        role=str(r.get('dataset_role',''))
        if stage=='K_benign_diversity' or cid.startswith('k-'):
            if label != 0: errors.append(f'{cid}: Stage K must be benign')
            if role != 'benign_background': errors.append(f'{cid}: Stage K role must be benign_background')
            if r.get('training_eligible') is not True: errors.append(f'{cid}: Stage K must be training eligible')
        if stage=='L_long_timing' or cid.startswith('l-'):
            if int(r.get('timing_acceleration',1)) != 1: errors.append(f'{cid}: Stage L timing must not be accelerated')
            if float(r.get('real_interval_seconds',0)) <= 0: errors.append(f'{cid}: Stage L missing real interval')
            if r.get('training_eligible') is not False: errors.append(f'{cid}: Stage L must be challenge-only')
        if stage=='J_framework_holdout':
            if r.get('training_eligible') is not False or r.get('dataset_role')!='external_framework_holdout':
                errors.append(f'{cid}: framework holdout leaked into training contract')
        if str(r.get('ech_mode','')):
            if r.get('wire_real') is not True: errors.append(f'{cid}: ECH record is not wire-real')
            if r.get('ech_mode')!='shared_frontend_suspicious' and label != 0:
                errors.append(f'{cid}: ECH presence cannot be an attack label')
    report.update({'passed':not errors,'errors':errors[:300],'error_count':len(errors),'warnings':warnings[:300],
                   'warning_count':len(warnings),'contract_revision':3})
    return report


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--stage-dir',required=True); ap.add_argument('--out'); a=ap.parse_args()
    report=validate(Path(a.stage_dir)); text=json.dumps(report,indent=2,sort_keys=True)
    if a.out: Path(a.out).parent.mkdir(parents=True,exist_ok=True); Path(a.out).write_text(text+'\n')
    print(text)
    if not report['passed']: raise SystemExit('dataset ground-truth contract v3 failed')

if __name__=='__main__': main()
