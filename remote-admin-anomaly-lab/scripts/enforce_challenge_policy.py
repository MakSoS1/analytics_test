#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,sys
from pathlib import Path
import pandas as pd

ROOT=Path(__file__).resolve().parents[1]; SRC=ROOT/'src'
if str(SRC) not in sys.path: sys.path.insert(0,str(SRC))
from adminlab.config import load_yaml  # noqa:E402
from adminlab.splits import audit_leakage  # noqa:E402


def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument('--merged',type=Path,required=True); ap.add_argument('--feature-contract',type=Path,default=ROOT/'configs/feature_contract.yaml'); args=ap.parse_args()
    root=args.merged; gold=root/'gold'; quality=root/'quality'
    labels=pd.read_parquet(gold/'labels.parquet'); splits=pd.read_parquet(gold/'splits.parquet'); matrix=pd.read_parquet(gold/'model_matrix.parquet')
    if len(labels)!=len(matrix): raise SystemExit('labels/model_matrix row order contract broken')
    force=labels['session_id'].astype(str).str.startswith('ses-h-')
    if 'semantic_fidelity' in labels:
        force |= labels['semantic_fidelity'].astype(str).eq('partial_winrm')
    forced_ids=set(labels.loc[force,'session_id'].astype(str))
    labels.loc[force,'split']='challenge'; matrix.loc[force.to_numpy(),'split']='challenge'; splits.loc[splits['session_id'].astype(str).isin(forced_ids),'split']='challenge'
    labels.to_parquet(gold/'labels.parquet',index=False); matrix.to_parquet(gold/'model_matrix.parquet',index=False); splits.to_parquet(gold/'splits.parquet',index=False)
    contract=load_yaml(args.feature_contract)
    split_report_path=quality/'global_split_report.json'; split_report=json.loads(split_report_path.read_text()) if split_report_path.is_file() else {}
    session_cols=['session_id','campaign_id','pair_id','src_host_id','dst_host_id']
    sessions=labels[session_cols].copy()
    leakage=audit_leakage(sessions,splits,list(matrix.columns),contract,split_report)
    if not leakage['ok']: raise SystemExit(json.dumps(leakage,sort_keys=True))
    report={'forced_challenge_rows':int(force.sum()),'forced_session_ids_count':len(forced_ids),'partial_winrm_forced':int(labels.get('semantic_fidelity',pd.Series(dtype=str)).astype(str).eq('partial_winrm').sum()),'stage_h_forced':int(labels['session_id'].astype(str).str.startswith('ses-h-').sum()),'split_counts':{str(k):int(v) for k,v in matrix['split'].value_counts().to_dict().items()},'leakage_ok':True}
    quality.mkdir(parents=True,exist_ok=True); (quality/'challenge_policy.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf-8'); (quality/'global_leakage_checks.json').write_text(json.dumps(leakage,indent=2,sort_keys=True)+'\n',encoding='utf-8'); print(json.dumps(report,sort_keys=True)); return 0
if __name__=='__main__': raise SystemExit(main())
