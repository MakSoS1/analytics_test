#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import pandas as pd

ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/'src'
if str(SRC) not in sys.path: sys.path.insert(0,str(SRC))

from adminlab.config import load_yaml,validate_feature_contract  # noqa:E402
from adminlab.features import select_model_columns  # noqa:E402
from adminlab.splits import assign_grouped_splits,audit_leakage  # noqa:E402


def write_json(path:Path,payload:dict)->None:
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(payload,indent=2,sort_keys=True)+'\n',encoding='utf-8')


def sha256(path:Path)->str:
    h=hashlib.sha256()
    with path.open('rb') as fh:
        for chunk in iter(lambda:fh.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()


def collect(root:Path)->list[tuple[str,Path]]:
    items=[]
    for flow in root.glob('**/gold/*/flow_features.parquet'):
        shard=flow.parent.name
        items.append((shard,flow.parent))
    unique={str(path.resolve()):(shard,path) for shard,path in items}
    return sorted(unique.values(),key=lambda item:(item[0],str(item[1])))


def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--root',type=Path,required=True)
    ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--feature-contract',type=Path,default=ROOT/'configs/feature_contract.yaml')
    ap.add_argument('--split-seed',type=int,default=20260814)
    args=ap.parse_args()
    shards=collect(args.root.resolve())
    if not shards: raise SystemExit('no Gold shards found')
    contract=load_yaml(args.feature_contract); validate_feature_contract(contract)

    sessions_all=[]; flows=[]; windows=[]; graphs=[]
    seen_release_shard=set()
    shard_report=[]
    for shard,gold in shards:
        release=gold.parents[1]
        key=(str(release.resolve()),shard)
        if key in seen_release_shard: continue
        seen_release_shard.add(key)
        sessions_path=release/'bronze'/shard/'manifests/sessions.parquet'
        for required in (gold/'flow_features.parquet',gold/'window_features.parquet',gold/'graph_features.parquet',sessions_path):
            if not required.is_file(): raise SystemExit(f'incomplete shard {shard}: {required}')
        s=pd.read_parquet(sessions_path); f=pd.read_parquet(gold/'flow_features.parquet')
        w=pd.read_parquet(gold/'window_features.parquet'); g=pd.read_parquet(gold/'graph_features.parquet')
        sessions_all.append(s); flows.append(f); windows.append(w); graphs.append(g)
        shard_report.append({'shard':shard,'sessions':len(s),'flow_rows':len(f),'release':str(release)})

    sessions=pd.concat(sessions_all,ignore_index=True)
    flow=pd.concat(flows,ignore_index=True); window=pd.concat(windows,ignore_index=True); graph=pd.concat(graphs,ignore_index=True)
    if sessions['session_id'].duplicated().any():
        dup=sessions.loc[sessions['session_id'].duplicated(),'session_id'].astype(str).head(20).tolist()
        raise SystemExit(f'duplicate session IDs across shards: {dup}')
    for name,frame in [('flow',flow),('window',window),('graph',graph)]:
        if frame['session_id'].duplicated().any(): raise SystemExit(f'duplicate {name} session rows')

    combined=flow.merge(window,on='session_id',how='inner',validate='one_to_one').merge(graph,on='session_id',how='inner',validate='one_to_one')
    coverage=len(combined)/len(sessions) if len(sessions) else 0.0
    if coverage<.95: raise SystemExit(f'global feature/session coverage below .95: {coverage:.6f}')

    splits,split_report=assign_grouped_splits(sessions,seed=args.split_seed)
    label_cols=['session_id','campaign_id','scenario_id','pair_id','label_binary','label_family','mitre_technique','protocol','src_role','dst_role','src_host_id','dst_host_id','netem_profile','wire_fidelity','semantic_fidelity','start_ts','end_ts','status']
    labels=sessions[[c for c in label_cols if c in sessions]].merge(splits,on='session_id',how='left',validate='one_to_one')
    aligned=labels.set_index('session_id').reindex(combined['session_id']).reset_index()
    model_features=select_model_columns(combined,contract)
    matrix=model_features.copy(); matrix['label_binary']=aligned['label_binary'].astype(int).to_numpy(); matrix['split']=aligned['split'].astype(str).to_numpy()
    leakage=audit_leakage(sessions,splits,list(matrix.columns),contract,split_report)
    if not leakage['ok']: raise SystemExit(json.dumps(leakage,sort_keys=True))

    gold=args.out/'gold'; quality=args.out/'quality'; gold.mkdir(parents=True,exist_ok=True); quality.mkdir(parents=True,exist_ok=True)
    flow.to_parquet(gold/'flow_features.parquet',index=False); window.to_parquet(gold/'window_features.parquet',index=False); graph.to_parquet(gold/'graph_features.parquet',index=False)
    splits.to_parquet(gold/'splits.parquet',index=False); aligned.to_parquet(gold/'labels.parquet',index=False); matrix.to_parquet(gold/'model_matrix.parquet',index=False)
    contract_payload={'feature_contract_version':int(contract['feature_contract_version']),'feature_contract_sha256':sha256(args.feature_contract),'available_model_features':list(model_features.columns),'forbidden':list(contract.get('forbidden',[]))}
    write_json(gold/'feature_contract.json',contract_payload)
    write_json(quality/'global_split_report.json',split_report); write_json(quality/'global_leakage_checks.json',leakage)
    summary={'shards':shard_report,'shard_count':len(shard_report),'session_count':len(sessions),'feature_rows':len(combined),'coverage':coverage,'model_rows':len(matrix),'model_features':len(model_features.columns),'split_counts':split_report['split_counts'],'leakage_ok':True}
    write_json(quality/'merge_summary.json',summary)
    print(json.dumps(summary,sort_keys=True))
    return 0

if __name__=='__main__': raise SystemExit(main())
