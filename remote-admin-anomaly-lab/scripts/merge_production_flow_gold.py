#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,sys
from pathlib import Path
import pandas as pd
ROOT=Path(__file__).resolve().parents[1];SRC=ROOT/'src'
if str(SRC) not in sys.path:sys.path.insert(0,str(SRC))
from adminlab.config import load_yaml,validate_feature_contract  # noqa:E402
from adminlab.features import select_model_columns  # noqa:E402
from adminlab.splits import assign_grouped_splits,audit_leakage  # noqa:E402

def write(path:Path,payload:dict):path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(payload,indent=2,sort_keys=True)+'\n',encoding='utf-8')

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument('--root',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);ap.add_argument('--feature-contract',type=Path,default=ROOT/'configs/feature_contract.yaml');ap.add_argument('--split-seed',type=int,default=20260814);args=ap.parse_args()
    contract=load_yaml(args.feature_contract);validate_feature_contract(contract)
    feature_files=sorted(args.root.glob('**/gold/*/production_flow_features.parquet'))
    if not feature_files:raise SystemExit('no production flow Gold shards found')
    sessions_parts=[];features_parts=[];labels_parts=[];shards=[]
    for fp in feature_files:
        shard=fp.parent.name;release=fp.parents[2];lp=fp.parent/'production_flow_labels.parquet';sp=release/'bronze'/shard/'manifests/sessions.parquet'
        if not lp.is_file() or not sp.is_file():raise SystemExit(f'incomplete production shard {shard}')
        f=pd.read_parquet(fp);l=pd.read_parquet(lp);s=pd.read_parquet(sp)
        if len(f)!=len(l):raise SystemExit(f'feature/label row mismatch {shard}')
        f=f.copy();l=l.copy();f['global_flow_id']=shard+':'+f['flow_uid'].astype(str);l['global_flow_id']=shard+':'+l['flow_uid'].astype(str)
        features_parts.append(f);labels_parts.append(l);sessions_parts.append(s);shards.append(shard)
    sessions=pd.concat(sessions_parts,ignore_index=True)
    if sessions['session_id'].duplicated().any():raise SystemExit('duplicate behavioral session ids globally')
    features=pd.concat(features_parts,ignore_index=True);labels=pd.concat(labels_parts,ignore_index=True)
    if features['global_flow_id'].duplicated().any() or labels['global_flow_id'].duplicated().any():raise SystemExit('duplicate global flow ids')
    joined=features.merge(labels,on=['global_flow_id','flow_uid','session_id'],how='inner',validate='one_to_one',suffixes=('','_label'))
    coverage=len(joined)/len(features) if len(features) else 0.0
    if coverage<.999:raise SystemExit(f'feature-label flow coverage below .999: {coverage}')
    splits,split_report=assign_grouped_splits(sessions,seed=args.split_seed)
    force_sessions=set(sessions.loc[sessions['session_id'].astype(str).str.startswith('ses-h-'),'session_id'].astype(str))
    force_sessions|=set(labels.loc[labels.get('semantic_fidelity',pd.Series(index=labels.index,dtype=str)).astype(str).eq('partial_winrm'),'session_id'].astype(str))
    group_map=splits.set_index('session_id')['group_id'];forced_groups=set(group_map.reindex(list(force_sessions)).dropna().astype(str));splits.loc[splits['group_id'].astype(str).isin(forced_groups),'split']='challenge'
    split_map=splits.set_index('session_id')['split'];joined['split']=joined['session_id'].map(split_map)
    if joined['split'].isna().any():raise SystemExit('global flow split missing')
    selected=select_model_columns(joined,contract);matrix=selected.copy();matrix['label_binary']=joined['label_binary'].astype(int).to_numpy();matrix['split']=joined['split'].astype(str).to_numpy()
    leakage=audit_leakage(sessions,splits,list(matrix.columns),contract,split_report)
    if not leakage['ok']:raise SystemExit(json.dumps(leakage,sort_keys=True))
    if not forced_groups:raise SystemExit('Stage H/partial challenge policy matched zero groups')
    out=args.out;gold=out/'gold';quality=out/'quality';gold.mkdir(parents=True,exist_ok=True);quality.mkdir(parents=True,exist_ok=True)
    joined.to_parquet(gold/'production_flow_features_and_labels.parquet',index=False);splits.to_parquet(gold/'behavioral_session_splits.parquet',index=False);matrix.to_parquet(gold/'production_model_matrix.parquet',index=False)
    report={'shards':shards,'shard_count':len(shards),'behavioral_sessions':len(sessions),'production_flows':len(matrix),'flow_join_coverage':coverage,'feature_count':len(selected.columns),'forced_challenge_sessions':len(force_sessions),'forced_challenge_groups':len(forced_groups),'split_counts':{str(k):int(v) for k,v in matrix['split'].value_counts().to_dict().items()},'leakage_ok':True,'production_unit':'parser_flow'}
    write(quality/'production_merge.json',report);write(quality/'production_leakage.json',leakage);print(json.dumps(report,sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
