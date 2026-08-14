#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,sys
from pathlib import Path
import pandas as pd
ROOT=Path(__file__).resolve().parents[1];SRC=ROOT/'src'
if str(SRC) not in sys.path:sys.path.insert(0,str(SRC))
from adminlab.config import load_yaml,validate_feature_contract
from adminlab.features import map_zeek_flows_to_sessions,read_zstd_json_lines,select_model_columns
from adminlab.flow_gold import build_split_isolated_production_flow_features
from adminlab.splits import assign_grouped_splits,audit_leakage

def write(path:Path,payload:dict):path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(payload,indent=2,sort_keys=True)+'\n',encoding='utf-8')
def attach_behavior_time(mapped:pd.DataFrame,sessions:pd.DataFrame)->pd.DataFrame:
    needed={'session_id','start_ts','execution_start_ts'}
    if not needed<=set(sessions.columns):raise SystemExit(f'dual-time manifest missing: {sorted(needed-set(sessions.columns))}')
    times=sessions[['session_id','start_ts','execution_start_ts']].copy();times['_sim_start']=pd.to_datetime(times['start_ts'],utc=True).astype('int64')/1e9;times['_exec_start']=pd.to_datetime(times['execution_start_ts'],utc=True).astype('int64')/1e9
    out=mapped.merge(times[['session_id','_sim_start','_exec_start']],on='session_id',how='left',validate='many_to_one')
    if out[['_sim_start','_exec_start']].isna().any().any():raise SystemExit('cannot map parser flow to simulated behavior clock')
    out['execution_ts']=pd.to_numeric(out['ts'],errors='coerce');out['behavior_ts']=out['_sim_start']+(out['execution_ts']-out['_exec_start']).clip(lower=0);return out.drop(columns=['_sim_start','_exec_start'])
def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument('--release',type=Path,required=True);ap.add_argument('--shard',required=True);ap.add_argument('--feature-contract',type=Path,default=ROOT/'configs/feature_contract.yaml');ap.add_argument('--split-seed',type=int,default=20260814);args=ap.parse_args();release=args.release.resolve();bronze=release/'bronze'/args.shard;silver=release/'silver'/args.shard;gold=release/'gold'/args.shard;quality=release/'quality'/args.shard;contract=load_yaml(args.feature_contract);validate_feature_contract(contract);sessions=pd.read_parquet(bronze/'manifests/sessions.parquet');conn=read_zstd_json_lines(silver/'zeek/conn.log.zst');mapped,report=map_zeek_flows_to_sessions(sessions,conn);write(quality/'production_flow_mapping.json',report)
    if report['session_mapping_coverage']<.95 or report['conn_mapping_coverage']<.90:raise SystemExit(f'flow mapping gate failed: {report}')
    if 'uid' not in mapped.columns or mapped['uid'].isna().any():raise SystemExit('Zeek UID required for production flow label alignment')
    mapped=attach_behavior_time(mapped,sessions);splits,split_report=assign_grouped_splits(sessions,seed=args.split_seed);split_index=splits.set_index('session_id');split_map=split_index['split'];reason_map=split_index['challenge_reason'];mapped['split']=mapped['session_id'].map(split_map)
    if mapped['split'].isna().any():raise SystemExit('mapped flow missing split before state computation')
    features=build_split_isolated_production_flow_features(mapped);label_cols=['session_id','campaign_id','scenario_id','pair_id','label_binary','label_family','protocol','semantic_fidelity','src_host_id','dst_host_id','persona_id','task_id','campaign_type','historical_relation'];label_source=mapped[['uid','session_id']].rename(columns={'uid':'flow_uid'}).merge(sessions[[c for c in label_cols if c in sessions]],on='session_id',how='left',validate='many_to_one');label_source['split']=label_source['session_id'].map(split_map);label_source['challenge_reason']=label_source['session_id'].map(reason_map);aligned=features[['flow_uid','session_id']].merge(label_source,on=['flow_uid','session_id'],how='left',validate='one_to_one')
    if len(aligned)!=len(features) or aligned[['label_binary','split']].isna().any().any():raise SystemExit('UID-based flow label alignment incomplete')
    selected=select_model_columns(features,contract);matrix=selected.copy();matrix['label_binary']=aligned['label_binary'].astype(int).to_numpy();matrix['split']=aligned['split'].astype(str).to_numpy();leakage=audit_leakage(sessions,splits,list(matrix.columns),contract,split_report)
    if not leakage['ok']:raise SystemExit(json.dumps(leakage,sort_keys=True))
    gold.mkdir(parents=True,exist_ok=True);quality.mkdir(parents=True,exist_ok=True);features.to_parquet(gold/'production_flow_features.parquet',index=False);aligned.to_parquet(gold/'production_flow_labels.parquet',index=False);matrix.to_parquet(gold/'production_model_matrix.parquet',index=False);summary={'rows':len(matrix),'feature_count':len(selected.columns),'session_mapping_coverage':report['session_mapping_coverage'],'conn_mapping_coverage':report['conn_mapping_coverage'],'uid_alignment_coverage':len(aligned)/len(features),'leakage_ok':True,'state_partition_policy':'fresh_state_per_split','time_policy':'PCAP execution_ts mapped to simulated behavior_ts','production_unit':'parser_flow','label_join_keys':['flow_uid','session_id'],'challenge_reason_counts':split_report.get('challenge_reason_counts',{}),'orchestrator_used_only_for':'labels_grouped_splits_and_simulated_time_mapping'};write(quality/'production_flow_gold.json',summary);print(json.dumps(summary,sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
