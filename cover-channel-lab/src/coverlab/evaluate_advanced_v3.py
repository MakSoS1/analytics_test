from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch

from .sequence_fusion_v3 import TinyTCN, OPAQUE_CHANNELS, VISIBLE_CHANNELS, build_sequence_arrays, build_visible_sequence_arrays, expert_probability_table, _metrics
from .train_baseline_v3 import availability_flags_v3
from . import train_baseline as _base


def _score_bundle(table:pd.DataFrame,session:pd.DataFrame,ids:list[str],bundle_path:Path,visible:bool=False):
    bundle=torch.load(bundle_path,map_location='cpu',weights_only=False);channels=tuple(bundle.get('channels',VISIBLE_CHANNELS if visible else OPAQUE_CHANNELS))
    model=TinyTCN(len(channels));model.load_state_dict(bundle['state_dict']);model.eval()
    builder=build_visible_sequence_arrays if visible else build_sequence_arrays
    x,m,y,kept=builder(table,session,ids)
    if len(y)==0:return {},{'rows':0}
    with torch.no_grad():raw=torch.sigmoid(model(torch.tensor(x),torch.tensor(m))).numpy()
    cal=bundle.get('calibrator');p=cal.predict(raw) if cal is not None else raw;threshold=float(bundle.get('threshold',.5))
    return {cid:float(prob) for cid,prob in zip(kept,p)},_metrics(y,p,threshold)


def sequence_scores(dataset_root:Path,models:Path):
    session=_base.load_parquets(dataset_root,'session_features.parquet').drop_duplicates('campaign_id',keep='last')
    if session.empty:return {},{}, {'rows':0},{'rows':0}
    session=availability_flags_v3(session);ids=session.campaign_id.astype(str).tolist()
    packet=_base.load_parquets(dataset_root,'packet_sequence_features.parquet')
    tx=_base.load_parquets(dataset_root,'transaction_features.parquet')
    opaque,opaque_report=_score_bundle(packet,session,ids,models/'B2-opaque-sequence.pt',False)
    encrypted=session.get('availability_encrypted',pd.Series([0]*len(session),index=session.index)).fillna(0).astype(int).eq(1)
    bypass=session.get('availability_inspection_bypassed',pd.Series([0]*len(session),index=session.index)).fillna(0).astype(int).eq(1)
    visible_ids=session.loc[~(encrypted|bypass),'campaign_id'].astype(str).tolist()
    visible,visible_report=_score_bundle(tx,session,visible_ids,models/'B2-visible-sequence.pt',True) if (models/'B2-visible-sequence.pt').exists() else ({},{'rows':0})
    return opaque,visible,opaque_report,visible_report


def fusion_score(dataset_root:Path,models:Path,opaque:dict[str,float],visible:dict[str,float])->dict:
    table=expert_probability_table(dataset_root,models,opaque,visible)
    if table.empty:return {'rows':0}
    bundle=joblib.load(models/'fusion-router.joblib');cols=bundle['features'];medians=bundle['medians']
    x=table.reindex(columns=cols).apply(pd.to_numeric,errors='coerce')
    for c in cols:x[c]=x[c].fillna(medians.get(c,0.0))
    p=bundle['model'].predict_proba(x)[:,1];y=table.label_binary.astype(int).to_numpy()
    return _metrics(y,p,float(bundle.get('threshold',.5)))


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--dataset-root',required=True);ap.add_argument('--models',required=True);ap.add_argument('--out',required=True)
    a=ap.parse_args();root=Path(a.dataset_root);models=Path(a.models)
    opaque,visible,opaque_report,visible_report=sequence_scores(root,models);fusion_report=fusion_score(root,models,opaque,visible)
    report={'policy_revision':4,'dataset_role':'D_mixed_frozen_evaluation','B2-opaque-sequence':opaque_report,'B2-visible-sequence':visible_report,'B2-sequence':opaque_report,'fusion-router':fusion_report,'opaque_plaintext_leakage_guard':True}
    p=Path(a.out);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
