from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch

from .sequence_fusion_v3 import TinyTCN, build_sequence_arrays, expert_probability_table, _metrics
from .train_baseline_v3 import availability_flags_v3
from . import train_baseline as _base


def sequence_scores(dataset_root: Path, models: Path) -> tuple[dict[str,float], dict]:
    bundle=torch.load(models/'B2-sequence.pt',map_location='cpu',weights_only=False)
    model=TinyTCN(); model.load_state_dict(bundle['state_dict']); model.eval()
    tx=_base.load_parquets(dataset_root,'transaction_features.parquet')
    session=_base.load_parquets(dataset_root,'session_features.parquet').drop_duplicates('campaign_id',keep='last')
    if session.empty: return {}, {'rows':0}
    session=availability_flags_v3(session); ids=session.campaign_id.astype(str).tolist()
    x,m,y,kept=build_sequence_arrays(tx,session,ids)
    if len(y)==0: return {}, {'rows':0}
    with torch.no_grad(): raw=torch.sigmoid(model(torch.tensor(x),torch.tensor(m))).numpy()
    cal=bundle.get('calibrator'); p=cal.predict(raw) if cal is not None else raw
    threshold=float(bundle.get('threshold',.5)); report=_metrics(y,p,threshold)
    return {cid:float(prob) for cid,prob in zip(kept,p)}, report


def fusion_score(dataset_root: Path, models: Path, seq: dict[str,float]) -> dict:
    table=expert_probability_table(dataset_root,models,seq)
    if table.empty: return {'rows':0}
    bundle=joblib.load(models/'fusion-router.joblib')
    cols=bundle['features']; medians=bundle['medians']
    x=table.reindex(columns=cols).apply(pd.to_numeric,errors='coerce')
    for c in cols: x[c]=x[c].fillna(medians.get(c,0.0))
    p=bundle['model'].predict_proba(x)[:,1]
    y=table.label_binary.astype(int).to_numpy()
    return _metrics(y,p,float(bundle.get('threshold',.5)))


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--dataset-root',required=True); ap.add_argument('--models',required=True); ap.add_argument('--out',required=True)
    a=ap.parse_args(); root=Path(a.dataset_root); models=Path(a.models)
    seq,seq_report=sequence_scores(root,models); fusion_report=fusion_score(root,models,seq)
    report={'policy_revision':3,'dataset_role':'D_mixed_frozen_evaluation','B2-sequence':seq_report,'fusion-router':fusion_report}
    p=Path(a.out); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n'); print(json.dumps(report,sort_keys=True))

if __name__=='__main__': main()
