from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier

from . import train_baseline as _base
from . import train_baseline_v2 as _v2
from .research_contract_v3 import FRAMEWORKS


def _framework_map(root: Path) -> dict[str,str]:
    out={}
    for p in root.rglob('framework_holdout.jsonl'):
        for line in p.read_text(errors='replace').splitlines():
            if not line.strip(): continue
            r=json.loads(line); out[str(r.get('campaign_id',''))]=str(r.get('framework','')).lower()
    return out


def _metrics(y: np.ndarray,p: np.ndarray,t=.5) -> dict:
    pred=(p>=t).astype(int); tn,fp,fn,tp=np.array(_base.metrics(y,p,t)['confusion_matrix']).ravel()
    return {'rows':int(len(y)),'positives':int(y.sum()),'precision':float(tp/max(1,tp+fp)),'recall':float(tp/max(1,tp+fn)),
            'fpr':float(fp/max(1,fp+tn)),'fp_per_million':float(fp/max(1,fp+tn)*1_000_000),'confusion_matrix':[[int(tn),int(fp)],[int(fn),int(tp)]]}


def run(synthetic_root: Path, framework_root: Path, seed=23) -> dict:
    synth=_v2.build_frames(synthetic_root)['B3-opaque'].copy(); split=_base.split_map(synthetic_root)
    synth=synth.merge(split,on='campaign_id',how='left'); synth=synth[synth.split.eq('train')].copy()
    ext=_base.load_parquets(framework_root,'session_features.parquet').drop_duplicates('campaign_id',keep='last')
    fmap=_framework_map(framework_root); ext['framework']=ext.campaign_id.astype(str).map(fmap)
    ext=ext[ext.framework.isin(FRAMEWORKS)].copy()
    if synth.empty or ext.empty or len(synth.label_binary.unique())<2:
        return {'status':'insufficient','framework_rows':int(len(ext))}
    # Feature schema is derived from synthetic train only so external evidence
    # cannot introduce a framework-specific feature column.
    xs,cols=_v2.numeric_matrix(synth); ys=synth.label_binary.astype(int).to_numpy()
    base=LGBMClassifier(n_estimators=350,learning_rate=.04,num_leaves=31,class_weight='balanced',random_state=seed,n_jobs=-1,verbosity=-1).fit(xs,ys)
    synthetic_only={}
    for fw in FRAMEWORKS:
        hold=ext[ext.framework.eq(fw)]
        if hold.empty: synthetic_only[fw]={'status':'missing'}; continue
        x,_=_v2.numeric_matrix(hold,cols); synthetic_only[fw]={'status':'ok',**_metrics(hold.label_binary.astype(int).to_numpy(),base.predict_proba(x)[:,1])}
    loo={}
    for fw in FRAMEWORKS:
        hold=ext[ext.framework.eq(fw)]; add=ext[ext.framework.ne(fw)]
        if hold.empty or add.empty: loo[fw]={'status':'insufficient'}; continue
        xa,_=_v2.numeric_matrix(add,cols); ya=add.label_binary.astype(int).to_numpy()
        xtrain=np.vstack([xs,xa]); ytrain=np.concatenate([ys,ya])
        model=LGBMClassifier(n_estimators=350,learning_rate=.04,num_leaves=31,class_weight='balanced',random_state=seed,n_jobs=-1,verbosity=-1).fit(xtrain,ytrain)
        xh,_=_v2.numeric_matrix(hold,cols); loo[fw]={'status':'ok',**_metrics(hold.label_binary.astype(int).to_numpy(),model.predict_proba(xh)[:,1])}
    return {'policy_revision':3,'status':'ok','canonical_framework_training_eligible':False,
            'synthetic_only_external_test':synthetic_only,'leave_one_framework_out':loo,
            'note':'LOFO uses temporary experimental copies; canonical framework holdout remains challenge-only.'}


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--synthetic-root',required=True); ap.add_argument('--framework-root',required=True); ap.add_argument('--out',required=True); ap.add_argument('--seed',type=int,default=23)
    a=ap.parse_args(); report=run(Path(a.synthetic_root),Path(a.framework_root),a.seed); p=Path(a.out); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n'); print(json.dumps(report,sort_keys=True))

if __name__=='__main__': main()
