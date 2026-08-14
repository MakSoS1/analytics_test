#!/usr/bin/env python3
from __future__ import annotations

import argparse,json,sys
from pathlib import Path
import numpy as np
import pandas as pd

ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/'src'
if str(SRC) not in sys.path: sys.path.insert(0,str(SRC))
from adminlab.modeling import train_supervised  # noqa:E402

FRACTIONS=(0.10,0.25,0.50,0.75,1.00)


def stratified_train_subset(frame:pd.DataFrame,fraction:float,seed:int)->pd.DataFrame:
    train=frame[frame['split']=='train']
    rest=frame[frame['split']!='train']
    parts=[]
    for label,group in train.groupby('label_binary'):
        n=max(8,int(round(len(group)*fraction)))
        n=min(n,len(group))
        parts.append(group.sample(n=n,random_state=seed+int(label)*101))
    return pd.concat(parts+[rest],ignore_index=True)


def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument('--model-matrix',type=Path,required=True); ap.add_argument('--out',type=Path,required=True); ap.add_argument('--seed',type=int,default=20260814)
    args=ap.parse_args(); frame=pd.read_parquet(args.model_matrix)
    rows=[]
    for idx,fraction in enumerate(FRACTIONS):
        subset=stratified_train_subset(frame,fraction,args.seed+idx)
        _,report=train_supervised(subset,seed=args.seed+idx)
        rows.append({'fraction':fraction,'train_rows':int((subset['split']=='train').sum()),'metrics':report['splits']})
    def metric(row,split,key):
        return row['metrics'].get(split,{}).get(key)
    last=rows[-1]; previous=rows[-2]
    final_pr=metric(last,'challenge','pr_auc') or metric(last,'test','pr_auc') or metric(last,'validation','pr_auc')
    prev_pr=metric(previous,'challenge','pr_auc') or metric(previous,'test','pr_auc') or metric(previous,'validation','pr_auc')
    delta=None if final_pr is None or prev_pr is None else float(final_pr-prev_pr)
    decision={
      'points':rows,
      'final_pr_auc':final_pr,
      'last_step_pr_auc_delta':delta,
      'policy':{
        'expand_if_last_step_delta_gt':0.005,
        'shortcut_audit_if_small_data_pr_auc_gt':0.98,
        'fix_before_scale_if_final_pr_auc_lt':0.80,
      }
    }
    early_pr=metric(rows[1],'challenge','pr_auc') or metric(rows[1],'test','pr_auc') or metric(rows[1],'validation','pr_auc')
    if final_pr is not None and final_pr < .80:
        decision['recommendation']='fix_generator_or_features_before_scale'
    elif early_pr is not None and early_pr > .98:
        decision['recommendation']='shortcut_audit_before_scale'
    elif delta is not None and delta > .005:
        decision['recommendation']='expand_corpus'
    else:
        decision['recommendation']='prefer_diversity_over_duplicate_scale'
    args.out.parent.mkdir(parents=True,exist_ok=True); args.out.write_text(json.dumps(decision,indent=2,sort_keys=True)+'\n',encoding='utf-8'); print(json.dumps(decision,sort_keys=True)); return 0

if __name__=='__main__': raise SystemExit(main())
