#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,sys
from pathlib import Path
import joblib,pandas as pd
ROOT=Path(__file__).resolve().parents[1];SRC=ROOT/'src'
if str(SRC) not in sys.path:sys.path.insert(0,str(SRC))
from adminlab.online_features import EveFeatureState  # noqa:E402

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument('--model',type=Path,required=True);ap.add_argument('--metrics',type=Path,required=True);ap.add_argument('--eve',default='-');ap.add_argument('--emit-all',action='store_true');args=ap.parse_args()
    model=joblib.load(args.model);metrics=json.loads(args.metrics.read_text());threshold=float(metrics['threshold']);columns=list(model.feature_names_in_);state=EveFeatureState();fh=sys.stdin if args.eve=='-' else open(args.eve,encoding='utf-8')
    try:
      for line in fh:
        if not line.strip():continue
        event=json.loads(line)
        if event.get('event_type')!='flow':continue
        row=state.consume_flow(event);features=row['features'];data={c:features.get(c,'unknown' if c=='app_proto' else 0.0) for c in columns};score=float(model.predict_proba(pd.DataFrame([data],columns=columns))[:,1][0]);alert=score>=threshold
        if alert or args.emit_all:
          out={'event_type':'remote_admin_ml','risk_score':score,'threshold':threshold,'alert':alert,'model':'M1-lightgbm','context':row['context']};print(json.dumps(out,sort_keys=True),flush=True)
    finally:
      if fh is not sys.stdin:fh.close()
    return 0
if __name__=='__main__':raise SystemExit(main())
