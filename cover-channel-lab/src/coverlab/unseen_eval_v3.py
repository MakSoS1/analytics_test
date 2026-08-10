from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier

from . import train_baseline as _base
from . import train_baseline_v2 as _v2
from .scenarios import BY_ID
from .research_contract_v3 import LEAVE_ONE_FAMILIES
from .train_baseline_v3 import availability_flags_v3

HEADER_CARRIERS = {
    "cookie", "authorization", "user_agent", "referer", "origin", "accept_language",
    "accept_encoding", "if_none_match", "if_modified_since", "range", "content_type_param",
    "x_session_id", "x_request_id", "x_correlation_id", "x_telemetry", "header_order",
    "header_case", "duplicate_headers",
}


def _read_manifests(root: Path) -> pd.DataFrame:
    rows = []
    for p in root.rglob("campaigns.jsonl"):
        try:
            for line in p.read_text(errors="replace").splitlines():
                if line.strip(): rows.append(json.loads(line))
        except Exception: pass
    if not rows: return pd.DataFrame()
    d = pd.DataFrame(rows).drop_duplicates("campaign_id", keep="last")
    d["campaign_id"] = d.campaign_id.astype(str)
    return d


def _group_for_scenario(sid: str) -> set[str]:
    s = BY_ID.get(str(sid)); groups: set[str] = set()
    if not s: return groups
    if s.carrier in HEADER_CARRIERS: groups.add("header")
    if s.family in {"websocket", "tunnel"} or s.transport == "wss": groups.add("wss")
    if s.family == "timing" or s.carrier in {"fixed_beacon","low_jitter","medium_jitter","high_jitter","burst","work_hours","backoff","binary_timing","low_slow","event_driven"}: groups.add("timing")
    if s.family == "http3" or s.transport in {"h3", "quic"}: groups.add("h3")
    if s.family in {"tunnel", "connect", "masque", "webtransport"}: groups.add("tunnel")
    return groups


def annotate(root: Path) -> pd.DataFrame:
    frames = _v2.build_frames(root)
    session = frames["B3-opaque"].copy()
    if session.empty: return session
    manifests = _read_manifests(root)
    scenario_col = next((c for c in ("scenario_id", "scenario", "requested_scenario_id") if c in manifests), None)
    if scenario_col:
        m = manifests[["campaign_id", scenario_col]].copy().rename(columns={scenario_col:"scenario_id"})
        session["campaign_id"] = session.campaign_id.astype(str); session = session.merge(m, on="campaign_id", how="left")
    else:
        session["scenario_id"] = ""
    for family in LEAVE_ONE_FAMILIES:
        session[f"holdout_{family}"] = session.scenario_id.map(lambda sid: int(family in _group_for_scenario(sid)))
    # A compositional cell is an exact combination of multiple technique/transport axes.
    session["composition_key"] = session.apply(lambda r: "+".join(f for f in LEAVE_ONE_FAMILIES if r.get(f"holdout_{f}",0)) or "other", axis=1)
    return session


def _fit_score(train: pd.DataFrame, hold: pd.DataFrame, seed: int) -> dict:
    if train.empty or hold.empty or len(train.label_binary.unique()) < 2:
        return {"status":"insufficient", "train_rows":int(len(train)), "holdout_rows":int(len(hold))}
    xtr, cols = _v2.numeric_matrix(train.drop(columns=[c for c in train.columns if c.startswith("holdout_") or c in {"scenario_id","composition_key"}], errors="ignore"))
    ytr = train.label_binary.astype(int).to_numpy()
    model = LGBMClassifier(n_estimators=250, learning_rate=.05, num_leaves=31, class_weight="balanced", random_state=seed, n_jobs=-1, verbosity=-1)
    model.fit(xtr, ytr)
    xh, _ = _v2.numeric_matrix(hold.drop(columns=[c for c in hold.columns if c.startswith("holdout_") or c in {"scenario_id","composition_key"}], errors="ignore"), cols)
    p = model.predict_proba(xh)[:,1]; y = hold.label_binary.astype(int).to_numpy()
    threshold = .5; m = _base.metrics(y, p, threshold)
    tn, fp, fn, tp = np.asarray(m["confusion_matrix"]).ravel()
    m.update({"status":"ok","train_rows":int(len(train)),"holdout_rows":int(len(hold)),"fpr":float(fp/max(1,fp+tn)),"fp_per_million":float(fp/max(1,fp+tn)*1_000_000)})
    return m


def run(root: Path, seed: int = 23) -> dict:
    df = annotate(root)
    trainbase = df[df.split.isin(["train","validation"])].copy()
    evidence = df[df.split.isin(["test","challenge"])].copy()
    families = {}
    for family in LEAVE_ONE_FAMILIES:
        train = trainbase[trainbase[f"holdout_{family}"].eq(0)].copy()
        hold = evidence[evidence[f"holdout_{family}"].eq(1)].copy()
        families[family] = _fit_score(train, hold, seed)
    # Choose sufficiently populated exact combinations and train while excluding
    # that exact combination. Components are still present individually.
    compositions = {}
    counts = evidence.composition_key.value_counts()
    for key in [k for k,n in counts.items() if k != "other" and "+" in k and n >= 20][:8]:
        train = trainbase[trainbase.composition_key.ne(key)].copy(); hold = evidence[evidence.composition_key.eq(key)].copy()
        compositions[key] = _fit_score(train, hold, seed)
    return {"leave_one_family_out":families,"compositional_holdout":compositions,"policy":"held family/composition removed from training before fit"}


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--dataset-root",required=True); ap.add_argument("--out",required=True); ap.add_argument("--seed",type=int,default=23)
    a=ap.parse_args(); report=run(Path(a.dataset_root),a.seed); p=Path(a.out); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(report,indent=2)); print(json.dumps({"out":str(p),"families":len(report["leave_one_family_out"])}))

if __name__=="__main__": main()
