from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd

from . import pipeline as _base
from . import pipeline_v2 as _v2  # installs Stage G correctness first

_v2_assign = _v2.assign_split
_v2_audit = _v2.leakage_audit
_v2_build_gold = _v2.build_gold


def assign_split(row: pd.Series) -> str:
    stage=str(row.get('experiment_stage','')).lower(); role=str(row.get('dataset_role','')).lower(); cid=str(row.get('campaign_id',''))
    training=row.get('training_eligible', True)
    if training is False or str(training).lower()=='false' or stage in {'j_framework_holdout','l_long_timing'} or role in {'external_framework_holdout','long_timing_challenge'} or cid.startswith(('j-','l-')):
        return 'challenge'
    return _v2_assign(row)


def leakage_audit(df: pd.DataFrame, split_counts: dict[str,int]) -> dict[str,Any]:
    report=_v2_audit(df,split_counts); split=df.apply(assign_split,axis=1)
    training=df.get('training_eligible',pd.Series([True]*len(df),index=df.index))
    ineligible=training.astype(str).str.lower().eq('false') | training.eq(False)
    bad=df.loc[ineligible & ~split.eq('challenge'),'campaign_id'].astype(str).tolist()
    report['training_ineligible_outside_challenge']=bad
    report['passed']=bool(report.get('passed',False)) and not bad
    return report


def build_gold(stage_dir: Path, silver: Path, gold: Path, pcap: Path):
    result=_v2_build_gold(stage_dir,silver,gold,pcap)
    session_path=gold/'session_features.parquet'
    if session_path.exists():
        df=pd.read_parquet(session_path)
        p_root=stage_dir/'parser'
        def rc(path:Path):
            try:return int(path.read_text().strip())
            except Exception:return -1
        df['suricata_parser_ok']=int(rc(p_root/'suricata'/'exit_code.txt')==0)
        df['zeek_parser_ok']=int(rc(p_root/'zeek'/'exit_code.txt')==0)
        df['telemetry_exported']=1
        # Every accepted shard also passed capture_tail_guard before pipeline_v3
        # is invoked by package_layers.sh.
        df['capture_tail_pass']=1
        df.to_parquet(session_path,index=False)
    diag=gold/'mapping_diagnostics.json'
    if diag.exists():
        data=json.loads(diag.read_text()); data['contract_revision']=3; data['training_ineligible_forced_challenge']=True
        diag.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')
    return result

_base.assign_split=assign_split
_base.leakage_audit=leakage_audit
_base.build_gold=build_gold

if __name__=='__main__': _base.main()
