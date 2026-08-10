from __future__ import annotations

import argparse
import json
from pathlib import Path

from .research_contract_v3 import LONG_TIMING_SECONDS, NETEM_PROFILES


def _rows(root: Path):
    seen=set()
    for p in root.rglob('campaigns.jsonl'):
        try:
            for line in p.read_text(errors='replace').splitlines():
                if not line.strip(): continue
                r=json.loads(line); cid=str(r.get('campaign_id',''))
                key=(cid,str(r.get('experiment_stage','')),str(r.get('configuration_id','')))
                if key in seen: continue
                seen.add(key); yield r
        except Exception:
            continue


def scan(root: Path, min_benign: int = 60000) -> dict:
    rows=list(_rows(root))
    benign=[r for r in rows if r.get('experiment_stage')=='K_benign_diversity' or str(r.get('campaign_id','')).startswith('k-')]
    long=[r for r in rows if r.get('experiment_stage')=='L_long_timing' or str(r.get('campaign_id','')).startswith('l-')]
    intervals={int(float(r.get('real_interval_seconds',0))) for r in long if float(r.get('real_interval_seconds',0) or 0)>0}
    accelerated=[str(r.get('campaign_id','')) for r in long if int(r.get('timing_acceleration',1) or 1)!=1]
    netem={str(r.get('netem_profile','')) for r in benign if r.get('netem_profile')}
    required_netem={p.name for p in NETEM_PROFILES}
    actual_clients={str(r.get('client_impl','')) for r in benign if r.get('client_impl')}
    services={str(r.get('benign_service_profile','')) for r in benign if r.get('benign_service_profile')}
    return {
        'policy_revision':3,
        'benign_campaigns':len(benign),
        'benign_corpus_minimum':min_benign,
        'benign_corpus_ready':len(benign)>=min_benign,
        'benign_service_profiles':sorted(services),
        'actual_linux_client_stacks':sorted(actual_clients),
        'long_timing_campaigns':len(long),
        'long_timing_intervals_seconds':sorted(intervals),
        'long_timing_accelerated_campaigns':accelerated,
        'long_timing_ready':set(LONG_TIMING_SECONDS).issubset(intervals) and not accelerated,
        'kernel_netem_profiles':sorted(netem),
        'kernel_netem_ready':required_netem.issubset(netem),
        'required_kernel_netem_profiles':sorted(required_netem),
        'training_policy':'Stage K eligible; Stage L challenge-only',
    }


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--dataset-root',required=True); ap.add_argument('--out',required=True); ap.add_argument('--min-benign',type=int,default=60000)
    a=ap.parse_args(); report=scan(Path(a.dataset_root),a.min_benign); p=Path(a.out); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n'); print(json.dumps(report,sort_keys=True))

if __name__=='__main__': main()
