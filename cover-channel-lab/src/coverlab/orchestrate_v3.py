from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from . import orchestrate as _base
from . import orchestrate_v2  # installs label/browser correctness patches on _base
from . import run_campaign as _rc
from .client_runtime_v3 import install as _install_client_runtime
from .research_contract_v3 import BENIGN_SERVICE_PROFILES, CLIENT_STACKS, LONG_TIMING_SECONDS, NETEM_PROFILES, SERVER_STACKS
from .scenarios import SCENARIOS

_install_client_runtime()
_ORIGINAL_SLEEP = _rc.time.sleep
_real_timing_calls = 0


def _sleep_v3(seconds: float):
    global _real_timing_calls
    raw=os.environ.get('COVERLAB_REAL_TIMING_SECONDS')
    if raw and 0.009 <= float(seconds) <= 0.20:
        _real_timing_calls += 1
        gaps=int(os.environ.get('COVERLAB_REAL_TIMING_GAPS','1'))
        return _ORIGINAL_SLEEP(float(raw) if _real_timing_calls <= gaps else 0.001)
    return _ORIGINAL_SLEEP(seconds)

_rc.time.sleep = _sleep_v3

ACTUAL_LINUX_CLIENTS=("python_httpx","python_httpx_h2","python_stdlib","curl_linux","go_nethttp","node_fetch","java_httpclient","rust_reqwest")


def benign_stage(args, manifest: Path, events_out: Path):
    """Stage K: 60k independent benign sessions by default, real wire traffic."""
    total=args.sessions or int(os.environ.get('COVERLAB_BENIGN_SESSIONS','60000'))
    candidates=[s for s in SCENARIOS if s.family not in {'lots'}]
    for i in range(total):
        if i % args.shards != args.shard: continue
        persona,ip=_base.PERSONAS[i % len(_base.PERSONAS)]
        s=candidates[(i*37 + args.shard*11) % len(candidates)]
        service=BENIGN_SERVICE_PROFILES[i % len(BENIGN_SERVICE_PROFILES)]
        planned_stack=CLIENT_STACKS[(i//3) % len(CLIENT_STACKS)]
        actual_client=ACTUAL_LINUX_CLIENTS[(i//7) % len(ACTUAL_LINUX_CLIENTS)]
        config={
            'experiment_stage':'K_benign_diversity','dataset_role':'benign_background',
            'configuration_id':f'K-{i:06d}','benign_service_profile':service,
            'planned_client_stack':planned_stack,'client_impl':actual_client,
            'planned_server_stack':SERVER_STACKS[(i//13)%len(SERVER_STACKS)],
            'actual_server_stack':'hypercorn_or_protocol_fixture',
            'netem_profile':NETEM_PROFILES[(i//17)%len(NETEM_PROFILES)].name,
            'training_eligible':True,'transform_chain':['benign_native'],
            'timing_profile':'native_request','payload_size_class':_base.SIZES[i%len(_base.SIZES)],
        }
        _base.invoke(s.scenario_id,False,args.seed+90_000_000+i,f'k-{i:07d}','run-00',persona,ip,1,manifest,events_out,args.capture_file,config)


def long_stage(args, manifest: Path, events_out: Path):
    """Stage L: true wall-clock timing. Each shard owns one interval profile."""
    profiles=list(LONG_TIMING_SECONDS)
    profile_ids=[i for i in range(len(profiles)) if i % args.shards == args.shard]
    timing=[s for s in SCENARIOS if s.family=='timing']
    for p in profile_ids:
        interval=profiles[p]
        reps=args.long_repetitions or int(os.environ.get('COVERLAB_LONG_REPETITIONS','2'))
        for rep in range(reps):
            suspicious=rep % 2 == 0
            persona,ip=_base.PERSONAS[(p+rep)%len(_base.PERSONAS)]
            s=timing[(p+rep)%len(timing)]
            global _real_timing_calls; _real_timing_calls=0
            os.environ['COVERLAB_REAL_TIMING_SECONDS']=str(interval); os.environ['COVERLAB_REAL_TIMING_GAPS']='1'
            config={
                'experiment_stage':'L_long_timing','dataset_role':'long_timing_challenge',
                'configuration_id':f'L-{interval}-{rep}','real_interval_seconds':interval,
                'timing_acceleration':1,'training_eligible':False,'challenge_only':True,
                'transform_chain':['raw_utf8'],'timing_profile':f'real_{interval}s',
                'client_impl':'python_httpx','payload_size_class':'small',
            }
            _base.invoke(s.scenario_id,suspicious,args.seed+100_000_000+p*100+rep,f'l-{p:02d}-{rep:02d}',f'run-{rep:02d}',persona,ip,2,manifest,events_out,args.capture_file,config)
            os.environ.pop('COVERLAB_REAL_TIMING_SECONDS',None)


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--stage',choices=['parser','isolated','sequence','challenge','lots','future','mixed','benign','long'],required=True)
    p.add_argument('--out',required=True); p.add_argument('--capture-file',required=True); p.add_argument('--seed',type=int,default=26080823)
    p.add_argument('--shard',type=int,default=0); p.add_argument('--shards',type=int,default=1); p.add_argument('--persona-index',type=int,choices=[0,1,2,3],default=None)
    p.add_argument('--mixed-index',type=int); p.add_argument('--duration-minutes',type=int); p.add_argument('--flow-count',type=int)
    p.add_argument('--sessions',type=int); p.add_argument('--long-repetitions',type=int)
    a=p.parse_args(); out=Path(a.out); out.mkdir(parents=True,exist_ok=True)
    if a.persona_index is not None: os.environ['COVERLAB_PERSONA_INDEX']=str(a.persona_index)
    manifest=out/'campaigns.jsonl'; events=out/'events.jsonl'; manifest.touch(); events.touch()
    if a.stage == 'benign':
        fn=benign_stage
    elif a.stage == 'long':
        fn=long_stage
    else:
        fn=getattr(_base,a.stage+'_stage')
    fn(a,manifest,events)
    print(json.dumps({'stage':a.stage,'shard':a.shard,'campaigns':sum(1 for _ in manifest.open()),'events':sum(1 for _ in events.open())}))

if __name__=='__main__': main()
