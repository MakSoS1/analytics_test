from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from . import orchestrate as _base
from . import orchestrate_v2  # installs label/browser correctness patches on _base
from . import run_campaign as _rc
from .client_runtime_v3 import install as _install_client_runtime
from .research_contract_v3 import BENIGN_SERVICE_PROFILES, CLIENT_STACKS, LONG_TIMING_SECONDS, SERVER_STACKS
from .scenarios import SCENARIOS

_install_client_runtime()
_ORIGINAL_SLEEP = _rc.time.sleep
_real_timing_calls = 0


def _timing_factor(mode: str, call: int) -> float:
    phase=((call*37)%101)/100.0
    if mode=='fixed': return 1.0
    if mode=='jitter_5': return 0.95+phase*0.10
    if mode=='jitter_20': return 0.80+phase*0.40
    if mode=='jitter_50': return 0.50+phase*1.00
    if mode=='burst_silence': return 0.20 if call%4 in (1,2,3) else 2.40
    if mode=='backoff': return min(3.0,0.55*(1.28**max(0,call-1)))
    if mode=='phase_transition': return 0.65 if call%10<5 else 1.45
    if mode=='mixed':
        cycle=('fixed','jitter_5','jitter_20','jitter_50','burst_silence','backoff','phase_transition')
        return _timing_factor(cycle[(call-1)%len(cycle)],call)
    return 1.0


def _sleep_v3(seconds: float):
    global _real_timing_calls
    raw=os.environ.get('COVERLAB_REAL_TIMING_SECONDS')
    if raw and 0.009 <= float(seconds) <= 0.20:
        _real_timing_calls += 1
        gaps=int(os.environ.get('COVERLAB_REAL_TIMING_GAPS','1'))
        if _real_timing_calls <= gaps:
            return _ORIGINAL_SLEEP(float(raw)*_timing_factor(os.environ.get('COVERLAB_REAL_TIMING_MODE','fixed'),_real_timing_calls))
        return _ORIGINAL_SLEEP(0.001)
    return _ORIGINAL_SLEEP(seconds)

_rc.time.sleep = _sleep_v3

ACTUAL_LINUX_CLIENTS=("python_httpx","python_httpx_h2","python_stdlib","curl_linux","go_nethttp","node_fetch","java_httpclient","rust_reqwest")
BENIGN_PATTERNS=(
    'websocket_dashboard','sse_feed','long_polling','grpc_telemetry','mqtt_telemetry',
    'health_check','oauth_refresh','cloud_sync','software_update','ide_telemetry',
    'ci_polling','webhook_retry','api_pagination','browser_background',
)
MATCHED_ANALOGUES={
    'websocket_dashboard':'long_lived_wss','sse_feed':'streaming_channel','long_polling':'beacon_poll',
    'grpc_telemetry':'grpc_channel','mqtt_telemetry':'mqtt_channel','health_check':'periodic_beacon',
    'oauth_refresh':'token_refresh_beacon','cloud_sync':'result_upload','software_update':'bulk_download',
    'ide_telemetry':'telemetry_upload','ci_polling':'periodic_poll','webhook_retry':'retry_backoff',
    'api_pagination':'chunked_transfer','browser_background':'background_periodicity',
}
# A temporal hard-negative label must correspond to the actual wire protocol family.
# Some business semantics (OAuth/cloud/IDE) are approximated locally, but never
# represented as a different transport than the bytes actually generated.
PATTERN_FAMILIES={
    'websocket_dashboard':('websocket',),
    'sse_feed':('sse',),
    'long_polling':('longpoll',),
    'grpc_telemetry':('grpc',),
    'mqtt_telemetry':('mqtt_ws',),
    'health_check':('timing','response'),
    'oauth_refresh':('header','body'),
    'cloud_sync':('body','response','timing'),
    'software_update':('response','body'),
    'ide_telemetry':('body','grpc','websocket'),
    'ci_polling':('longpoll','timing'),
    'webhook_retry':('body','timing'),
    'api_pagination':('uri',),
    'browser_background':('browser','timing','websocket'),
}


def _benign_event_count(i:int)->int:
    q=i%100
    if q<20:return 1
    if q<40:return 2+(i%2)
    if q<60:return 4+(i%7)
    if q<80:return 10+(i%21)
    if q<95:return 30+(i%31)
    return 61+(i%40)


def _benign_scenario(pattern:str,i:int,shard:int):
    families=set(PATTERN_FAMILIES[pattern])
    candidates=[s for s in SCENARIOS if s.family in families and s.family!='lots']
    if not candidates:raise RuntimeError(f'no wire-compatible benign candidates for {pattern}')
    return candidates[(i*37+shard*11)%len(candidates)]


def benign_stage(args, manifest: Path, events_out: Path):
    total=args.sessions or int(os.environ.get('COVERLAB_BENIGN_SESSIONS','60000'))
    actual_netem=os.environ.get('COVERLAB_NETEM_PROFILE','clean')
    for i in range(total):
        if i % args.shards != args.shard: continue
        persona,ip=_base.PERSONAS[i % len(_base.PERSONAS)]
        service=BENIGN_SERVICE_PROFILES[i % len(BENIGN_SERVICE_PROFILES)]
        planned_stack=CLIENT_STACKS[(i//3) % len(CLIENT_STACKS)]
        actual_client=ACTUAL_LINUX_CLIENTS[(i//7) % len(ACTUAL_LINUX_CLIENTS)]
        pattern=BENIGN_PATTERNS[(i//5)%len(BENIGN_PATTERNS)]
        s=_benign_scenario(pattern,i,args.shard)
        event_count=_benign_event_count(i)
        config={
            'experiment_stage':'K_benign_diversity','dataset_role':'benign_background',
            'configuration_id':f'K-{i:06d}','benign_service_profile':service,
            'planned_client_stack':planned_stack,'client_impl':actual_client,
            'planned_server_stack':SERVER_STACKS[(i//13)%len(SERVER_STACKS)],
            'actual_server_stack':'hypercorn_or_protocol_fixture','netem_profile':actual_netem,
            'training_eligible':True,'transform_chain':['benign_native'],
            'timing_profile':'matched_multi_event','payload_size_class':_base.SIZES[i%len(_base.SIZES)],
            'benign_temporal_pattern':pattern,'matched_attack_analogue':MATCHED_ANALOGUES[pattern],
            'event_count_target':event_count,'temporal_negative_pair':True,
            'wire_family_matched':True,'actual_wire_family':s.family,'actual_wire_transport':s.transport,
            'semantic_fidelity':'wire_family_real_local_semantic_approximation',
        }
        _base.invoke(s.scenario_id,False,args.seed+90_000_000+i,f'k-{i:07d}','run-00',persona,ip,event_count,manifest,events_out,args.capture_file,config)


def _long_event_count(interval:int)->int:
    return {5:30,30:30,120:20,300:10,1200:5,3600:4}.get(interval,10)


def long_stage(args, manifest: Path, events_out: Path):
    profiles=list(LONG_TIMING_SECONDS)
    profile_ids=[i for i in range(len(profiles)) if i % args.shards == args.shard]
    timing=[s for s in SCENARIOS if s.family=='timing']
    for p in profile_ids:
        interval=profiles[p]
        reps=args.long_repetitions or int(os.environ.get('COVERLAB_LONG_REPETITIONS','2'))
        events=_long_event_count(interval)
        for rep in range(reps):
            suspicious=rep % 2 == 0
            persona,ip=_base.PERSONAS[(p+rep)%len(_base.PERSONAS)]
            s=timing[(p+rep)%len(timing)]
            global _real_timing_calls; _real_timing_calls=0
            os.environ['COVERLAB_REAL_TIMING_SECONDS']=str(interval)
            os.environ['COVERLAB_REAL_TIMING_GAPS']=str(max(1,events-1))
            os.environ['COVERLAB_REAL_TIMING_MODE']='mixed'
            config={
                'experiment_stage':'L_long_timing','dataset_role':'long_timing_challenge',
                'configuration_id':f'L-{interval}-{rep}','real_interval_seconds':interval,
                'timing_acceleration':1,'training_eligible':False,'challenge_only':True,
                'transform_chain':['raw_utf8'],'timing_profile':f'real_{interval}s_multi_pattern',
                'timing_modes_exercised':['fixed','jitter_5','jitter_20','jitter_50','burst_silence','backoff','phase_transition'],
                'event_count_target':events,'client_impl':'python_httpx','payload_size_class':'small',
                'netem_profile':os.environ.get('COVERLAB_NETEM_PROFILE','clean'),'hosted_recommended':interval<=300,
            }
            _base.invoke(s.scenario_id,suspicious,args.seed+100_000_000+p*100+rep,f'l-{p:02d}-{rep:02d}',f'run-{rep:02d}',persona,ip,events,manifest,events_out,args.capture_file,config)
            for key in ('COVERLAB_REAL_TIMING_SECONDS','COVERLAB_REAL_TIMING_GAPS','COVERLAB_REAL_TIMING_MODE'):os.environ.pop(key,None)


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
    if a.stage == 'benign': fn=benign_stage
    elif a.stage == 'long': fn=long_stage
    else: fn=getattr(_base,a.stage+'_stage')
    fn(a,manifest,events)
    print(json.dumps({'stage':a.stage,'shard':a.shard,'campaigns':sum(1 for _ in manifest.open()),'events':sum(1 for _ in events.open())}))

if __name__=='__main__': main()
