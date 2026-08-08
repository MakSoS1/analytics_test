from __future__ import annotations

import argparse
import json
import os
import random
import time
from pathlib import Path
from types import SimpleNamespace

from .run_campaign import run
from .scenarios import SCENARIOS, select

PERSONAS = [
    ("Victim-1-Office","10.20.0.10"),
    ("Victim-2-Dev","10.20.0.11"),
    ("Persona-DevOps","10.20.0.30"),
    ("Persona-SOC-Analyst","10.20.0.31"),
]
TRANSFORMS = ["raw_utf8","base64","base64url","hex","zlib_base64","semantic_uuid"]
TIMINGS = ["fixed","low_jitter","medium_jitter","burst"]
CLIENTS = ["python_httpx","curl_linux","node_fetch","go_nethttp","python_stdlib","python_httpx_h2"]
SIZES = ["tiny","small","medium","large"]


def _append_config(manifest: Path, campaign_id: str, updates: dict):
    # Rewrite only the last record, adding experiment dimensions that are nuisance variables.
    lines=manifest.read_text().splitlines()
    rec=json.loads(lines[-1]); rec.update(updates); lines[-1]=json.dumps(rec,separators=(",",":"))
    manifest.write_text("\n".join(lines)+"\n")


def invoke(scenario_id: str, suspicious: bool, seed: int, campaign_id: str, run_id: str,
           persona: str, source_ip: str, events: int, manifest: Path, events_out: Path,
           capture_file: str, config: dict):
    persona_filter=os.environ.get("COVERLAB_PERSONA_INDEX")
    if persona_filter is not None and PERSONAS[int(persona_filter)][0] != persona:
        return
    ns=SimpleNamespace(
        scenario=scenario_id, variant="suspicious" if suspicious else "benign", seed=seed,
        campaign_id=campaign_id, run_id=run_id, persona=persona, source_ip=source_ip,
        events=events, client_impl=config.get("client_impl","python_httpx"), state="/tmp/coverlab_server_state.json", manifest=str(manifest),
        events_out=str(events_out), capture_file=capture_file,
    )
    run(ns)
    _append_config(manifest,campaign_id,config)


def parser_stage(args, manifest, events_out):
    # Exact source-plan Stage A: 60 suspicious + 60 paired benign, five repetitions = 600 sessions.
    scenarios=select("parser",args.shard,args.shards)
    seq=0
    for s in scenarios:
        for rep in range(5):
            for suspicious in (True,False):
                persona,ip=PERSONAS[(seq+rep)%len(PERSONAS)]
                cid=f"a-{args.shard:02d}-{seq:05d}-{rep}-{1 if suspicious else 0}"
                seed=args.seed+args.shard*1_000_000+seq*100+rep*2+(0 if suspicious else 1)
                config={"experiment_stage":"A_parser","configuration_id":f"A-{s.scenario_id}","transform_chain":[TRANSFORMS[rep%len(TRANSFORMS)]],"timing_profile":TIMINGS[rep%4],"client_impl":"python_httpx","payload_size_class":SIZES[rep%4]}
                invoke(s.scenario_id,suspicious,seed,cid,f"run-{rep:02d}",persona,ip,3,manifest,events_out,args.capture_file,config)
        seq+=1


def isolated_stage(args, manifest, events_out):
    # Exact volume: 216 configs, each 20 suspicious runs and 40 paired benign runs -> 12,960 sessions.
    core=select("core")
    config_ids=[i for i in range(216) if i % args.shards == args.shard]
    for cfg in config_ids:
        s=core[cfg%len(core)]
        transform=TRANSFORMS[(cfg//len(core))%len(TRANSFORMS)]
        timing=TIMINGS[(cfg//7)%len(TIMINGS)]
        client=CLIENTS[(cfg//11)%len(CLIENTS)]
        size=SIZES[(cfg//13)%len(SIZES)]
        for k in range(60):
            suspicious=k<20
            rep=k if suspicious else k-20
            persona,ip=PERSONAS[(cfg+k)%len(PERSONAS)]
            cid=f"b-{cfg:03d}-{k:02d}"
            seed=args.seed+cfg*10_000+k
            config={"experiment_stage":"B_isolated","configuration_id":f"B-{cfg:03d}","transform_chain":[transform],"timing_profile":timing,"client_impl":client,"payload_size_class":size,"pair_group":f"B-{cfg:03d}-{rep%20:02d}"}
            invoke(s.scenario_id,suspicious,seed,cid,f"run-{k:02d}",persona,ip,3,manifest,events_out,args.capture_file,config)


def sequence_stage(args, manifest, events_out):
    # 72 profiles * 10 runs = 720 campaigns; 60 transactions each -> 43,200 transactions.
    all_s=list(SCENARIOS)
    profiles=[p for p in range(72) if p%args.shards==args.shard]
    for p in profiles:
        for rep in range(10):
            s=all_s[(p*7+rep)%len(all_s)]
            suspicious=(p%4)!=0
            persona,ip=PERSONAS[(p+rep)%len(PERSONAS)]
            cid=f"c-{p:02d}-{rep:02d}"
            seed=args.seed+20_000_000+p*100+rep
            config={"experiment_stage":"C_sequence","configuration_id":f"C-{p:02d}","campaign_profile":p,"transform_chain":[TRANSFORMS[p%6]],"timing_profile":TIMINGS[p%4],"client_impl":CLIENTS[p%6],"payload_size_class":SIZES[p%4]}
            invoke(s.scenario_id,suspicious,seed,cid,f"run-{rep:02d}",persona,ip,60,manifest,events_out,args.capture_file,config)


def challenge_stage(args, manifest, events_out):
    groups=[]
    browser=[s for s in SCENARIOS if s.family=="browser"]
    tunnel=[s for s in SCENARIOS if s.family=="tunnel"]
    grpc_sse=[s for s in SCENARIOS if s.family in {"grpc","sse","longpoll"}]
    tls=[s for s in SCENARIOS if s.family=="tls"]
    # Profile counts from source plan. Repeat scenarios with varied configuration dimensions.
    groups += [(browser[i%len(browser)],True,"browser_native") for i in range(40)]
    groups += [(tunnel[i%len(tunnel)],True,"wss_tunnel") for i in range(40)]
    groups += [(grpc_sse[i%len(grpc_sse)],True,"grpc_sse") for i in range(20)]
    groups += [(tls[i%len(tls)],True,"tls_impersonation") for i in range(20)]
    # 20 privacy-like benign hard negatives (represented by TLS visibility fixtures with label 0).
    groups += [(tls[(i+5)%len(tls)],False,"privacy_benign") for i in range(20)]
    # 40 additional hard-negative profiles so total with 10 runs/profile and two paired benign
    # for each of the 120 suspicious profiles reaches >=4,200 sessions.
    hard=[s for s in SCENARIOS if s.family in {"browser","tls","websocket","http2"}]
    groups += [(hard[i%len(hard)],False,"hard_negative") for i in range(40)]
    profile_idx=0
    for s,is_suspicious,kind in groups:
        if profile_idx%args.shards != args.shard:
            profile_idx+=1; continue
        # Suspicious profile: 10 suspicious + 20 paired benign. Benign-only: 10 benign.
        variants=[True]*10+[False]*20 if is_suspicious else [False]*10
        for rep,suspicious in enumerate(variants):
            persona,ip=PERSONAS[(profile_idx+rep)%len(PERSONAS)]
            cid=f"f-{profile_idx:03d}-{rep:02d}"
            config={"experiment_stage":"F_challenge","challenge_kind":kind,"configuration_id":f"F-{profile_idx:03d}","transform_chain":[TRANSFORMS[(profile_idx+rep)%6]],"timing_profile":TIMINGS[(profile_idx+rep)%4],"client_impl":"browser_chromium" if kind=="browser_native" else CLIENTS[(profile_idx+rep)%6],"payload_size_class":SIZES[(profile_idx+rep)%4],"open_set":kind in {"privacy_benign","hard_negative"}}
            invoke(s.scenario_id,suspicious,args.seed+40_000_000+profile_idx*100+rep,cid,f"run-{rep:02d}",persona,ip,4,manifest,events_out,args.capture_file,config)
        profile_idx+=1


def lots_stage(args, manifest, events_out):
    target=[s for s in SCENARIOS if s.family in {"lots","mqtt_ws","doh"} or s.scenario_id in {"CC_BROWSER_09","CC_BROWSER_10","CC_BROWSER_11"}]
    profile_plan=[]
    for sid_prefix,count in [("lots_chatops",30),("lots_tunnel",20),("bucket",15),("mqtt",15),("browser_exfil",15),("doh",15)]:
        for i in range(count):
            if sid_prefix=="lots_chatops": candidates=[s for s in target if s.scenario_id in {"CC_LOTS_01","CC_LOTS_02","CC_LOTS_03","CC_LOTS_04"}]
            elif sid_prefix=="lots_tunnel": candidates=[s for s in target if s.scenario_id in {"CC_LOTS_05","CC_LOTS_06","CC_LOTS_07"}]
            elif sid_prefix=="bucket": candidates=[s for s in target if s.scenario_id=="CC_LOTS_08"]
            elif sid_prefix=="mqtt": candidates=[s for s in target if s.family=="mqtt_ws"]
            elif sid_prefix=="browser_exfil": candidates=[s for s in target if s.scenario_id.startswith("CC_BROWSER_")]
            else: candidates=[s for s in target if s.family=="doh"]
            profile_plan.append((candidates[i%len(candidates)],sid_prefix))
    for p,(s,kind) in enumerate(profile_plan):
        if p%args.shards != args.shard: continue
        for rep in range(10):
            # Produce one suspicious + at least two paired benign; chatops/tunnel gets 3:1 benign.
            benign_ratio=3 if kind in {"lots_chatops","lots_tunnel"} else 2
            for v in range(1+benign_ratio):
                suspicious=v==0
                persona,ip=PERSONAS[(p+rep+v)%len(PERSONAS)]
                cid=f"g-{p:03d}-{rep:02d}-{v}"
                config={"experiment_stage":"G_commodity","profile_kind":kind,"configuration_id":f"G-{p:03d}","transform_chain":[TRANSFORMS[(p+rep)%6]],"timing_profile":TIMINGS[(p+rep)%4],"client_impl":CLIENTS[(p+rep)%6],"payload_size_class":SIZES[(p+rep)%4]}
                invoke(s.scenario_id,suspicious,args.seed+60_000_000+p*1000+rep*10+v,cid,f"run-{rep:02d}",persona,ip,3,manifest,events_out,args.capture_file,config)



def mixed_stage(args, manifest, events_out):
    """Source-plan Stage D: one 60-120 minute capture per mixed_index.

    The workflow fans out 30 independent jobs. Captures 0-9 are completely benign.
    Remaining captures contain 10-100 suspicious events among 3k-15k benign flows.
    """
    idx=args.mixed_index
    if idx is None: raise ValueError("--mixed-index is required for mixed stage")
    duration=args.duration_minutes if args.duration_minutes is not None else [60,90,120][idx%3]
    flow_count=args.flow_count if args.flow_count is not None else min(15000,3000+idx*400)
    suspicious_total=0 if idx<10 else min(100,10+(idx-10)*4)
    suspicious_points=set()
    if suspicious_total==1: suspicious_points={flow_count//2}
    elif suspicious_total>1:
        suspicious_points={round(j*(flow_count-1)/(suspicious_total-1)) for j in range(suspicious_total)}
    pidx=args.persona_index if args.persona_index is not None else 0
    own=[i for i in range(flow_count) if (i+idx)%4==pidx]
    interval=(duration*60.0/max(1,len(own)))
    benign_candidates=[s for s in SCENARIOS if s.family in {"uri","header","body","response","websocket","http2","sse","longpoll","lots"}]
    suspicious_candidates=[s for s in SCENARIOS if s.family in {"uri","header","body","response","websocket","http2","timing","tunnel","lots"}]
    r=random.Random(args.seed+idx*100000+pidx)
    persona,ip=PERSONAS[pidx]
    for pos,i in enumerate(own):
        suspicious=i in suspicious_points
        candidates=suspicious_candidates if suspicious else benign_candidates
        sc=candidates[(i*17+idx)%len(candidates)]
        # Keep mixed corpus wire diversity but browser is isolated into challenge stage.
        client=CLIENTS[(i+idx)%len(CLIENTS)]
        cid=f"d-{idx:02d}-{i:05d}"
        config={"experiment_stage":"D_mixed","mixed_capture_index":idx,"logical_capture_minutes":duration,"configuration_id":f"D-{idx:02d}","transform_chain":[TRANSFORMS[(i+idx)%6]],"timing_profile":TIMINGS[(i+idx)%4],"client_impl":client,"payload_size_class":SIZES[(i+idx)%4],"mixed_prevalence":suspicious_total/max(1,flow_count)}
        invoke(sc.scenario_id,suspicious,args.seed+80_000_000+idx*100000+i,cid,"run-00",persona,ip,1,manifest,events_out,args.capture_file,config)
        if pos != len(own)-1: time.sleep(interval)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--stage",choices=["parser","isolated","sequence","challenge","lots","mixed"],required=True)
    p.add_argument("--out",required=True)
    p.add_argument("--capture-file",required=True)
    p.add_argument("--seed",type=int,default=26080823)
    p.add_argument("--shard",type=int,default=0)
    p.add_argument("--shards",type=int,default=1)
    p.add_argument("--persona-index",type=int,choices=[0,1,2,3],default=None)
    p.add_argument("--mixed-index",type=int,default=None)
    p.add_argument("--duration-minutes",type=int,default=None)
    p.add_argument("--flow-count",type=int,default=None)
    args=p.parse_args()
    out=Path(args.out); out.mkdir(parents=True,exist_ok=True)
    if args.persona_index is not None: os.environ["COVERLAB_PERSONA_INDEX"]=str(args.persona_index)
    manifest=out/"campaigns.jsonl"; events=out/"events.jsonl"
    manifest.touch(); events.touch()
    globals()[args.stage+"_stage"](args,manifest,events)
    print(json.dumps({"stage":args.stage,"shard":args.shard,"campaigns":sum(1 for _ in manifest.open()),"events":sum(1 for _ in events.open())}))

if __name__=="__main__": main()
