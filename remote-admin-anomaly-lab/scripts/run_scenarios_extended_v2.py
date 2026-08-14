#!/usr/bin/env python3
from __future__ import annotations
import argparse,importlib.util,json,os,sys
from collections import Counter,defaultdict
from dataclasses import replace
from datetime import datetime,timezone
from ipaddress import ip_address,ip_network
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];SRC=ROOT/'src'
if str(SRC) not in sys.path:sys.path.insert(0,str(SRC))
from adminlab.config import load_yaml
from adminlab.digital_twin import load_digital_twin_bundle,plan_digital_twin_sessions
from adminlab.extended_wire_v2 import run_rdp_session,run_vnc_session,run_winrm_session
from adminlab.manifest import SessionRecord,write_sessions
from adminlab.wire_controls import materialize_wire_controls
spec=importlib.util.spec_from_file_location('adminlab_core_wire',ROOT/'scripts/run_scenarios.py')
if spec is None or spec.loader is None:raise RuntimeError('cannot load core wire runner')
core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
LAB_NETWORK=ip_network('10.77.0.0/24');TRAIN_PROTOCOLS=('ssh','smb','rdp','vnc');CHALLENGE_PROTOCOLS=TRAIN_PROTOCOLS+('winrm',)
def namespace_map(t:dict)->dict[str,str]:return {str(h['id']):str(h['namespace']) for h in t['hosts']}
def assert_lab(v:str)->None:
    if ip_address(v) not in LAB_NETWORK:raise RuntimeError(f'non-lab address rejected: {v}')
def balanced_select(records:list[SessionRecord],count:int,protocols:tuple[str,...])->list[SessionRecord]:
    b:dict[str,list[SessionRecord]]=defaultdict(list)
    for r in records:
        if r.protocol in protocols:b[r.protocol].append(r)
    base=count//len(protocols);rem=count%len(protocols);out=[]
    for i,p in enumerate(protocols):
        need=base+(1 if i<rem else 0)
        if len(b[p])<need:raise RuntimeError(f'digital twin produced only {len(b[p])} {p} rows; need {need}')
        out.extend(b[p][:need])
    out.sort(key=lambda r:(r.start_ts,r.session_id))
    if len(out)!=count:raise AssertionError((len(out),count))
    return out
def execute(r:SessionRecord,namespaces:dict[str,str],core_state:Path,work:Path,netem:dict)->SessionRecord:
    assert_lab(r.src_ip);assert_lab(r.dst_ip);ns=namespaces[r.src_host_id];started=datetime.now(timezone.utc);status='success'
    try:
        core.apply_netem(ns,r.netem_profile,netem)
        if r.protocol=='ssh':core.run_ssh(r,ns,core_state,work)
        elif r.protocol=='smb':core.run_smb(r,ns,work)
        elif r.protocol=='rdp':run_rdp_session(r,ns)
        elif r.protocol=='vnc':run_vnc_session(r,ns)
        elif r.protocol=='winrm':run_winrm_session(r,ns)
        else:raise RuntimeError(f'unsupported/fidelity-only protocol: {r.protocol}')
    except Exception as exc:status=f'failed:{type(exc).__name__}:{str(exc)[:180]}'
    finally:core.clear_netem(ns)
    return replace(r,execution_start_ts=started.isoformat(),execution_end_ts=datetime.now(timezone.utc).isoformat(),status=status)
def main()->int:
    p=argparse.ArgumentParser();p.add_argument('--stage',required=True,choices=list('ABCDEFGH'));p.add_argument('--count',type=int,required=True);p.add_argument('--seed',type=int,required=True);p.add_argument('--core-state',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--include-partial-winrm',action='store_true');a=p.parse_args()
    if os.geteuid()!=0:raise SystemExit('extended scenario runner requires root')
    topology=load_yaml(ROOT/'configs/topology.yaml');scenarios=load_yaml(ROOT/'configs/scenarios.yaml');netem=load_yaml(ROOT/'configs/netem.yaml');bundle=load_digital_twin_bundle(ROOT/'configs');namespaces=namespace_map(topology);protocols=CHALLENGE_PROTOCOLS if a.include_partial_winrm else TRAIN_PROTOCOLS
    if a.stage!='H' and a.include_partial_winrm:raise SystemExit('partial WinRM is Stage-H challenge only')
    planned=plan_digital_twin_sessions(topology,scenarios,netem,bundle,seed=a.seed,count=max(a.count*16,a.count+1600),stage=a.stage);selected=materialize_wire_controls(balanced_select(planned,a.count,protocols),bundle['behavior'],seed=a.seed);a.out.mkdir(parents=True,exist_ok=True);fixtures=a.out/'inert-fixtures';fixtures.mkdir(exist_ok=True);write_sessions(selected,a.out/'sessions-planned.jsonl');executed=[execute(r,namespaces,a.core_state,fixtures,netem) for r in selected];write_sessions(executed,a.out/'sessions-executed.jsonl');statuses=Counter('success' if r.status=='success' else 'failed' for r in executed);pc=Counter(r.protocol for r in executed);lc=Counter('suspicious' if r.label_binary else 'benign' for r in executed);failures=[r.to_dict() for r in executed if r.status!='success'];summary={'requested':a.count,'executed':len(executed),'status_counts':dict(statuses),'protocol_counts':dict(pc),'label_counts':dict(lc),'protocol_balance_max_minus_min':max(pc.values())-min(pc.values()),'train_protocols':list(TRAIN_PROTOCOLS),'partial_winrm_included':a.include_partial_winrm,'dcerpc_train_included':False,'external_targets_allowed':False,'payload_execution_allowed':False,'planner':'digital_twin_v1','wire_controls_label_dependent':False,'simulated_timeline_preserved':True,'failures':failures[:20]};(a.out/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n');print(json.dumps(summary,sort_keys=True))
    if failures:return 1
    if set(pc)!=set(protocols):return 1
    if summary['protocol_balance_max_minus_min']>1:return 1
    return 0
if __name__=='__main__':raise SystemExit(main())
