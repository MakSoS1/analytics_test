#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,os,subprocess,sys
from collections import Counter
from dataclasses import replace
from datetime import datetime,timezone
from ipaddress import ip_address,ip_network
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];SRC=ROOT/'src'
if str(SRC) not in sys.path:sys.path.insert(0,str(SRC))
from adminlab.campaign_sequences import organize_campaign_sequences
from adminlab.config import load_yaml
from adminlab.digital_twin import load_digital_twin_bundle,plan_digital_twin_sessions
from adminlab.manifest import SessionRecord,write_sessions
from adminlab.wire_controls import materialize_wire_controls
LAB_NETWORK=ip_network('10.77.0.0/24');SUPPORTED_PROTOCOLS={'ssh','smb'}
def run(cmd:list[str],*,check:bool=True,timeout:int=20)->subprocess.CompletedProcess:return subprocess.run(cmd,check=check,timeout=timeout,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
def assert_lab_address(address:str)->None:
    if ip_address(address) not in LAB_NETWORK:raise ValueError(f'destination outside isolated lab: {address}')
def namespace_by_host(topology:dict)->dict[str,str]:return {str(h['id']):str(h['namespace']) for h in topology['hosts']}
def apply_netem(ns:str,profile_name:str,netem:dict)->None:
    p=netem['profiles'][profile_name];mtu=int(p.get('mtu',1500));run(['ip','netns','exec',ns,'ip','link','set','dev','eth0','mtu',str(mtu)]);args=['ip','netns','exec',ns,'tc','qdisc','replace','dev','eth0','root','netem'];n=0;delay=float(p.get('delay_ms',0));jitter=float(p.get('jitter_ms',0));loss=float(p.get('loss_pct',0));reorder=float(p.get('reorder_pct',0));rate=float(p.get('rate_mbit',0))
    if delay>0 or jitter>0:
        args+=['delay',f'{delay:g}ms'];n+=1
        if jitter>0:args+=[f'{jitter:g}ms']
    if loss>0:args+=['loss',f'{loss:g}%'];n+=1
    if reorder>0:args+=['reorder',f'{reorder:g}%'];n+=1
    if rate>0:args+=['rate',f'{rate:g}mbit'];n+=1
    if n==0:args+=['delay','0ms']
    run(args)
def clear_netem(ns:str)->None:run(['ip','netns','exec',ns,'tc','qdisc','del','dev','eth0','root'],check=False);run(['ip','netns','exec',ns,'ip','link','set','dev','eth0','mtu','1500'],check=False)
def ssh_base(ns:str,key:Path,dst_ip:str)->list[str]:assert_lab_address(dst_ip);return ['ip','netns','exec',ns,'ssh','-i',str(key),'-o','BatchMode=yes','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','ConnectTimeout=5',f'root@{dst_ip}']
def _transfer_bytes(r:SessionRecord,fallback:int)->int:return int(r.wire_transfer_bytes) if int(r.wire_transfer_bytes)>0 else fallback
def _attempts(r:SessionRecord)->int:return max(1,int(r.wire_attempts))
def run_ssh(r:SessionRecord,ns:str,state_dir:Path,work_dir:Path)->None:
    key=state_dir/'ssh/client_ed25519'
    if not key.is_file():raise RuntimeError(f'SSH client key missing: {key}')
    base=ssh_base(ns,key,r.dst_ip)
    if r.action=='inert_sftp_transfer':
        size=_transfer_bytes(r,64*1024);f=work_dir/f'inert-{r.session_id}.bin';f.write_bytes((b'ADMINLAB-INERT-SSH-MARKER\n'*((size//26)+1))[:size]);scp=['ip','netns','exec',ns,'scp','-q','-i',str(key),'-o','BatchMode=yes','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null',str(f),f'root@{r.dst_ip}:/tmp/{f.name}']
        for _ in range(_attempts(r)):run(scp,timeout=30)
        return
    if r.action=='bounded_proxyjump' or r.task_id=='approved_forwarding':
        jump='10.77.0.21';target='10.77.0.22';assert_lab_address(jump);assert_lab_address(target)
        proxy=['ip','netns','exec',ns,'ssh','-i',str(key),'-o','BatchMode=yes','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','ConnectTimeout=5','-o',f'ProxyCommand=ssh -i {key} -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -W %h:%p root@{jump}',f'root@{target}','true']
        for _ in range(_attempts(r)):run(proxy,timeout=20)
        return
    reps=_attempts(r) if r.action=='repeated_login' else 1
    for _ in range(reps):run(base+["printf 'adminlab-session-ok\\n' >/dev/null; true"],timeout=15)
def run_smb(r:SessionRecord,ns:str,work_dir:Path)->None:
    assert_lab_address(r.dst_ip);base=['ip','netns','exec',ns,'smbclient',f'//{r.dst_ip}/adminlab_admin','-U','adminlab_smb%AdminlabSMB-2026!','-m','SMB3'];reps=_attempts(r)
    if r.action=='inert_marker_put':
        size=_transfer_bytes(r,128*1024);f=work_dir/f'inert-marker-{r.session_id}.bin';f.write_bytes((b'ADMINLAB-INERT-SMB-MARKER\n'*((size//26)+1))[:size])
        for _ in range(reps):run(base+['-c',f'put {f} {f.name}'],timeout=30)
    else:
        for _ in range(reps):run(base+['-c','ls; get readme.txt /tmp/adminlab-readme.txt'],timeout=20)
def execute_record(r:SessionRecord,ns_by_host:dict[str,str],state_dir:Path,work_dir:Path,netem:dict)->SessionRecord:
    assert_lab_address(r.src_ip);assert_lab_address(r.dst_ip);ns=ns_by_host[r.src_host_id];started=datetime.now(timezone.utc);status='success'
    try:
        apply_netem(ns,r.netem_profile,netem)
        if r.protocol=='ssh':run_ssh(r,ns,state_dir,work_dir)
        elif r.protocol=='smb':run_smb(r,ns,work_dir)
        else:status='unsupported'
    except (subprocess.CalledProcessError,subprocess.TimeoutExpired,OSError,RuntimeError,ValueError) as exc:status=f'failed:{type(exc).__name__}'
    finally:clear_netem(ns)
    return replace(r,execution_start_ts=started.isoformat(),execution_end_ts=datetime.now(timezone.utc).isoformat(),status=status)
def select_supported(records:list[SessionRecord],count:int,protocols:set[str])->list[SessionRecord]:
    selected=[r for r in records if r.protocol in protocols]
    if len(selected)<count:raise RuntimeError(f'planner produced only {len(selected)} supported sessions, need {count}')
    return selected[:count]
def main()->int:
    p=argparse.ArgumentParser();p.add_argument('--stage',default='A',choices=list('ABCDEFGH'));p.add_argument('--count',type=int,default=40);p.add_argument('--seed',type=int,default=20260814);p.add_argument('--protocols',default='ssh,smb');p.add_argument('--state-dir',type=Path,default=Path('/tmp/adminlab-services'));p.add_argument('--out',type=Path,default=Path('/tmp/adminlab-wire-smoke'));a=p.parse_args()
    if os.geteuid()!=0:raise SystemExit('run_scenarios.py must run as root because it uses ip netns exec')
    protocols={x.strip() for x in a.protocols.split(',') if x.strip()}
    if not protocols or not protocols<=SUPPORTED_PROTOCOLS:raise SystemExit(f'V1 core runner supports only {sorted(SUPPORTED_PROTOCOLS)}')
    topology=load_yaml(ROOT/'configs/topology.yaml');scenarios=load_yaml(ROOT/'configs/scenarios.yaml');netem=load_yaml(ROOT/'configs/netem.yaml');bundle=load_digital_twin_bundle(ROOT/'configs');nsmap=namespace_by_host(topology)
    planned=plan_digital_twin_sessions(topology,scenarios,netem,bundle,seed=a.seed,count=max(a.count*12,240),stage=a.stage)
    selected=select_supported(planned,a.count,protocols)
    selected=organize_campaign_sequences(selected,bundle['campaigns'],seed=a.seed)
    records=materialize_wire_controls(selected,bundle['behavior'],seed=a.seed)
    a.out.mkdir(parents=True,exist_ok=True);work=a.out/'inert-fixtures';work.mkdir(parents=True,exist_ok=True);write_sessions(records,a.out/'sessions-planned.jsonl');executed=[execute_record(r,nsmap,a.state_dir,work,netem) for r in records];write_sessions(executed,a.out/'sessions-executed.jsonl');statuses=Counter(r.status for r in executed);pc=Counter(r.protocol for r in executed);lc=Counter('suspicious' if r.label_binary else 'benign' for r in executed);success={x:sum(1 for r in executed if r.protocol==x and r.status=='success') for x in sorted(protocols)};campaigns={r.campaign_id for r in records};multi=sum(1 for cid in campaigns if sum(1 for r in records if r.campaign_id==cid)>=3);summary={'requested':a.count,'executed':len(executed),'status_counts':dict(statuses),'protocol_counts':dict(pc),'label_counts':dict(lc),'success_by_protocol':success,'campaign_count':len(campaigns),'multi_session_campaigns':multi,'lab_network':str(LAB_NETWORK),'external_targets_allowed':False,'payload_execution_allowed':False,'planner':'digital_twin_v1','wire_controls_label_dependent':False,'simulated_timeline_preserved':True};(a.out/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n');print(json.dumps(summary,sort_keys=True))
    if statuses.get('success',0)!=len(executed):return 1
    if any(success.get(x,0)==0 for x in protocols):return 1
    if len(lc)<2 and a.stage!='B':return 1
    return 0
if __name__=='__main__':raise SystemExit(main())
