"""Container-only original source entrypoint. No office data or host network."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def client(job):
    from browser_guard import install as install_browser_guard
    install_browser_guard()
    import coverlab
    from coverlab import run_campaign as rc
    from coverlab.scenarios import SCENARIOS
    from dataclasses import replace
    ids={s.scenario_id for s in SCENARIOS}
    if len(ids)!=158 or 'CC_WEBTRANS_01' not in ids or rc.run.__name__ != '_run_with_transport_dispatch':
        raise RuntimeError('required upstream dispatch hooks absent')
    out=Path(job['container_output']); seed=job['seed']; campaign=job['profile'].get('source_campaign_id',job['job_id'])
    if job['entry']['namespace']=='catalog':
        variant='suspicious' if job['arm']=='scenario' and job['entry']['dataset_role']!='hard_negative' else 'benign'
        profile=job['profile']
        if profile.get('stage'):
            from coverlab import orchestrate_v2
            from coverlab.client_runtime_v3 import install
            install()
        if job.get('native_interval') is not None:
            from coverlab import orchestrate_v3 as timing
            os.environ['COVERLAB_REAL_TIMING_SECONDS']=str(job['native_interval'])
            os.environ['COVERLAB_REAL_TIMING_GAPS']=str(max(1,job.get('events',3)-1))
            os.environ['COVERLAB_REAL_TIMING_MODE']='mixed'
        args=argparse.Namespace(scenario=profile.get('scenario_id',job['entry_id']),variant=variant,
            seed=seed,campaign_id=campaign,run_id=job['registry_sha256'],persona='Victim-2-Dev',source_ip='10.20.0.11',
            events=profile.get('events',job.get('events',3)),client_impl=profile.get('client','python_httpx') if profile.get('stage') else 'python_httpx',state='/tmp/coverlab_server_state.json',
            manifest=str(out/'campaign.jsonl'),events_out=str(out/'events.jsonl'),capture_file=str(out/'capture.pcap'))
        rc.run(args)
    else:
        from coverlab import stage_m as sm
        from browser_client import install_stage
        install_stage(sm)
        from protocol_patch import install as install_protocol
        install_protocol(sm,job)
        control=None
        if job['arm']=='control':
            from stage_controls import install
            control=install(sm,job)
        if job.get('mechanics'):
            from application_patch import install as install_application
            application=install_application(sm,job)
        specs=sm.build_specs('smoke')
        spec=next(s for s in specs if s.family==job['entry_id'] and s.implementation_id==job['profile'].get('implementation_id',job['profile_id']))
        # Smoke covers protocol dispatch and three native-cadence events, not
        # the full 15,150-campaign volume grid or hours-long persistence.
        spec=replace(spec,event_count=job.get("events",3))
        if job.get("native_interval") is not None:spec=replace(spec,interval_seconds=job["native_interval"])
        os.environ['COVERLAB_STAGE_M_TIME_SCALE']='1' if job['timing']=='native' else '0.001'
        os.environ['COVERLAB_STAGE_M_MAX_SLEEP_SECONDS']='' if job['timing']=='native' else '0.05'
        result,events=sm.run_one(spec,seed,campaign,'Victim-2-Dev','10.20.0.11',str(out/'capture.pcap'))
        if job.get('mechanics'):result['bounded_application_contract']=application
        if control:
            result.update(arm='control',label_binary=0,positive_only=False,control_contract=control,
                          training_eligible=False,timing_training_eligible=False)
        (out/'campaign.jsonl').write_text(json.dumps(result)+'\n')
        (out/'events.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
    (out/'dispatch.json').write_text(json.dumps({'dispatch_verified':True,'catalog_count':len(ids),'package_version':coverlab.__version__})+'\n')


def filter_required_service_probes(script, required_services):
    required = set(required_services or {"all"})
    if "all" in required:
        return script
    def service_for_probe(name):
        if name.startswith("h3-"):
            return "h3"
        if name == "grpc":
            return "grpc"
        if name == "mqtt-wss":
            return "mqtt"
        if name.startswith("stage-m-"):
            return "stage_m"
        return "core"
    output = []
    for line in script.splitlines():
        stripped = line.strip()
        if stripped.startswith("required_probe "):
            parts = stripped.split()
            probe_name = parts[1] if len(parts) > 1 else ""
            service = service_for_probe(probe_name)
            if service not in required:
                output.append(f'echo "optional service probe skipped: {probe_name}"')
                continue
        output.append(line)
    return "\n".join(output) + ("\n" if script.endswith("\n") else "")


def setup(required_services=None):
    # Docker mounts /etc/hosts as an individual file: upstream sed -i cannot
    # rename it. Derive a logged patch that changes only write mechanics.
    import re
    with Path('/etc/hosts').open('a') as hosts:hosts.write('\n127.0.0.1 '+__import__('socket').gethostname()+'\n')
    original=Path('/lab/scripts/setup_netns.sh').read_text()
    patched=re.sub(r'sudo sed -i -E (.+) /etc/hosts',r'sed -E \1 /etc/hosts > /tmp/cover-hosts.edit; cat /tmp/cover-hosts.edit > /etc/hosts',original)
    Path('/tmp/setup_netns.sh').write_text(patched)
    Path('/out/setup_patch.json').write_text(json.dumps({'original_sha256':hashlib.sha256(original.encode()).hexdigest(),
        'patched_sha256':hashlib.sha256(patched.encode()).hexdigest(),'reason':'Docker hosts mount write in place'})+'\n')
    subprocess.run(['bash','/tmp/setup_netns.sh'],check=True)
    from environment import apply_office_wire_translation
    apply_office_wire_translation('/out')
    for ns in ('cc-office','cc-dev','cc-c2','cc-dns','cc-devops','cc-soc'):
        routes=subprocess.check_output(['ip','netns','exec',ns,'ip','route'],text=True)
        if 'default' in routes:raise RuntimeError('unexpected default route')
    if 'default' in subprocess.check_output(['ip','route'],text=True):raise RuntimeError('container has default route')
    # Read-back the actual veth offload flags; host interfaces are never touched.
    offloads=[]
    for ns in (None,'cc-office','cc-dev','cc-c2','cc-dns','cc-devops','cc-soc'):
        prefix=['ip','netns','exec',ns] if ns else []
        devices=json.loads(subprocess.check_output(prefix+['ip','-j','link'],text=True))
        for dev in devices:
            name=dev['ifname']
            if name=='lo' or name=='br-cc':continue
            command=prefix+['ethtool','-K',name,'tso','off','gso','off','gro','off']
            subprocess.run(command,check=True,stdout=subprocess.DEVNULL)
            features=subprocess.check_output(prefix+['ethtool','-k',name],text=True)
            for key in ('tcp-segmentation-offload','generic-segmentation-offload','generic-receive-offload'):
                if key+': off' not in features:raise RuntimeError('offload remains enabled: '+name+' '+key)
            offloads.append({'namespace':ns,'device':name,'mtu':dev['mtu'],'features':features})
    Path('/out/offloads.json').write_text(json.dumps(offloads,indent=2)+'\n')
    services=Path('/lab/scripts/start_services.sh').read_text()
    # Upstream runs Mosquitto as a non-root GitHub runner. Container setup
    # starts as root: its implicit drop to mosquitto cannot read a 0600 root
    # TLS key. The isolated broker stays root inside its network namespace.
    service_patch=services.replace('listen 10.20.0.22:8443 ssl;','listen 10.20.0.22:8443 ssl http2;').replace('allow_anonymous true\npersistence false','allow_anonymous true\nuser root\npersistence false')
    service_patch=filter_required_service_probes(service_patch, required_services or {"all"})
    script=Path('/lab/scripts/start_services.container.sh');script.write_text(service_patch)
    Path('/out/services_patch.json').write_text(json.dumps({'original_sha256':hashlib.sha256(services.encode()).hexdigest(),
        'patched_sha256':hashlib.sha256(service_patch.encode()).hexdigest(),'reason':'container-root TLS key ownership and actual HTTP/2 on isolated nginx front'})+'\n')
    os.environ['RUNNER_TEMP']='/out/runtime'
    import shutil
    shutil.copyfile('/mechanic_patch.py','/lab/src/cover_mechanics.py')
    shutil.copyfile('/application_patch.py','/lab/src/cover_application.py')
    wss_path=Path('/lab/src/coverlab/wss_server.py');wss_original=wss_path.read_text()
    old='await ws.send(json.dumps({"type": "data_ack", "conn_id": obj.get("conn_id", "0"), "n": len(str(obj.get("data", "")))}))'
    new='await ws.send(json.dumps(await tunnel_reply(obj))) if st.get("scenario_id") == "M-TUNNEL" and st.get("suspicious") else '+old
    if wss_original.count(old)!=1:raise RuntimeError('upstream WSS patch target changed')
    patched_wss=wss_original.replace('from __future__ import annotations\n','from __future__ import annotations\nfrom cover_mechanics import tunnel_reply\n',1).replace(old,new)
    wss_path.write_text(patched_wss)
    Path('/out/wss_patch.json').write_text(json.dumps({'original_sha256':hashlib.sha256(wss_original.encode()).hexdigest(),
        'patched_sha256':hashlib.sha256(patched_wss.encode()).hexdigest(),'reason':'bounded fixed local TCP forwarding for M-TUNNEL only'})+'\n')
    subprocess.Popen(['ip','netns','exec','cc-c2','python','/mechanic_patch.py'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    server_path=Path('/lab/src/coverlab/server.py');server_original=server_path.read_text()
    patched_server=server_original.replace('let sent = 0, recv = 0;',
        "let sent = 0, recv = 0; window.__cover_evidence={sent:0,received:0,sent_bytes:0,received_bytes:0,sent_times_ms:[],received_times_ms:[],sent_lengths:[],received_lengths:[]}; const params=new URLSearchParams(location.search); const interval=Math.min(3600,Math.max(0,Number(params.get('interval')||0))); const jitter=Math.min(.5,Math.max(0,Number(params.get('jitter')||0)));")
    patched_server=patched_server.replace('ws.onopen = () => {','ws.onopen = async () => {')
    patched_server=patched_server.replace('ws.send(JSON.stringify(msg)); sent++;',
        "const wire=JSON.stringify(msg); window.__cover_evidence.sent_times_ms.push(Date.now()); window.__cover_evidence.sent_lengths.push(wire.length); ws.send(wire); sent++; window.__cover_evidence.sent=sent; window.__cover_evidence.sent_bytes+=wire.length; if(i+1<20 && interval>0) await new Promise(resolve=>setTimeout(resolve,interval*1000*(1+jitter*(2*parseInt(token,16)/4294967296-1))));")
    patched_server=patched_server.replace('ws.onmessage = () => { recv++; if (recv >= %d) ws.close(); };',
        'ws.onmessage = event => { window.__cover_evidence.received_times_ms.push(Date.now()); window.__cover_evidence.received_lengths.push(event.data.length); recv++; window.__cover_evidence.received=recv; window.__cover_evidence.received_bytes+=event.data.length; if (recv >= %d) ws.close(); };')
    target='    resp=response_for(sid, suspicious, seed)'
    replacement='    if not suspicious and st.get(\"benign_response_bytes\"):\n        target_size=max(32,min(65536,int(st.get(\"benign_response_bytes\",256))))\n        raw=json.dumps({\"status\":\"ok\",\"service\":\"office-control\",\"value\":token(seed,12)},separators=(\",\",\":\")).encode()\n        response_body=(raw+(b\" \"*target_size))[:target_size]\n        resp=Response(response_body,media_type=\"application/octet-stream\")\n    elif path.startswith(\"bounded/\"):\n        import asyncio\n        from cover_application import server_answer\n        answer=await asyncio.to_thread(server_answer,\"/\"+path,dict(request.query_params),req_body,str(st.get(\"campaign_id\",\"\")))\n        resp=JSONResponse(answer)\n    else:\n        resp=response_for(sid,suspicious,seed)'
    if patched_server.count(target)!=1:raise RuntimeError('bounded application patch target changed')
    patched_server=patched_server.replace(target,replacement)
    server_path.write_text(patched_server)
    Path('/out/browser_fixture_patch.json').write_text(json.dumps({'original_sha256':hashlib.sha256(server_original.encode()).hexdigest(),
        'patched_sha256':hashlib.sha256(patched_server.encode()).hexdigest(),'reason':'real CDP completion counts and native browser WSS cadence'})+'\n')
    subprocess.run(['bash',str(script)],check=True)


def run(job):
    out=Path('/out')/job['job_id'];out.mkdir(exist_ok=True)
    job={**job,'container_output':str(out)}
    (out/'job.json').write_text(json.dumps(job)+'\n')
    if job.get('path_rtt_ms') is not None:
        from environment import apply
        apply(job['path_rtt_ms'],out,job.get('client_mtu'),job.get('client_tcp_timestamps'),job.get('path_profile'))
    trace_paths=[Path('/tmp/coverlab_server_trace.jsonl'),Path('/tmp/coverlab_wss_trace.jsonl'),Path('/out/fixed_forwarding.jsonl'),Path('/out/application_receipts.jsonl')]
    trace_offsets={p:p.stat().st_size if p.exists() else 0 for p in trace_paths}
    base={k:job[k] for k in ('entry_id','profile_id','arm','registry_sha256','job_id')}
    capture=subprocess.Popen(['tcpdump','--immediate-mode','-i','v-dev','-U','-s','0','-w',str(out/'capture.pcap')],stderr=subprocess.PIPE)
    try:
        import selectors
        selector=selectors.DefaultSelector();selector.register(capture.stderr,selectors.EVENT_READ)
        ready=[];deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            if not selector.select(.1):continue
            line=capture.stderr.readline();ready.append(line)
            if b'listening on ' in line:break
            if capture.poll() is not None:raise RuntimeError('tcpdump exited before readiness')
        else:raise RuntimeError('tcpdump readiness timeout')
        selector.close()
        with (out/'client.log').open('w') as log:
            env={k:v for k,v in os.environ.items() if 'proxy' not in k.lower()}
            env.update(PYTHONPATH='/upstream-main/src' if job['entry']['namespace']=='catalog' else '/lab/src',
                       NO_PROXY='.test,10.20.0.0/24,localhost,127.0.0.1',no_proxy='.test,10.20.0.0/24,localhost,127.0.0.1')
            cp=subprocess.run(['ip','netns','exec','cc-dev','python','/entrypoint.py','--client',str(out/'job.json')],env=env,stdout=log,stderr=subprocess.STDOUT,timeout=job.get('timeout_seconds',180))
        time.sleep(.1)
    finally:
        capture.send_signal(signal.SIGINT);_,stderr=capture.communicate(timeout=10)
        (out/'tcpdump.log').write_bytes(b''.join(ready)+stderr)
    data=(out/'capture.pcap').read_bytes();position=24;packets=0
    import struct
    while position<len(data):
        if position+16>len(data):raise RuntimeError('truncated PCAP record')
        cap=struct.unpack_from('<IIII',data,position)[2];position+=16+cap;packets+=1
    if position!=len(data):raise RuntimeError('truncated PCAP frame')
    ok=cp.returncode==0 and packets>0
    for path in trace_paths:
        if path.exists():
            with path.open('rb') as f:f.seek(trace_offsets[path]);(out/path.name).write_bytes(f.read())
    state=Path('/tmp/coverlab_server_state.json')
    if state.exists():__import__('shutil').copyfile(state,out/'server_state.json')
    result={**base,'status':'captured' if ok else 'failed','reason':None if ok else 'empty_capture' if cp.returncode==0 else 'client_exit:'+str(cp.returncode),
            'timing':job['timing'],'behavior_profile_sha256':str((job.get('profile') or {}).get('behavior_profile_sha256','')),
            'production_ready':False,'capture_path':str(out/'capture.pcap'),
            'capture_sha256':sha(out/'capture.pcap'),'source_fidelity':job['entry']['source_fidelity'],
            'observed_packets':packets,'capture_scope':'client_access_link_v-dev_both_directions'}
    result['evidence_sha256']={p.name:sha(p) for p in sorted(out.iterdir()) if p.is_file() and p.name not in ('result.json','capture.pcap')}
    if job['entry_id']=='M-TUNNEL' and job['arm']=='scenario':
        journal=out/'fixed_forwarding.jsonl'
        records=[json.loads(line) for line in journal.read_text().splitlines()] if journal.exists() else []
        result['fixed_forwarding_verified']=len(records)==job.get("events",3) and all(r['target']=='fixed_loopback_9092' for r in records)
        if not result['fixed_forwarding_verified']:result.update(status='failed',reason='missing_fixed_local_forwarding_evidence')
    if job.get('mechanics') and (out/'expected_receipts.json').exists():
        expected=json.loads((out/'expected_receipts.json').read_text())
        receipts=[json.loads(line) for line in (out/'application_receipts.jsonl').read_text().splitlines()] if (out/'application_receipts.jsonl').exists() else []
        required=[r for r in expected if r['complete_required']]
        actual=[r for r in receipts if r.get('complete')]
        result['application_decode_verified']=len(actual)==len(required) and all(
            a['path']==b['path'] and a['sha256']==b['sha256'] for a,b in zip(actual,required))
        if not result['application_decode_verified']:result.update(status='failed',reason='missing_or_mismatched_application_decode')
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def main():
    if len(sys.argv)>2 and sys.argv[1]=='--client':client(json.loads(Path(sys.argv[2]).read_text()));return
    request=json.loads(Path(sys.argv[1]).read_text());setup(request.get('required_services'))
    results=[]
    for job in request.get('jobs',[request]):
        try:results.append(run(job))
        except Exception as exc:results.append({'job_id':job['job_id'],'status':'failed','reason':type(exc).__name__+':'+str(exc)})
        Path('/out/results.json').write_text(json.dumps(results,indent=2)+'\n')


if __name__=='__main__':main()