"""Predeclared ordinary GET experiments; no credentials, uploads or arbitrary targets."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import socket
import subprocess
import time
import threading
from urllib.parse import urlsplit,quote
from .public_capture import TARGETS
from .public_validation import verify_browser_page

GIB=1<<30
OUTPUT_BUDGET=6*GIB
FILE_LIMIT=128<<20
TRAINING_SEED=20261116

def workload(profile):
    if profile not in range(12):raise ValueError('only twelve predeclared profiles')
    persistent=(profile%6)//3==1
    url=TARGETS[profile%3][0]
    return {'method':'GET','urls':[url]*(3 if persistent else 1),'target_profile':profile%3,
            'usage':'persistent' if persistent else 'fresh','path_variant':'office_added_delay' if profile//6 else 'proxy_only',
            'between_visits_seconds':3 if persistent else 0,'browser_hold_seconds':8 if persistent else 2,
            'fitted_to_office_features':False}

def experiment_plan():
    return {'training_seed':TRAINING_SEED,'groups':[{'group_id':f'BENIGN_BROWSE_{c.upper()}|p{p}',
        'client':c,'profile':p,'path_variant':workload(p)['path_variant'],'usage':workload(p)['usage']} for c in ('chrome','curl') for p in range(12)],
        'capture_count':48,'free_disk_floor_bytes':20*GIB,'output_budget_bytes':OUTPUT_BUDGET,'pcap_limit_bytes':FILE_LIMIT,'all_process_file_limit_bytes':FILE_LIMIT,'watchdog_reserve_bytes':256<<20,
        'scope':'bounded actual public GETs through existing proxy; not observed office users; no production claim'}

def storage_guard(root,min_free_bytes=20*GIB,max_bytes=OUTPUT_BUDGET):
    root=Path(root);anchor=root if root.exists() else root.parent
    if shutil.disk_usage(anchor).free<min_free_bytes:raise ValueError('free disk below experiment floor')
    used=sum(p.stat().st_size for p in root.rglob('*') if p.is_file()) if root.exists() else 0
    if used>=max_bytes:raise ValueError('experiment output budget exhausted')
    return used

def watch_storage(root,stop,errors,halt,min_free_bytes=20*GIB+(256<<20),max_bytes=OUTPUT_BUDGET-(256<<20),interval=.25):
    while not stop.is_set():
        try:storage_guard(root,min_free_bytes,max_bytes)
        except Exception as exc:
            errors.append(str(exc));halt();return
        stop.wait(interval)

def validate_browser_evidence(root):
    from office_injection.source import sha256
    root=Path(root);pins=json.loads((root/'browser_trace_copy_pins.json').read_text());expected={f'chrome_p{p}/{a}/netlog.json' for p in range(12) for a in ('scenario','control')}
    if len(pins)!=24 or {r['path'] for r in pins}!=expected:raise ValueError('exact 24 canonical browser traces required')
    rows=[]
    for r in pins:
        path=root/'browser_evidence'/r['path'];profile=int(Path(r['path']).parts[0].split('_p')[1]);arm=Path(r['path']).parts[1]
        if r.get('source_sha256')!=r['sha256'] or sha256(path)!=r['sha256']:raise ValueError('browser raw/copy attestation failed')
        verify_browser_page(json.loads(path.read_text()),profile%3)
        receipt=json.loads((root/'captures'/f'chrome_p{profile}'/arm/'receipt.json').read_text());verify_receipt(receipt)
        if receipt['proof_pins']['netlog.json']!=r['sha256']:raise ValueError('receipt/browser evidence differs')
        proof=json.loads((root/'captures'/f'chrome_p{profile}'/arm/'page_proofs.json').read_text())
        if sha256(root/'captures'/f'chrome_p{profile}'/arm/'page_proofs.json')!=receipt['proof_pins']['page_proofs.json']:raise ValueError('page proof changed')
        if len(proof)!=len(workload(profile)['urls']) or any(q['ready']!='complete' or q['marker'] is not True for q in proof):raise ValueError('per-tab page content unproved')
        rows.append({'profile':profile,'arm':arm,'page_visits':len(proof),'target_http_status':200,'netlog_sha256':r['sha256']})
    return rows

def verify_receipt(r):
    expected=workload(r['profile'])
    if r['client'] not in ('chrome','curl'):raise ValueError('unknown ordinary client')
    if r['plan']!=expected or r['dataset_role']!='hard_negative':raise ValueError('activity plan/role differs')
    allowed=(0,-signal.SIGTERM) if r['client']=='chrome' and r.get('collector_stopped_browser') else (0,)
    if r['returncode'] not in allowed or r['requests_verified']!=len(expected['urls']):raise ValueError('incomplete page visits')
    if not r.get('certificate_checks_enabled') or not r.get('target_statuses') or any(s!=200 for s in r['target_statuses']):raise ValueError('target response/TLS unproved')
    if r['client']=='curl' and len(r['target_statuses'])!=len(expected['urls']):raise ValueError('partial curl transfer')
    if r['client']=='chrome' and len(expected['urls'])>1 and (r.get('distinct_tab_ids',0)!=len(expected['urls']) or r.get('page_content_proofs',0)!=len(expected['urls'])):raise ValueError('browser visit evidence missing')
    return True

def capture(out,helper,limit=None,start_profile=0):
    if out.exists():raise FileExistsError('retain existing capture output')
    if not Path('/.dockerenv').exists():raise ValueError('disposable container required')
    proxy=urlsplit(os.environ.get('https_proxy',''))
    if proxy.scheme!='http' or not proxy.hostname or proxy.username or proxy.password:raise ValueError('existing unauthenticated proxy required')
    proxy_url='http://'+socket.gethostbyname(proxy.hostname)+':'+str(proxy.port or 80)
    storage_guard(out);out.mkdir();helper.save(out/'PLAN.json',experiment_plan())
    helper.topology();helper.run('iptables','-t','nat','-A','POSTROUTING','-s','10.30.0.10/32','-o','eth0','-j','MASQUERADE')
    helper.run('ip','netns','exec','client','ip','route','add','default','via','10.30.0.20')
    receipts=[]
    def ns(args):return helper.namespace_args(['ip','netns','exec','client',*args])
    def cdp(path,method='GET'):
        return json.loads(subprocess.run(ns(['curl','--noproxy','*','--silent','--show-error','--fail','--max-time','2','--request',method,'http://127.0.0.1:9222'+path]),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True).stdout)
    try:
        tasks=[(c,p,a) for p in range(start_profile,12) for c in ('chrome','curl') for a in ('scenario','control')]
        if limit:tasks=tasks[:limit]
        for client,profile,arm in tasks:
            storage_guard(out,max_bytes=OUTPUT_BUDGET-(256<<20));plan=workload(profile);d=out/f'{client}_p{profile}'/arm;d.mkdir(parents=True)
            config=helper.path_config(profile%3,True,'office_path_v1')
            if plan['path_variant']=='proxy_only':config={**config,'path_rtt_ms':0}
            environment=helper.apply_path(config)
            def cap_limit():resource.setrlimit(resource.RLIMIT_FSIZE,(FILE_LIMIT,FILE_LIMIT))
            with (d/'tcpdump.log').open('wb') as log:
                dump=subprocess.Popen(['tcpdump','--immediate-mode','-i','labserver','-s','0','-U','-w',str(d/'capture.pcap'),'tcp'],stdout=subprocess.DEVNULL,stderr=log,preexec_fn=cap_limit,start_new_session=True)
            browser=None;curl=None;stop=threading.Event();errors=[]
            def halt():
                for proc in (browser,curl,dump):
                    if proc is not None and proc.poll() is None:
                        try:os.killpg(proc.pid,signal.SIGTERM)
                        except ProcessLookupError:pass
            watcher=threading.Thread(target=watch_storage,args=(out,stop,errors,halt),daemon=True);watcher.start();time.sleep(.2);started=time.time()
            try:
                if client=='curl':
                    cmd=['curl','--proxy',proxy_url,'--fail','--silent','--show-error','--location','--max-time','25','--rate','20/m','--write-out','%{json}\n']
                    for i,url in enumerate(plan['urls']):cmd+=['--output',str(d/f'response_{i}.html'),'--url',url]
                    with (d/'client.stderr').open('wb') as error:
                        curl=subprocess.Popen(ns(cmd),stdout=subprocess.PIPE,stderr=error,preexec_fn=cap_limit,start_new_session=True);output,_=curl.communicate(timeout=85)
                    (d/'curl_results.jsonl').write_bytes(output);infos=[json.loads(line) for line in output.splitlines()]
                    for i,info in enumerate(infos):
                        if info['url_effective']!=plan['urls'][i] or info['ssl_verify_result']!=0 or TARGETS[profile%3][1].encode() not in (d/f'response_{i}.html').read_bytes():raise ValueError('curl content/target/TLS failed')
                    receipt={'returncode':curl.returncode,'requests_verified':len(infos),'target_statuses':[i['http_code'] for i in infos],'certificate_checks_enabled':all(i['ssl_verify_result']==0 for i in infos)}
                else:
                    args=['google-chrome','--headless','--no-sandbox','--disable-dev-shm-usage','--disable-quic','--disable-background-networking','--disable-component-update','--no-first-run','--remote-debugging-port=9222','--proxy-server='+proxy_url,'--user-data-dir='+str(d/'browser_profile'),'--log-net-log='+str(d/'netlog.json'),'about:blank']
                    with (d/'client.stderr').open('wb') as error:browser=subprocess.Popen(ns(args),stdout=subprocess.DEVNULL,stderr=error,preexec_fn=cap_limit,start_new_session=True)
                    browser_info=helper.wait_for(lambda:cdp('/json/version'),seconds=12)
                    tabs=[]
                    for url in plan['urls']:
                        tabs.append(cdp('/json/new?'+quote(url,safe=':/'),'PUT'));time.sleep(plan['between_visits_seconds'] or 2)
                    time.sleep(plan['browser_hold_seconds']);listed=cdp('/json/list')
                    ids={t['id'] for t in tabs};visited={t['id'] for t in listed if t.get('url')==plan['urls'][0]}
                    if not ids<=visited:raise ValueError('target browser tabs not loaded')
                    proofs=[]
                    for tab in tabs:
                        result=subprocess.run(ns(['python3','/research_code/framework_runtime/benign_web/browser_control.py','--url',tab['webSocketDebuggerUrl'],'--marker',TARGETS[profile%3][1]]),stdout=subprocess.PIPE,check=True,timeout=10);proofs.append(json.loads(result.stdout))
                    helper.save(d/'page_proofs.json',proofs);helper.save(d/'tab_visits.json',tabs);subprocess.run(ns(['python3','/research_code/framework_runtime/benign_web/browser_control.py','--url',browser_info['webSocketDebuggerUrl']]),check=True,timeout=10);browser.wait(timeout=10)
                    verify_browser_page(json.loads((d/'netlog.json').read_text()),profile%3)
                    receipt={'returncode':browser.returncode,'collector_stopped_browser':True,'requests_verified':len(tabs),'distinct_tab_ids':len(ids),'page_content_proofs':len(proofs),'target_statuses':[200],'certificate_checks_enabled':True,'browser_cache_allowed':True,'network_response_proof':'target HTTP/2 stream 200; repeated visits may use browser cache'}
                receipt.update(client=client,profile=profile,arm=arm,plan=plan,environment=environment,dataset_role='hard_negative',started_at=started,ended_at=time.time(),office_equivalence_claim=False)
                if errors:raise ValueError('live disk guard: '+errors[0])
                helper.save(d/'ATTEMPT.json',receipt);verify_receipt(receipt);time.sleep(.2)
            finally:
                stop.set();watcher.join(timeout=2)
                if curl is not None and curl.poll() is None:curl.terminate();curl.wait(timeout=10)
                if browser is not None and browser.poll() is None:browser.terminate();browser.wait(timeout=10)
                if dump.poll() is None:dump.send_signal(signal.SIGINT)
                dump.wait(timeout=5)
            if errors:raise ValueError('live disk guard: '+errors[0])
            if dump.returncode!=0:raise ValueError('packet capture failed or file-size limit reached')
            receipt['capture_sha256']=helper.digest(d/'capture.pcap');receipt['proof_pins']={p.name:helper.digest(p) for p in d.iterdir() if p.is_file() and p.suffix in ('.json','.jsonl','.html')};helper.save(d/'receipt.json',receipt);receipts.append(receipt)
            print('CAPTURED',client,profile,arm,plan['usage'],plan['path_variant'],flush=True)
    finally:
        helper.CLIENT_NAMESPACE.terminate();helper.CLIENT_NAMESPACE.wait(timeout=5)
    storage_guard(out);helper.save(out/'COMPLETE.json',{'receipts':receipts,'capture_code_sha256':helper.digest(__file__),'helper_code_sha256':helper.digest('/adaptix_capture.py'),'plan_sha256':helper.digest(out/'PLAN.json'),'preflight_only':bool(limit),'component_code_sha256':{n:helper.digest(Path(__file__).parent/n) for n in ('browser_control.py','public_validation.py','public_capture.py')}})

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--limit',type=int);p.add_argument('--start-profile',type=int,choices=range(12),default=0);a=p.parse_args()
    spec=importlib.util.spec_from_file_location('helper','/adaptix_capture.py');helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    capture(a.out,helper,a.limit,a.start_profile)
