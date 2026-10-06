"""Bounded public-page reads through an existing unauthenticated HTTP proxy.

No uploads, logins, arbitrary targets or commands. Disposable bridge container
and its own client netns only; all captures are legitimate hard negatives.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
from urllib.parse import urlsplit

TARGETS=(('https://example.org/','Example Domain'),('https://docs.python.org/3/','Python'),('https://www.wikipedia.org/','Wikipedia'))

def plan(profile):
    if profile not in range(len(TARGETS)):raise ValueError('only three fixed public pages')
    return {'url':TARGETS[profile][0],'marker':TARGETS[profile][1],'method':'GET','fitted_to_office':False}

def verify_receipt(r):
    p=plan(r['profile'])
    if r['returncode']!=0 or r['bytes']<=200 or not r['marker_found']:raise ValueError('page read incomplete')
    if r['client']=='curl':
        if r['http_code']!=200 or r['ssl_verify_result']!=0 or r['effective_url']!=p['url']:
            raise ValueError('public response/status/TLS verification failed')
    elif r['client']=='chrome':
        if not r.get('response_200_observed') or not r.get('certificate_checks_enabled'):raise ValueError('browser response not verified')
    else:raise ValueError('unknown client')
    return True

def capture(out,helper):
    if out.exists():raise FileExistsError('retain existing public captures')
    if not Path('/.dockerenv').exists():raise ValueError('disposable container required')
    proxy=urlsplit(os.environ.get('https_proxy',''))
    if proxy.scheme!='http' or not proxy.hostname or proxy.username or proxy.password:raise ValueError('existing unauthenticated HTTP proxy required')
    proxy_ip=socket.gethostbyname(proxy.hostname);proxy_url='http://'+proxy_ip+':'+str(proxy.port or 80)
    helper.topology()
    if helper.run('sysctl','-n','net.ipv4.ip_forward').decode().strip()!='1':raise ValueError('container forwarding unavailable')
    helper.run('iptables','-t','nat','-A','POSTROUTING','-s','10.30.0.10/32','-o','eth0','-j','MASQUERADE')
    helper.run('ip','netns','exec','client','ip','route','add','default','via','10.30.0.20')
    out.mkdir();receipts=[]
    try:
        for client in ('curl','chrome'):
            for profile in range(3):
                for arm in ('scenario','control'):
                    d=out/f'{client}_p{profile}'/arm;d.mkdir(parents=True);p=plan(profile)
                    environment=helper.apply_path(helper.path_config(profile,True,'office_path_v1'))
                    dump=subprocess.Popen(['tcpdump','--immediate-mode','-i','labserver','-s','0','-U','-w',str(d/'capture.pcap'),'tcp'],stdout=subprocess.DEVNULL,stderr=(d/'tcpdump.log').open('wb'))
                    time.sleep(.2);start=time.time()
                    try:
                        if client=='curl':
                            cmd=['curl','--proxy',proxy_url,'--fail','--silent','--show-error','--location','--max-time','25','--output',str(d/'response.html'),'--write-out','%{json}',p['url']]
                        else:
                            cmd=['google-chrome','--headless','--no-sandbox','--disable-dev-shm-usage','--disable-quic','--disable-background-networking','--disable-component-update','--no-first-run','--proxy-server='+proxy_url,'--user-data-dir='+str(d/'browser_profile'),'--log-net-log='+str(d/'netlog.json'),'--dump-dom',p['url']]
                        with (d/'client.stderr').open('wb') as error:
                            proc=subprocess.run(helper.namespace_args(['ip','netns','exec','client',*cmd]),stdout=subprocess.PIPE,stderr=error,timeout=35)
                        if client=='chrome':(d/'response.html').write_bytes(proc.stdout)
                        body=(d/'response.html').read_bytes() if (d/'response.html').exists() else b''
                        receipt={'client':client,'profile':profile,'arm':arm,'returncode':proc.returncode,'bytes':len(body),'marker_found':p['marker'].encode() in body,'started_at':start,'ended_at':time.time(),'plan':p,'environment':environment,'proxy_in_use':True,'proxy_authenticated':False,'dataset_role':'hard_negative','office_equivalence_claim':False,'scope':'actual public server response through an existing HTTP proxy; not direct Internet or observed office usage'}
                        if client=='curl':
                            info=json.loads(proc.stdout);receipt.update(http_code=info['http_code'],ssl_verify_result=info['ssl_verify_result'],effective_url=info['url_effective'],http_version=info['http_version'])
                        else:
                            log=json.loads((d/'netlog.json').read_text());headers=[str(e.get('params',{}).get('headers','')) for e in log['events']]
                            receipt.update(response_200_observed=any(':status: 200' in h or 'HTTP/1.1 200' in h or 'HTTP/2 200' in h for h in headers),certificate_checks_enabled=True)
                        verify_receipt(receipt);receipt['response_sha256']=helper.digest(d/'response.html')
                        time.sleep(.3)
                    finally:
                        dump.send_signal(signal.SIGINT);dump.wait(timeout=5)
                    if dump.returncode!=0:raise ValueError('public packet capture failed')
                    receipt['capture_sha256']=helper.digest(d/'capture.pcap');helper.save(d/'receipt.json',receipt);receipts.append(receipt)
                    print('CAPTURED',client,profile,arm,flush=True)
    finally:
        helper.CLIENT_NAMESPACE.terminate();helper.CLIENT_NAMESPACE.wait(timeout=5)
    helper.save(out/'COMPLETE.json',{'receipts':receipts,'capture_code_sha256':helper.digest(__file__),'helper_code_sha256':helper.digest('/adaptix_capture.py'),'scope':'12 independent bounded public-page reads, no credentials or uploads'})

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    spec=importlib.util.spec_from_file_location('helper','/adaptix_capture.py');helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    capture(a.out,helper)
