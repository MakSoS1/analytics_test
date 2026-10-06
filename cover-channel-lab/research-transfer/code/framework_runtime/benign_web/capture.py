"""Ordinary fixed HTTPS fixtures, never a claim of real office user behavior.

Run in a Docker network-none container with a private client network namespace.
No targets, commands, host files or credentials are accepted as task arguments.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import random
import signal
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CLIENTS=('chrome','curl','python')


def workload(profile):
    if profile not in (0,1,2):raise ValueError('only three declared fixtures')
    return {'download_bytes':(65536,262144,1048576)[profile],
            'upload_bytes':(4096,32768,131072)[profile], 'polls':3,
            'poll_delays_seconds':[1,2,3], 'fitted_to_office':False}


def verify_receipt(rows,plan,upload_hash):
    if not any(r['method']=='GET' and r['path']=='/download' and r['bytes']==plan['download_bytes'] for r in rows):
        raise ValueError('download not served completely')
    if not any(r['method']=='POST' and r['path']=='/upload' and r['bytes']==plan['upload_bytes'] and r.get('sha256')==upload_hash for r in rows):
        raise ValueError('upload not received or hash differs')
    if not any(r['method']=='POST' and r['path']=='/done' for r in rows):raise ValueError('client did not confirm completion')
    uploads=[i for i,r in enumerate(rows) if r['method']=='POST' and r['path']=='/upload']
    completions=[i for i,r in enumerate(rows) if r['method']=='POST' and r['path']=='/done']
    polls=[i for i,r in enumerate(rows) if r['method']=='GET' and r['path']=='/status']
    if len(uploads)!=1 or len(completions)!=1 or len(polls)!=plan['polls'] or not uploads[0]<polls[0]<=polls[-1]<completions[0]:
        raise ValueError('missing, duplicated or out-of-order status polling')
    previous=float(rows[uploads[0]].get('at',float('nan')))
    for i,delay in zip(polls,plan['poll_delays_seconds']):
        stamp=float(rows[i].get('at',float('nan')))
        if not math.isfinite(previous) or not math.isfinite(stamp) or stamp-previous<delay-.25:
            raise ValueError('status polling accelerated or timestamps unavailable')
        previous=stamp
    return True


def save(p,v):Path(p).write_text(json.dumps(v,indent=2)+'\n')


def capture(directory,client,profile,arm,helper):
    directory.mkdir(parents=True,exist_ok=False);plan=workload(profile)
    rng=random.Random(1701+profile)
    content=rng.randbytes(plan['download_bytes']);upload=bytes(i%251 for i in range(plan['upload_bytes']))
    upload_hash=hashlib.sha256(upload).hexdigest();rows=[];done=threading.Event()
    html=('''<!doctype html><title>Research file portal</title><h1>File portal</h1>
<script>async function run(){try{await (await fetch('/download')).arrayBuffer();
let a=new Uint8Array(UPLOAD);for(let i=0;i<a.length;i++)a[i]=i%251;
await fetch('/upload',{method:'POST',body:a});
for(let d of [1,2,3]){await new Promise(r=>setTimeout(r,d*1000));await fetch('/status');}
await fetch('/done',{method:'POST'});document.body.dataset.complete='yes';}
catch(e){document.body.textContent=String(e)}}run();</script>''').replace('UPLOAD',str(plan['upload_bytes'])).encode()
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*args):pass
        def reply(self,data,kind):
            self.send_response(200);self.send_header('Content-Type',kind)
            self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data);self.wfile.flush()
            rows.append({'method':'GET','path':self.path,'bytes':len(data),'at':time.time()})
        def do_GET(self):
            if self.path=='/':self.reply(html,'text/html')
            elif self.path=='/download':self.reply(content,'application/octet-stream')
            elif self.path=='/status':self.reply(b'{"status":"ok"}','application/json')
            else:self.send_error(404)
        def do_POST(self):
            n=int(self.headers.get('Content-Length',0));b=self.rfile.read(n)
            if self.path=='/upload' and (n!=len(upload) or hashlib.sha256(b).hexdigest()!=upload_hash):
                self.send_error(400);return
            if self.path not in ('/upload','/done'):self.send_error(404);return
            rows.append({'method':'POST','path':self.path,'bytes':n,'sha256':hashlib.sha256(b).hexdigest(),'at':time.time()})
            self.send_response(200);self.send_header('Content-Length','0');self.end_headers()
            if self.path=='/done':done.set()
    server=ThreadingHTTPServer(('10.30.0.20',8443),Handler)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain('/fixture/server.pem','/fixture/server.key')
    ctx.set_alpn_protocols(['http/1.1']);server.socket=ctx.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    config=helper.path_config(profile,True,'office_path_v1');environment=helper.apply_path(config)
    pcap=directory/'capture.pcap';dump=subprocess.Popen(['tcpdump','--immediate-mode','-i','labserver','-U','-s','0','-w',str(pcap),'tcp','port','8443'],stdout=subprocess.DEVNULL,stderr=(directory/'tcpdump.log').open('wb'))
    time.sleep(.3);proc=None
    try:
        base='https://files.research.test:8443'
        if client=='chrome':
            args=['google-chrome','--headless','--no-sandbox','--disable-dev-shm-usage','--disable-background-networking',
                  '--disable-component-update','--no-first-run','--no-proxy-server','--ignore-certificate-errors',
                  '--host-resolver-rules=MAP files.research.test 10.30.0.20',
                  '--user-data-dir='+str(directory/'browser_profile'),base+'/']
            proc=subprocess.Popen(helper.namespace_args(['ip','netns','exec','client',*args]),stdout=(directory/'client.log').open('wb'),stderr=subprocess.STDOUT)
        else:
            script=directory/'client.py'
            script.write_text('''import ssl,urllib.request,time,subprocess,sys
client=sys.argv[1];size=int(sys.argv[2]);upload=bytes(i%251 for i in range(size))
base='https://files.research.test:8443'
def req(path,data=None):
 if client=='curl':
  args=['curl','--fail','--silent','--show-error','--noproxy','*','--resolve','files.research.test:8443:10.30.0.20','--cacert','/fixture/server.pem',base+path]
  if data is not None:args+=['--data-binary','@-']
  return subprocess.run(args,input=data,check=True,stdout=subprocess.PIPE).stdout
 with urllib.request.urlopen(urllib.request.Request(base+path,data=data),context=ssl.create_default_context(cafile='/fixture/server.pem'),timeout=10) as r:return r.read()
assert len(req('/download'))==DOWNLOAD
req('/upload',upload)
for delay in [1,2,3]:time.sleep(delay);req('/status')
req('/done',b'')
'''.replace('DOWNLOAD',str(plan['download_bytes'])))
            proc=subprocess.Popen(helper.namespace_args(['ip','netns','exec','client','python3',str(script),client,str(len(upload))]),stdout=(directory/'client.log').open('wb'),stderr=subprocess.STDOUT)
        if not done.wait(35):raise RuntimeError('ordinary client completion timed out; inspect retained client.log')
        if client!='chrome' and proc.wait(timeout=5)!=0:raise ValueError('client failed')
        verify_receipt(rows,plan,upload_hash);time.sleep(.3)
    finally:
        if proc is not None and proc.poll() is None:proc.terminate();proc.wait(timeout=10)
        dump.send_signal(signal.SIGINT);dump.wait(timeout=5)
        server.shutdown();server.server_close();thread.join(timeout=3)
    if dump.returncode!=0:raise ValueError('capture failed')
    receipt={'version':'ordinary-web-v1','client':client,'profile':profile,'arm':arm,'dataset_role':'hard_negative',
        'workload':plan,'requests':rows,'download_sha256':hashlib.sha256(content).hexdigest(),'upload_sha256':upload_hash,
        'application_exchange_verified':True,'environment':environment,'capture_sha256':helper.digest(pcap),
        'office_equivalence_claim':False,'scope':'real client stack with synthetic ordinary application fixtures; not observed office usage'}
    save(directory/'receipt.json',receipt);return receipt


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    if Path('/.dockerenv').exists() is False:raise RuntimeError('run only in isolated Docker image')
    if a.out.exists() and any(a.out.iterdir()):raise FileExistsError('retain existing capture output')
    import importlib.util
    spec=importlib.util.spec_from_file_location('helper','/adaptix_capture.py');helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    a.out.mkdir(parents=True,exist_ok=True);helper.topology()
    routes=helper.run('ip','netns','exec','client','ip','route').decode()
    if 'default' in routes:raise ValueError('client namespace must have no uplink')
    # Only this disposable container's hosts file is edited.
    with open('/etc/hosts','a') as f:f.write('\n10.30.0.20 files.research.test\n')
    root=Path('/fixture');root.mkdir(exist_ok=True)
    helper.run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'server.key'),'-out',str(root/'server.pem'),'-days','2','-subj','/CN=files.research.test','-addext','subjectAltName=DNS:files.research.test')
    receipts=[]
    try:
        for client in CLIENTS:
            for profile in range(3):
                for arm in ('scenario','control'):
                    receipts.append(capture(a.out/f'{client}_p{profile}'/arm,client,profile,arm,helper))
                    print('CAPTURED',client,profile,arm,flush=True)
    finally:
        helper.CLIENT_NAMESPACE.terminate();helper.CLIENT_NAMESPACE.wait(timeout=5)
    save(a.out/'COMPLETE.json',{'receipts':receipts,'capture_code_sha256':helper.digest(__file__),
                              'helper_code_sha256':helper.digest('/adaptix_capture.py')})

if __name__=='__main__':main()
