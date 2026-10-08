"""Bounded, disconnected HTTPS shape trial; no forwarding or covert data encoder.

Adapted from MakSoS1/analytics_test, pinned Stage M commit (see provenance).
Run on processor .18 using its isolated office_injection_v1 runtime.
"""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import random
import signal
import ssl
import statistics
import subprocess
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

COMMIT='1028b4a922c9b59e841fc71d58ae1df60ded6da4'

def run(args, **kwargs):
    return subprocess.run([str(x) for x in args],check=True,**kwargs)

def request_shape(arm,i):
    # Stage M _payload(low_entropy) and _http_events(M-HTTPS-LOWENT).
    rng=random.Random(100+i)
    values=(b'id=do',b'status=ok',b'cmd=1',str(uuid.UUID(int=rng.getrandbits(128))).encode())
    value=values[i%4]
    if arm=='control':value=b'x'*len(value)
    return '/stage-m/status?q='+value.decode(), b'{"status":"ok","id":"do"}'

def server(root):
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def do_POST(self):
            body=self.rfile.read(int(self.headers.get('Content-Length','0')))
            if not self.path.startswith('/stage-m/status?q=') or body!=b'{"status":"ok","id":"do"}':
                self.send_error(400);return
            data=json.dumps({'ok':True,'ts':int(time.time()),'value':'0123456789abcdef'},separators=(',',':')).encode()
            self.send_response(200);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(data)));self.send_header('Connection','close');self.end_headers();self.wfile.write(data)
            with (root/'server_events.jsonl').open('a') as f:
                f.write(json.dumps({'ts':time.time(),'path':self.path,'body_sha256':hashlib.sha256(body).hexdigest(),'status':200})+'\n')
        def log_message(self,*args):pass
    http=HTTPServer(('10.203.0.2',8443),Handler)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(root/'cert.pem',root/'key.pem')
    http.socket=ctx.wrap_socket(http.socket,server_side=True);http.serve_forever()

def extract(runtime,root,arm):
    folder=root/arm;stage=folder/'rows';stage.mkdir()
    python=Path(sys.executable)
    log=(folder/'extract.log').open('w')
    def execute(args):run([python,*args],stdout=log,stderr=subprocess.STDOUT)
    rows=stage/'capture.pkts';pay=stage/'capture.pay'
    execute([runtime/'export_full_packets.py','--pcap',folder/'capture.pcap','--out',rows,'--payload-out',pay,'--salt-file',root/'salt'])
    from office_injection.payload import downgrade
    downgrade(pay,1) # Existing office corpus has availability v1.
    execute([runtime/'extract_office_sessions.py','--pcap-dir',stage,'--glob','*.pkts','--min-packets','1','--salt-file',root/'salt','--out-sessions',folder/'raw.csv','--out-lots-conns',folder/'lots.csv','--session-index',folder/'index.csv','--stats-json',folder/'stats.json','--finalize'])
    (folder/'live.csv').write_text('ip_a,port_a,ip_b,port_b,proto,seg_start\n')
    execute([runtime/'merge_payload_sidecars.py','--sidecar-dir',stage,'--session-index',folder/'index.csv','--out-csv',folder/'payload.csv','--live',folder/'live.csv','--pending-out',folder/'pending.pkl'])
    execute([runtime/'finalize_tables.py','--sessions',folder/'raw.csv','--payload',folder/'payload.csv','--lots-conns-in',folder/'lots.csv','--out-sessions',folder/'office_sessions.csv','--out-lots-conns',folder/'office_lots_conns.csv'])
    with (folder/'office_sessions.csv').open() as f:items=list(csv.DictReader(f))
    labels=[{'session_uid':r['session_uid'],'segment_uid':r['segment_uid'],'arm':arm,'scenario':'M-HTTPS-LOWENT-shape' if arm=='scenario' else 'matched-static-HTTPS-control','label_scope':'synthetic_application_shape','production_training_ready':False} for r in items]
    (folder/'labels.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in labels))
    return items

def compare(groups,office_paths):
    csv.field_size_limit(1<<26)
    office=[];seen=0;rng=random.Random(17)
    for path in office_paths:
        with path.open() as f:
            for row in csv.DictReader(f):
                # Comparable observed TLS/TCP subset; office remains unlabelled.
                if row.get('proto')!='tcp' or float(row.get('tls_sni_len') or 0)<=0:continue
                seen+=1
                if len(office)<4000:office.append(row)
                else:
                    k=rng.randrange(seen)
                    if k<4000:office[k]=row
    groups['office_tls']=office
    def flag(row,key):return str(row.get(key,'')).lower() in ('1','true','1.0')
    for key in ('scenario','control','office_tls'):
        groups[key+'_complete']=[r for r in groups[key] if flag(r,'start_observed') and not flag(r,'truncated_at_capture_end')]
    observation={key:{'start_observed':sum(flag(r,'start_observed') for r in rows),'capture_end_truncated':sum(flag(r,'truncated_at_capture_end') for r in rows)} for key,rows in groups.items()}
    names=['tcp_handshake_rtt_ms','flow_duration','pkt_count','up_bytes','down_bytes','tls_sni_len','tls_cipher_count','tls_ext_count','tls_alpn_http11','dest_port']
    out={'counts':{k:len(v) for k,v in groups.items()},'office_tls_total':seen,'observation_flags':observation,'metrics':{},'production_training_ready':False,'interpretation':'Single-VM isolated TLS shape experiment; office source and labels remain confounded. No office naturalness or FPR claim.'}
    for name in names:
        out['metrics'][name]={}
        for key,rows in groups.items():
            vals=[]
            for row in rows:
                try:vals.append(float(row[name]))
                except (KeyError,ValueError,TypeError):pass
            if vals:out['metrics'][name][key]={'n':len(vals),'p50':statistics.median(vals),'min':min(vals),'max':max(vals)}
    return out

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--server',action='store_true');p.add_argument('--office-csv',type=Path,action='append',default=[])
    args=p.parse_args();root=args.out.resolve()
    if args.server:return server(root)
    root.mkdir(parents=True,exist_ok=False);runtime=Path(__file__).resolve().parents[1]
    (root/'salt').write_bytes(os.urandom(32));(root/'salt').chmod(0o600)
    namespace='httrial-'+uuid.uuid4().hex[:8];client=namespace+'c';srv=namespace+'s';process=None;capture=None
    run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',root/'key.pem','-out',root/'cert.pem','-days','1','-subj','/CN=cover-api.test'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    (root/'provenance.json').write_text(json.dumps({'repository':'MakSoS1/analytics_test','commit':COMMIT,'source_functions':['stage_m._payload','stage_m._http_events','run_campaign.execute_http(curl_linux)'],'adaptations':['stdlib TLS server instead of nginx reverse proxy; fixed JSON marker','six requests per arm; five seconds between requests; no CI time acceleration','control replaces query value with equal-length static x characters','new captures; disconnected two namespaces on one VM; no netem'],'role':'defensive synthetic shape trial; no arbitrary message encoder'},indent=2))
    try:
        for ns in (client,srv):run(['sudo','ip','netns','add',ns])
        run(['sudo','ip','link','add','trialc','type','veth','peer','name','trials'])
        for ns,interface,address in ((client,'trialc','10.203.0.1/30'),(srv,'trials','10.203.0.2/30')):
            run(['sudo','ip','link','set',interface,'netns',ns]);run(['sudo','ip','-n',ns,'addr','add',address,'dev',interface]);run(['sudo','ip','-n',ns,'link','set',interface,'up']);run(['sudo','ip','-n',ns,'link','set','lo','up'])
        process=subprocess.Popen(['sudo','ip','netns','exec',srv,sys.executable,__file__,'--server','--out',str(root)])
        time.sleep(1)
        if process.poll() is not None:raise RuntimeError('fixture server failed')
        groups={}
        for arm in ('scenario','control'):
            folder=root/arm;folder.mkdir()
            with (folder/'capture.log').open('w') as log:
                capture=subprocess.Popen(['sudo','ip','netns','exec',srv,'tcpdump','--immediate-mode','-U','-s','0','-i','trials','-Z',os.environ['USER'],'-w',str(folder/'capture.pcap'),'tcp port 8443'],stdout=log,stderr=log)
                time.sleep(1)
                with (folder/'requests.jsonl').open('w') as journal:
                    for i in range(6):
                        path,body=request_shape(arm,i);start=time.time()
                        result=run(['sudo','ip','netns','exec',client,'curl','--noproxy','*','-ksS','--max-time','10','--resolve','cover-api.test:8443:10.203.0.2','-o','/dev/null','-w','%{http_code}','-X','POST','-H','User-Agent: Mozilla/5.0','-H','Accept: application/json','-H','X-Lab-Profile: stage-m','-H','Content-Type: application/json','--data-binary','@-',f'https://cover-api.test:8443{path}'],input=body,stdout=subprocess.PIPE)
                        if result.stdout!=b'200':raise RuntimeError('unexpected HTTPS response')
                        journal.write(json.dumps({'event':i,'start':start,'end':time.time(),'status':200,'request_body_sha256':hashlib.sha256(body).hexdigest()})+'\n');journal.flush()
                        if i<5:time.sleep(5)
                time.sleep(1)
                capture_ids=subprocess.check_output(['sudo','ip','netns','pids',srv],text=True).split()
                capture_ids=[pid for pid in capture_ids if Path('/proc',pid,'comm').read_text().strip()=='tcpdump']
                if len(capture_ids)!=1:raise RuntimeError('Expected exactly one owned capture process')
                run(['sudo','kill','-INT',*capture_ids]);capture.wait(timeout=10);capture=None
            groups[arm]=extract(runtime,root,arm)
            if len(groups[arm])!=6:raise RuntimeError('Expected six observed transport sessions per arm')
        report=compare(groups,args.office_csv);(root/'comparison.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
    finally:
        for ns in (client,srv):
            ids=subprocess.run(['sudo','ip','netns','pids',ns],capture_output=True,text=True).stdout.split()
            if ids:subprocess.run(['sudo','kill','-TERM',*ids],check=False)
            subprocess.run(['sudo','ip','netns','del',ns],check=False)

if __name__=='__main__':main()
