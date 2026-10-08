"""Declared HTTP/2 clients must negotiate HTTP/2; no host-alias substitution."""
import json
from pathlib import Path


def requires_h2(client,use_h2):return use_h2 or client in ('python_httpx_h2','python_httpx_h2_reuse')


def install(sm,job):
    import httpx
    original=sm._http_exchange
    request_original=httpx.Client.request
    out=Path(job['container_output'])
    install_node_cadence(sm,out)
    def observed_request(self,method,url,*args,**kwargs):
        reply=request_original(self,method,url,*args,**kwargs)
        with (out/'http_protocol_receipts.jsonl').open('a') as f:f.write(json.dumps({'url':str(url),'client':job['profile']['client'],'http_version':reply.http_version,'status':reply.status_code})+'\n')
        if job['profile']['client'] in ('python_httpx_h2','python_httpx_h2_reuse') and str(url).startswith('https:') and reply.http_version!='HTTP/2':raise RuntimeError('declared HTTPS H2 profile negotiated '+reply.http_version)
        return reply
    httpx.Client.request=observed_request
    def exchange(client,method,url,headers,body,use_h2=False):
        if client=='python_httpx_h2':
            with httpx.Client(verify=False,http2=True,timeout=15,trust_env=False) as requester:
                reply=requester.request(method,url,headers=headers,content=body);reply.read()
                if url.startswith('https:') and reply.http_version!='HTTP/2':raise RuntimeError('declared H2 profile negotiated '+reply.http_version)
                with (out/'http_protocol_receipts.jsonl').open('a') as f:f.write(json.dumps({'url':url,'client':client,'http_version':reply.http_version,'status':reply.status_code})+'\n')
                return reply.status_code,client
        status,effective=original(client,method,url,headers,body,use_h2)
        if client in ('curl_linux','node_fetch','go_nethttp','python_stdlib','java_httpclient','rust_reqwest','browser_chromium') and effective!=client:
            raise RuntimeError('generic client fallback forbidden: '+client+'->'+effective)
        return status,effective
    sm._http_exchange=exchange


def patch_node_source(source):
    replacements={
        "const mode=arg('--mode','wss');":"const mode=arg('--mode','wss'); const interval=Number(arg('--interval','0')); const jitter=Number(arg('--jitter','0')); const scale=Number(arg('--scale','1')); const cap=Number(arg('--cap','0')); const sentTimes=[]; let sendIndex=0;",
        "const timer=setTimeout(()=>reject(new Error('stage-m raw Node WSS timeout')),30000);":"const timer=setTimeout(()=>reject(new Error('stage-m raw Node WSS timeout')),Math.max(30000,events*interval*scale*(1+jitter)*1000+30000));",
        "      for(let i=0;i<events;i++){":"      function sendNext(){ const i=sendIndex++;",
        "        socket.write(maskedTextFrame(JSON.stringify(msg)));":"        sentTimes[i]=Date.now(); socket.write(maskedTextFrame(JSON.stringify(msg))); if(i+1<events){const requested=interval*scale*(1+jitter*(2*parseInt(token(i),16)/4294967296-1)); setTimeout(sendNext,1000*(cap>0?Math.min(cap,requested):requested));}",
        "      }\n    }else{":"      } sendNext();\n    }else{",
        "sent_at:new Date(started).toISOString()":"sent_at:new Date(sentTimes[received]).toISOString()",
    }
    for old,new in replacements.items():
        if source.count(old)!=1:raise RuntimeError('Node cadence patch source changed')
        source=source.replace(old,new)
    return source


def install_node_cadence(sm,out):
    import hashlib,os
    path=Path(sm.__file__).resolve().parents[2]/'clients/stage_m_ws_client.mjs'
    backup=path.with_suffix('.source-original')
    if not backup.exists():backup.write_text(path.read_text())
    original=backup.read_text();patched=patch_node_source(original);path.write_text(patched)
    (out/'node_cadence_patch.json').write_text(json.dumps({'original_sha256':hashlib.sha256(original.encode()).hexdigest(),'patched_sha256':hashlib.sha256(patched.encode()).hexdigest(),'reason':'actual per-event native/accelerated Node WSS cadence and send-time receipts'})+'\n')
    original_wss=sm._node_wss
    def node_wss(spec,seed,tunnel):
        run_original=sm.subprocess.run
        def run(cmd,*args,**kwargs):
            if isinstance(cmd,list) and 'stage_m_ws_client.mjs' in str(cmd):
                cmd=cmd+['--interval',str(spec.interval_seconds),'--jitter',str(spec.jitter_fraction),'--scale',os.environ.get('COVERLAB_STAGE_M_TIME_SCALE','0.001'),'--cap',os.environ.get('COVERLAB_STAGE_M_MAX_SLEEP_SECONDS','0.05') or '0']
                kwargs['timeout']=max(120,spec.event_count*spec.interval_seconds*(1+spec.jitter_fraction)+30)
            return run_original(cmd,*args,**kwargs)
        sm.subprocess.run=run
        try:return original_wss(spec,seed,tunnel)
        finally:sm.subprocess.run=run_original
    sm._node_wss=node_wss
