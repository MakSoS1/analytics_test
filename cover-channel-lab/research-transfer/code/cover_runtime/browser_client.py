"""Genuine Chromium primitives with CDP completion, not process-exit evidence."""
import base64
from datetime import datetime,timezone
import math
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

SAFE_HOSTS={'cover-api.test','cover-h2.test','edge-front.test','cdn-front.test','workers-front.test',
            'graph-front.test','telegram-front.test','resolver-front.test','edge-ws.test','cover-ws.test',
            'benign-api.test','benign-chat.test','benign-market.test','benign-update.test','lots-chatops.test'}


def events_from_evidence(evidence,count):
    fields=('sent_times_ms','received_times_ms','sent_lengths','received_lengths')
    if evidence.get('received')!=count or any(len(evidence.get(k,[]))!=count for k in fields):
        raise ValueError('browser per-event timing evidence incomplete')
    result=[];previous=-math.inf
    for i,(sent,received,size,reply) in enumerate(zip(*(evidence[k] for k in fields))):
        if not all(isinstance(t,(int,float)) and math.isfinite(t) for t in (sent,received)) or sent<previous or received<sent:
            raise ValueError('browser event timestamps inconsistent')
        previous=sent
        def stamp(t):return datetime.fromtimestamp(t/1000,timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
        result.append({'event_id':f'e{i:03d}','event_type':'stage_m_wss_browser','sent_at':stamp(sent),'completed_at':stamp(received),
            'encoded_length':size,'reply_len':reply,'wss_client_impl':'chromium_websocket',
            'browser_received_count':count,'browser_adapter':'cdp_per_event_times_v2'})
    return result


def run_page(url, condition, timeout=35):
    from websockets.sync.client import connect
    parsed=urllib.parse.urlparse(url)
    if parsed.scheme!='https' or parsed.hostname not in SAFE_HOSTS or parsed.port!=8443:raise ValueError('browser local allowlist only')
    addresses=socket.getaddrinfo(parsed.hostname,parsed.port,type=socket.SOCK_STREAM)
    if any(not a[4][0].startswith('10.20.0.') for a in addresses):raise ValueError('browser fixture resolved outside laboratory')
    with tempfile.TemporaryDirectory(prefix='cover-cdp-') as profile:
        command=[os.environ['COVERLAB_CHROME'],'--headless=new','--no-sandbox','--disable-gpu',
                 '--ignore-certificate-errors','--disable-background-networking','--disable-component-update',
                 '--disable-sync','--disable-default-apps','--disable-extensions','--no-first-run',
                 '--disable-dev-shm-usage','--remote-debugging-address=127.0.0.1','--remote-debugging-port=9222',
                 '--user-data-dir='+profile,'about:blank']
        process=subprocess.Popen(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        try:
            deadline=time.monotonic()+timeout;endpoint=None
            while time.monotonic()<deadline:
                if process.poll() is not None:raise RuntimeError('Chromium exited before CDP readiness')
                try:
                    with urllib.request.urlopen('http://127.0.0.1:9222/json/version',timeout=1) as response:
                        endpoint=json.load(response)['webSocketDebuggerUrl']
                    break
                except OSError:time.sleep(.05)
            if not endpoint:raise TimeoutError('CDP readiness timeout')
            with connect(endpoint,proxy=None,open_timeout=5,max_size=4<<20) as ws:
                sequence=0
                def call(method,params=None,session=None):
                    nonlocal sequence
                    sequence+=1;message={'id':sequence,'method':method,'params':params or {}}
                    if session:message['sessionId']=session
                    ws.send(json.dumps(message))
                    while time.monotonic()<deadline:
                        r=json.loads(ws.recv(timeout=max(.1,deadline-time.monotonic())))
                        if r.get('id')!=sequence:continue
                        if 'error' in r:raise RuntimeError('CDP command failed: '+str(r['error']))
                        return r.get('result',{})
                    raise TimeoutError('CDP command timeout')
                target=call('Target.createTarget',{'url':'about:blank'})['targetId']
                session=call('Target.attachToTarget',{'targetId':target,'flatten':True})['sessionId']
                call('Page.enable',session=session)
                call('Page.navigate',{'url':url},session=session)
                while time.monotonic()<deadline:
                    response=call('Runtime.evaluate',{'expression':condition,'returnByValue':True},session)
                    if response.get('exceptionDetails'):raise RuntimeError('browser completion predicate failed')
                    value=response.get('result',{}).get('value')
                    if value:
                        result=call('Runtime.evaluate',{'expression':'JSON.stringify(window.__cover_evidence || {done:document.body.dataset.done})','returnByValue':True},session)
                        return json.loads(result['result']['value'])
                    time.sleep(.05)
                raise TimeoutError('browser application exchange did not complete')
        finally:
            try:os.killpg(process.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            time.sleep(.05)
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait()


def install_stage(sm):
    def http(url,method,body):
        u=urllib.parse.urlparse(url)
        fixture=f'https://{u.hostname}:8443/stage-m/http-fixture?'+urllib.parse.urlencode(
            {'target':u.path+('?' +u.query if u.query else ''),'method':method,'body':base64.urlsafe_b64encode(body or b'').decode()})
        evidence=run_page(fixture,"document.body && document.body.dataset.done === '1'")
        return 200,'browser_chromium'
    def wss(spec,seed,tunnel):
        scaled=spec.interval_seconds*float(os.environ.get('COVERLAB_STAGE_M_TIME_SCALE','0.001'))
        cap=os.environ.get('COVERLAB_STAGE_M_MAX_SLEEP_SECONDS','0.05')
        interval=min(scaled,float(cap)) if cap else scaled
        url='https://edge-front.test:8443/stage-m/ws-fixture?'+urllib.parse.urlencode(
            {'host':spec.front_host or sm.WSS_FRONT,'events':min(spec.event_count,20),'seed':seed,
             'mode':'tunnel' if tunnel else 'wss','interval':interval,'jitter':spec.jitter_fraction})
        evidence=run_page(url,'window.__cover_evidence && window.__cover_evidence.received === '+str(min(spec.event_count,20)),
                          timeout=max(35,interval*spec.event_count*1.6+20))
        return events_from_evidence(evidence,min(spec.event_count,20))
    sm._chromium_http=http;sm._chromium_wss=wss
