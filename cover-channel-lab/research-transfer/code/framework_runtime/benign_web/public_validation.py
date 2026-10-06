"""Independently verify the target HTTP/2 response, not a proxy/background 200."""
import json
from pathlib import Path
from urllib.parse import urlsplit
from .public_capture import plan
from office_injection.source import sha256

def verify_browser_page(log,profile):
    url=urlsplit(plan(profile)['url']);path=url.path or '/'
    types={v:k for k,v in log['constants']['logEventTypes'].items()};requested=set()
    for event in log['events']:
        if types.get(event['type'])!='HTTP2_SESSION_SEND_HEADERS':continue
        p=event.get('params',{});h=p.get('headers',[])
        if ':method: GET' in h and ':authority: '+url.netloc in h and ':path: '+path in h:
            requested.add((event['source']['id'],p.get('stream_id')))
    for event in log['events']:
        if types.get(event['type'])!='HTTP2_SESSION_RECV_HEADERS':continue
        p=event.get('params',{})
        if (event['source']['id'],p.get('stream_id')) in requested and ':status: 200' in p.get('headers',[]):return True
    raise ValueError('target HTTP/2 200 not observed; CONNECT/background responses do not qualify')

def validate_browser_evidence(root):
    root=Path(root);pins=json.loads((root/'browser_trace_copy_pins.json').read_text());rows=[]
    expected={f'chrome_p{p}/{a}/netlog.json' for p in range(3) for a in ('scenario','control')}
    if len(pins)!=6 or {r['path'] for r in pins}!=expected:raise ValueError('exact six canonical browser capture identities required')
    for r in pins:
        p=root/'browser_evidence'/r['path']
        if r.get('source_sha256')!=r['sha256']:raise ValueError('source-to-copy hash attestation differs')
        if sha256(p)!=r['sha256']:raise ValueError('browser trace copy changed')
        parts=Path(r['path']).parts
        profile=int(parts[0].split('_p')[1]);arm=parts[1]
        if profile not in range(3) or arm not in ('scenario','control'):raise ValueError('unexpected browser evidence identity')
        verify_browser_page(json.loads(p.read_text()),profile)
        rows.append({'client':'chrome','profile':profile,'arm':arm,'target_url':plan(profile)['url'],'target_http_status':200,'netlog_sha256':r['sha256']})
    return rows
