"""Bounded application decoding fixtures; payloads remain inert bytes."""
import hashlib,json,re,time
from pathlib import Path

LIMIT=65536


def decode_request(path,query,body,state):
    campaign=str(query.get('campaign',''));value=str(query.get('q',query.get('data',''))).encode()
    if len(body)>LIMIT or len(value)>LIMIT:raise ValueError('bounded payload exceeded')
    result={'complete':True,'bytes':len(value),'sha256':hashlib.sha256(value).hexdigest()}
    if path=='/bounded/fragment':
        total=int(query['total']);part=int(query['part'])
        if not 1<=total<=64 or not 0<=part<total:raise ValueError('invalid fragment index')
        frag=state.setdefault('fragment',{'total':total,'parts':{}})
        if frag['total']!=total:raise ValueError('fragment total changed')
        key=str(part)
        if key in frag['parts'] and frag['parts'][key]!=value.decode():raise ValueError('conflicting fragment duplicate')
        frag['parts'][key]=value.decode();complete=len(frag['parts'])==total
        whole=''.join(frag['parts'].get(str(i),'') for i in range(total)).encode()
        result.update(complete=complete,parts_received=len(frag['parts']),total=total,bytes=len(whole),sha256=hashlib.sha256(whole).hexdigest())
    elif path.startswith('/bounded/cloud/'):
        obj=query.get('object','')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',obj):raise ValueError('invalid fixed object key')
        objects=state.setdefault('objects',{})
        if len(objects)>64:raise ValueError('bounded object count exceeded')
        if path.endswith('/write'):objects[obj]=body.decode('ascii');value=body
        elif path.endswith('/read'):value=objects[obj].encode()
        else:raise ValueError('unknown cloud operation')
        result.update(data=value.decode(),bytes=len(value),sha256=hashlib.sha256(value).hexdigest(),operation=path.rsplit('/',1)[-1])
    elif path=='/bounded/rmm':
        phase=query.get('phase');allowed={'register','poll','interactive','idle'}
        if phase not in allowed:raise ValueError('unknown bounded state')
        previous=state.get('rmm','register');transitions={'register':{'register','poll'},'poll':{'poll','interactive'},'interactive':{'interactive','idle'},'idle':{'idle','poll'}}
        if phase not in transitions[previous]:raise ValueError('invalid state transition')
        state['rmm']=phase;value=body;result.update(state=phase,bytes=len(value),sha256=hashlib.sha256(value).hexdigest())
    elif path not in ('/bounded/lowentropy','/bounded/beacon','/bounded/plain','/bounded/front'):raise ValueError('unknown bounded fixture')
    elif path!='/bounded/lowentropy':
        value=body;result.update(bytes=len(value),sha256=hashlib.sha256(value).hexdigest())
    expected=query.get('sha256')
    if expected and result['complete'] and result['sha256']!=expected:raise ValueError('decoded SHA differs')
    return result


def server_answer(path,query,body,campaign):
    import fcntl
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',campaign):raise ValueError('invalid campaign')
    root=Path('/tmp/cover-application-store');root.mkdir(exist_ok=True);p=root/(campaign+'.json')
    with (root/(campaign+'.lock')).open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX);state=json.loads(p.read_text()) if p.exists() else {}
        answer=decode_request(path,{**query,'campaign':campaign},body,state);p.write_text(json.dumps(state))
        record={'ts':time.time(),'campaign_id':campaign,'path':path,**{k:v for k,v in answer.items() if k!='data'}}
        with Path('/out/application_receipts.jsonl').open('a') as f:f.write(json.dumps(record)+'\n')
    return answer


def install(sm,job):
    import random,urllib.parse
    original_http=sm._http_events;original_cloud=sm._cloud_events
    out=Path(job['container_output']);cid=job['job_id']
    supported={'M-HTTPS-FRAG','M-HTTPS-LOWENT','M-CLOUD-API','M-RMM-SHAPE','M-HTTPS-BEACON','M-HTTP-443','M-HTTPS-FRONT'}
    def run_events(spec,r,family=None):
        family=family or spec.family
        if family not in supported or family=='M-HTTPS-FRAG' and job['arm']=='control':return original_http(spec,r,family)
        events=[];expected=[];client=None
        if spec.client_impl.endswith('_reuse'):
            import httpx
            client=httpx.Client(verify=False,http2='h2' in spec.client_impl,timeout=10,trust_env=False)
        def exchange(path,body,method='POST'):
            host='plain-front.test' if family=='M-HTTP-443' else spec.front_host or 'cover-api.test'
            url=('http' if family=='M-HTTP-443' else 'https')+'://'+host+(':'+('443' if family=='M-HTTP-443' else '8443'))+path
            if client:
                reply=client.request(method,url,content=body);reply.read();status=int(reply.status_code);effective=spec.client_impl
            else:status,effective=sm._http_exchange(spec.client_impl,method,url,{'Content-Type':'application/octet-stream'},body,use_h2=(host=='cover-h2.test'))
            if status!=200:raise RuntimeError('bounded application receipt failed: '+str(status))
            return status,effective
        whole=''.join(random.Random(job['seed']+i).choice('abcdef0123456789') for i in range(spec.event_count*4)).encode()
        try:
            for i in range(spec.event_count):
                data=sm._payload(r,spec.payload_mode,i,32+(i%4)*24);started=sm.now_iso();path='/bounded/beacon';method='POST';wire=data
                if family=='M-HTTPS-FRAG':
                    wire=whole[i*4:(i+1)*4];path='/bounded/fragment?'+urllib.parse.urlencode({'part':i,'total':spec.event_count,'data':wire.decode()});method='GET';body=None
                elif family=='M-HTTPS-LOWENT':path='/bounded/lowentropy?'+urllib.parse.urlencode({'q':data.decode()});body=b'{"status":"ok"}'
                elif family=='M-CLOUD-API':path='/bounded/cloud/write?object=item-'+str(i);body=data
                elif family=='M-RMM-SHAPE':
                    phase='register' if i==0 else 'idle' if i==spec.event_count-1 else 'poll' if i<spec.event_count//2 else 'interactive'
                    path='/bounded/rmm?phase='+phase;body=data
                elif family=='M-HTTP-443':path='/bounded/plain';body=data
                elif family=='M-HTTPS-FRONT':path='/bounded/front';body=data
                else:body=data
                status,effective=exchange(path,body,method)
                expected.append({'event':i,'path':path.split('?')[0],'sha256':hashlib.sha256(whole if family=='M-HTTPS-FRAG' and i==spec.event_count-1 else wire).hexdigest(),
                    'complete_required':family!='M-HTTPS-FRAG' or i==spec.event_count-1})
                if family=='M-CLOUD-API':
                    status,effective=exchange('/bounded/cloud/read?object=item-'+str(i),None,'GET')
                    expected.append({'event':i,'path':'/bounded/cloud/read','sha256':hashlib.sha256(data).hexdigest(),'complete_required':True})
                events.append({'event_id':f'e{i:03d}','sent_at':started,'completed_at':sm.now_iso(),'http_method':method,'http_path':path,
                    'response_status':status,'effective_client_impl':effective,'encoded_length':len(wire),'bounded_mechanic':'actual_decode_v1'})
                sm._requested_sleep(spec,r,i)
        finally:
            if client:client.close()
        (out/'expected_receipts.json').write_text(json.dumps(expected,indent=2)+'\n')
        return events
    sm._http_events=run_events;sm._cloud_events=lambda spec,r:run_events(spec,r,'M-CLOUD-API')
    return {'version':'bounded_application_mechanics_v1','server_decoding':True,'control_fixture':job['arm']=='control','arbitrary_execution':False}
