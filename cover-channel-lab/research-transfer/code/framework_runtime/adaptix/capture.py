"""Bounded Adaptix research capture. Run only inside the isolated lab image.

The API task surface is deliberately restricted to reading known synthetic files.
No CLI option accepts a target, command, credential, or host path to read.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import signal
import ssl
import struct
import subprocess
import time
import urllib.request

CLIENT_NAMESPACE = None


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def runtime_command(output, script, name, path_profile='lab_fixed_v1'):
    command = ['docker', 'run', '--name', name, '--network', 'none', '--cap-add', 'NET_ADMIN',
            '--cap-add', 'NET_RAW', '--cap-add', 'SYS_ADMIN', '-v', str(output)+':/capture',
            '-v', str(script)+':/capture_code.py:ro']
    if path_profile == 'office_path_v1':
        environment = Path(__file__).resolve().parents[2] / 'cover_runtime/environment.py'
        command += ['--security-opt=apparmor=unconfined', '-v', str(environment)+':/path_environment.py:ro']
    elif path_profile != 'lab_fixed_v1':
        raise ValueError('unknown path profile')
    return command + ['cover-adaptix-isolated:20261004-v4',
            '/capture_code.py', '--out', '/capture', '--path-profile', path_profile]


def path_config(profile, tls, path_profile):
    if profile not in (0, 1, 2):
        raise ValueError('undeclared workload')
    if path_profile == 'lab_fixed_v1':
        return {'path_profile':path_profile, 'client_mtu':1500,
                'client_tcp_timestamps':True, 'path_rtt_ms':(8,36,70)[profile]}
    if path_profile != 'office_path_v1':
        raise ValueError('unknown path profile')
    try:
        from cover_runtime.environment import office_path
    except ImportError:
        from path_environment import office_path
    return office_path('ADAPTIX_GOPHER_'+('MTLS' if tls else 'TCP'), 'p'+str(profile), 20261004)


def apply_path(config):
    mtu = config['client_mtu']
    for prefix, dev in (([], 'labserver'), (['ip','netns','exec','client'], 'labclient')):
        run(*(prefix+['ip','link','set','dev',dev,'mtu',str(mtu)]))
        run(*(prefix+['tc','qdisc','replace','dev',dev,'root','netem','delay',str(config['path_rtt_ms']/2)+'ms']))
        actual = json.loads(run(*(prefix+['ip','-j','link','show','dev',dev])))[0]
        if actual['mtu'] != mtu:raise RuntimeError('MTU readback failed')
    run('mount','-o','remount,rw','/proc/sys')
    try:
        run('ip','netns','exec','client','sysctl','-w','net.ipv4.tcp_timestamps='+str(int(config['client_tcp_timestamps'])))
    finally:
        run('mount','-o','remount,ro','/proc/sys')
    value=run('ip','netns','exec','client','sysctl','-n','net.ipv4.tcp_timestamps').decode().strip()
    if value != str(int(config['client_tcp_timestamps'])):raise RuntimeError('timestamp readback failed')
    return {**config, 'mtu_readback_verified':True, 'tcp_timestamps_readback_verified':True,
            'office_equivalence_claim':False}


def workload(profile):
    if profile not in (0, 1, 2):
        raise ValueError('only three predeclared synthetic workloads')
    delays = ((2, 3, 5, 3, 8, 4), (2, 6, 3, 9, 4, 6), (3, 5, 8, 3, 7, 5))[profile]
    return [{'command': 'cat', 'path': f'/fixture/item_{i}.txt', 'delay': delay}
            for i, delay in enumerate(delays)]


def verify_results(expected, rows):
    for command, content in expected.items():
        matches = [r for r in rows if r.get('a_cmdline') == command and r.get('a_completed')]
        if len(matches) != 1 or matches[0].get('a_text', '').strip() != content.strip():
            raise ValueError('missing, duplicate, incomplete or incorrect task result: '+command)
    return True


def syn_options(options):
    """Preserve observed path facts; never infer MSS from the largest frame."""
    result = {'mss': None, 'window_scale': None, 'timestamps': False, 'sack_permitted': False}
    pos = 0
    while pos < len(options):
        kind = options[pos]
        if kind == 0:
            break
        if kind == 1:
            pos += 1
            continue
        if pos + 2 > len(options) or options[pos+1] < 2 or pos + options[pos+1] > len(options):
            raise ValueError('malformed TCP options')
        length = options[pos+1]
        if kind == 2 and length == 4:
            result['mss'] = struct.unpack_from('!H', options, pos+2)[0]
        elif kind == 3 and length == 3:
            result['window_scale'] = options[pos+2]
        elif kind == 8 and length == 10:
            result['timestamps'] = True
        elif kind == 4 and length == 2:
            result['sack_permitted'] = True
        pos += length
    return result


def verify_wire(path, tasks, end):
    raw=Path(path).read_bytes()
    if len(raw)<24:raise ValueError('missing PCAP header')
    if raw[:4]!=b'\xd4\xc3\xb2\xa1' or struct.unpack_from('<I',raw,20)[0]!=1:
        raise ValueError('expected microsecond Ethernet PCAP')
    records=[];offset=24;observed_syn=[];frame_lengths=[];previous_tick=None;timestamp_ties=0
    while offset<len(raw):
        if len(raw)-offset<16:raise ValueError('truncated PCAP record')
        sec,usec,size,original=struct.unpack_from('<IIII',raw,offset);offset+=16
        frame=raw[offset:offset+size];offset+=size
        if len(frame)!=size or size!=original or frame[12:14]!=b'\x08\x00':raise ValueError('invalid capture frame')
        if size>1514:raise ValueError('Ethernet MTU exceeded; possible transport offload artifact')
        ihl=(frame[14]&15)*4;tcp=14+ihl
        if frame[23]!=6 or len(frame)<tcp+20:raise ValueError('unexpected wire transport')
        source='.'.join(str(v) for v in frame[26:30]);target='.'.join(str(v) for v in frame[30:34])
        if {source,target}!={'10.30.0.10','10.30.0.20'}:raise ValueError('foreign capture endpoints')
        header=(frame[tcp+12]>>4)*4;length=struct.unpack_from('!H',frame,16)[0]-ihl-header
        if header < 20 or tcp+header > len(frame) or length < 0 or usec >= 1000000:
            raise ValueError('invalid TCP header or timestamp')
        tick=sec*1000000+usec
        timestamp_ties += previous_tick == tick
        previous_tick=tick
        frame_lengths.append(size)
        if frame[tcp+13]&2:
            observed_syn.append({'side':'client' if source=='10.30.0.10' else 'server',
                'syn_ack':bool(frame[tcp+13]&16),'ip_header_bytes':ihl,'tcp_header_bytes':header,
                'window':struct.unpack_from('!H',frame,tcp+14)[0],
                **syn_options(frame[tcp+20:tcp+header])})
        records.append({'timestamp':sec+usec/1e6,'source':source,'flags':frame[tcp+13],'payload_length':length})
    if len(records)<10 or records[0]['source']!='10.30.0.10' or records[0]['flags']&0x12!=2:
        raise ValueError('missing whole initiating TCP flow')
    counts=[]
    for i,task in enumerate(tasks):
        start=task['at']-.05;stop=tasks[i+1]['at'] if i+1<len(tasks) else end
        window=[r for r in records if start<=r['timestamp']<=stop and r['payload_length']>0]
        directions={s:sum(r['source']==s for r in window) for s in ('10.30.0.10','10.30.0.20')}
        if not all(directions.values()):raise ValueError('task exchange not observed on wire')
        counts.append(directions)
    return {'packet_count':len(records),'first':records[0]['timestamp'],'last':records[-1]['timestamp'],
            'task_exchange_packets':counts,'whole_flow_syn':True,'ethernet_mtu_verified':True,
            'path_observation':{'timestamp_resolution_ns':1000,'adjacent_timestamp_ties':timestamp_ties,
                'frame_length_min':min(frame_lengths),'frame_length_max':max(frame_lengths),
                'syn_options':observed_syn,'mss_inferred_from_frame_size':False}}


def run(*args):
    return subprocess.run(namespace_args(args), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def namespace_args(args):
    if list(args[:4]) == ['ip','netns','exec','client']:
        if CLIENT_NAMESPACE is None:raise RuntimeError('client namespace absent')
        return ['nsenter','-t',str(CLIENT_NAMESPACE.pid),'-n',*args[4:]]
    return list(args)


def save(path, data):
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n')


def certs(root):
    root.mkdir()
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'ca.key'),
        '-out',str(root/'ca.pem'),'-days','2','-subj','/CN=DisposableResearchCA')
    for name, san in (('server','IP:127.0.0.1,IP:10.30.0.20'), ('client','IP:10.30.0.10')):
        run('openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(root/(name+'.key')),
            '-out',str(root/(name+'.csr')),'-subj','/CN=DisposableResearch'+name)
        (root/(name+'.ext')).write_text('subjectAltName='+san+'\n')
        run('openssl','x509','-req','-in',str(root/(name+'.csr')),'-CA',str(root/'ca.pem'),
            '-CAkey',str(root/'ca.key'),'-CAcreateserial','-out',str(root/(name+'.pem')),
            '-days','2','-extfile',str(root/(name+'.ext')))


def api(path, data=None, token=None, context=None):
    headers={'Content-Type':'application/json'}
    if token: headers['Authorization']='Bearer '+token
    req=urllib.request.Request('https://127.0.0.1:4321/endpoint/'+path,
        data=json.dumps(data).encode() if data is not None else None, headers=headers)
    with urllib.request.urlopen(req, context=context, timeout=180) as response:
        result=json.load(response)
    if isinstance(result,dict) and result.get('ok') is False:
        raise ValueError('framework API failure: '+str(result.get('message'))[:500])
    return result


def wait_for(fn, seconds=40):
    deadline=time.monotonic()+seconds
    last=None
    while time.monotonic()<deadline:
        try:
            value=fn()
            if value:return value
        except Exception as exc: last=exc
        time.sleep(.5)
    raise TimeoutError('bounded wait expired: '+str(last))


def topology():
    # No default route; no host interfaces or host network namespace involved.
    global CLIENT_NAMESPACE
    CLIENT_NAMESPACE=subprocess.Popen(['unshare','--net','sleep','3600'])
    time.sleep(.2)
    if CLIENT_NAMESPACE.poll() is not None:raise RuntimeError('client namespace failed')
    if Path(f'/proc/{CLIENT_NAMESPACE.pid}/ns/net').readlink()==Path('/proc/self/ns/net').readlink():
        raise RuntimeError('client namespace was not isolated')
    run('ip','link','add','labserver','type','veth','peer','name','labclient')
    run('ip','link','set','labclient','netns',str(CLIENT_NAMESPACE.pid))
    run('ip','addr','add','10.30.0.20/24','dev','labserver')
    run('ip','link','set','labserver','up')
    run('ip','netns','exec','client','ip','addr','add','10.30.0.10/24','dev','labclient')
    for dev in ('lo','labclient'):run('ip','netns','exec','client','ip','link','set',dev,'up')
    offload={}
    for prefix,dev in (([], 'labserver'), (['ip','netns','exec','client'], 'labclient')):
        run(*(prefix+['ethtool','-K',dev,'gro','off','gso','off','tso','off']))
        features=run(*(prefix+['ethtool','-k',dev])).decode()
        for name in ('generic-receive-offload','generic-segmentation-offload','tcp-segmentation-offload'):
            if name+': off' not in features:raise ValueError('transport offload remains enabled')
        offload[dev]=features
    routes=run('ip','netns','exec','client','ip','route').decode()
    if 'default' in routes:raise ValueError('isolated client has a default route')
    return {'routes':routes,'offload':offload}


def capture_arm(out, profile, tls, arm, certificates, context, password, path_profile='lab_fixed_v1'):
    directory=out/f'{"mtls" if tls else "tcp"}_p{profile}'/arm
    directory.mkdir(parents=True)
    environment=apply_path(path_config(profile,tls,path_profile))
    rtt=environment['path_rtt_ms']
    tasks=workload(profile)
    values={t['path']:('fixture_'+str(i)+'_'+('sample-data-'*((16,128,512)[profile])))
            for i,t in enumerate(tasks)}
    fixture=Path('/fixture');fixture.mkdir(exist_ok=True)
    for name, text in values.items():Path(name).write_text(text)
    processes=[]
    receipts={'framework':'Adaptix','source_commit':'e99535c9ef4642190f7ea125c2983d1611f1a3f3',
        'transport':'mtls' if tls else 'tcp','profile':profile,'arm':arm,'rtt_ms_requested':rtt,
        'path_environment':environment,
        'task_schedule':tasks,'fixture_sha256':{p:hashlib.sha256(v.encode()).hexdigest() for p,v in values.items()},
        'started_at':time.time(),'verified':False}
    log=(directory/'runtime.log').open('wb')
    tcpdump=None
    try:
        if arm=='scenario':
            token=api('login',{'username':'research','password':password,'version':'research'}, context=context)['access_token']
            conf={'host_bind':'10.30.0.20','port_bind':8443,'callback_addresses':'10.30.0.20:8443',
                'encrypt_key':secrets.token_hex(16),'ssl':tls,'timeout':60,'tcp_banner':'','error_answer':''}
            for field, filename in (('ca_cert','ca.pem'),('server_cert','server.pem'),('server_key','server.key'),
                                    ('client_cert','client.pem'),('client_key','client.key')):
                conf[field]=base64.b64encode((certificates/filename).read_bytes()).decode()
            listener='lab_'+str(profile)+('_mtls' if tls else '_tcp')
            api('listener/create',{'name':listener,'type':'GopherTCP','config':json.dumps(conf)},token,context)
            payload=api('agent/generate',{'listener_name':[listener],'agent':'gopher',
                'config':json.dumps({'os':'linux','arch':'amd64','format':'Binary .ELF',
                                    'reconn_timeout':'2','reconn_count':1,'win7_support':False})},token,context)
            agent=Path('/tmp/lab-agent')
            agent.write_bytes(base64.b64decode(payload['message'].split(':',1)[1],validate=True));agent.chmod(0o700)
            receipts['agent_sha256']=digest(agent)
        else:
            server=subprocess.Popen(['/framework/telemetry','server',str(tls).lower(),str(certificates)],stdout=log,stderr=log)
            processes.append(server);time.sleep(.5)
        tcpdump=subprocess.Popen(['tcpdump','--immediate-mode','-i','labserver','-U','-s','0','-w',str(directory/'capture.pcap'),
            'host','10.30.0.10','and','tcp','port','8443'],stdout=log,stderr=log)
        def capture_ready():
            if tcpdump.poll() is not None:raise RuntimeError('tcpdump exited before capture')
            return b'listening on labserver' in (directory/'runtime.log').read_bytes()
        wait_for(capture_ready,5)
        if arm=='scenario':
            before={r['a_id'] for r in (api('agent/list',token=token,context=context) or [])}
            process=subprocess.Popen(namespace_args(['ip','netns','exec','client',str(agent)]),stdout=log,stderr=log)
            processes.append(process)
            row=wait_for(lambda: next((r for r in (api('agent/list',token=token,context=context) or []) if r['a_id'] not in before),None))
            agent_id=row['a_id'];receipts['registration']=row
            expected={}
            for task in tasks:
                time.sleep(task['delay']);command='cat '+task['path'];expected[command]=values[task['path']];sent=time.time()
                answer=api('agent/command/execute',{'id':agent_id,'ui':False,'cmdline':command,
                    'data':json.dumps({'command':'cat','path':task['path']}),'wait_answer':True},token,context)
                receipts.setdefault('submitted',[]).append({'cmdline':command,'api':answer,'at':sent})
            def completed():
                rows=api('agent/task/list?agent_id='+agent_id+'&limit=100',token=token,context=context)
                try:verify_results(expected,rows)
                except ValueError:return None
                return rows
            receipts['completed_tasks']=wait_for(completed)
            receipts['verified']=verify_results(expected,receipts['completed_tasks'])
            process.terminate();process.wait(timeout=5)
            # Release port before matched control; do not leave listeners active.
            api('listener/stop',{'name':listener,'type':'GopherTCP'},token,context)
        else:
            schedule=directory/'telemetry_schedule.json'
            save(schedule,[{'delay':t['delay'],'data':values[t['path']]} for t in tasks])
            client=subprocess.Popen(namespace_args(['ip','netns','exec','client','/framework/telemetry','client',str(tls).lower(),
                str(certificates),str(schedule)]),stdout=subprocess.PIPE,stderr=log)
            processes.append(client);client.wait(timeout=90)
            if client.returncode:raise ValueError('telemetry control failed')
            stdout=client.stdout.read();client.stdout.close()
            (directory/'telemetry_acknowledgements.jsonl').write_bytes(stdout)
            acknowledgements=[json.loads(line) for line in stdout.splitlines()]
            if len(acknowledgements)!=len(tasks):raise ValueError('telemetry acknowledgement count differs')
            for task,ack in zip(tasks,acknowledgements):
                if not ack['verified'] or ack['sha256']!=hashlib.sha256(values[task['path']].encode()).hexdigest() or ack['ack_at']<ack['at']:
                    raise ValueError('telemetry acknowledgement identity differs')
            receipts['verified']=True
            receipts['submitted']=acknowledgements
            receipts['control_semantics']='ordinary client-pushed telemetry with server SHA256 acknowledgements; not an idle C2 agent'
        time.sleep(1)
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()
        if tcpdump is not None:
            tcpdump.send_signal(signal.SIGINT);tcpdump.wait(timeout=5)
        log.close();receipts['ended_at']=time.time()
        if (directory/'capture.pcap').exists():receipts['capture_sha256']=digest(directory/'capture.pcap')
        if receipts['verified']:
            try:
                if tcpdump.returncode!=0:raise ValueError('tcpdump did not shut down successfully')
                text=(directory/'runtime.log').read_text(errors='replace')
                import re
                drops=re.search(r'(\d+) packets dropped by kernel',text)
                if drops is None or int(drops.group(1))!=0:raise ValueError('capture drops missing or nonzero')
                receipts['wire_verification']=verify_wire(directory/'capture.pcap',receipts['submitted'],receipts['ended_at'])
                syn=receipts['wire_verification']['path_observation']['syn_options']
                client=[s for s in syn if s['side']=='client' and not s['syn_ack']]
                if not client or any(s['mss'] != environment['client_mtu']-40 or s['timestamps'] != environment['client_tcp_timestamps'] for s in client):
                    raise ValueError('declared client path differs from captured SYN')
                if receipts['wire_verification']['path_observation']['frame_length_max'] > environment['client_mtu']+14:
                    raise ValueError('captured frame exceeds declared path MTU')
                receipts['wire_verification']['kernel_drops']=int(drops.group(1))
            except Exception:
                receipts['verified']=False;save(directory/'receipt.json',receipts);raise
        save(directory/'receipt.json',receipts)
    if not receipts['verified']:raise ValueError('unverified capture retained')
    return receipts


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--path-profile',choices=('lab_fixed_v1','office_path_v1'),default='lab_fixed_v1')
    args=parser.parse_args();out=args.out
    if not Path('/.dockerenv').exists():raise RuntimeError('isolated Docker runtime required')
    if any(out.iterdir()):raise FileExistsError('new empty capture directory required')
    topology_routes=topology()
    certificates=Path('/tmp/research-certs');certs(certificates)
    password=secrets.token_urlsafe(32)
    import yaml
    profile=yaml.safe_load(Path('/src/AdaptixServer/profile.yaml').read_text())
    profile['Teamserver'].update(interface='127.0.0.1',password=password,operators={'research':password},
        cert=str(certificates/'server.pem'),key=str(certificates/'server.key'),
        extenders=['extenders/gopher_listener_tcp/config.yaml','extenders/gopher_agent/config.yaml'])
    profile['HttpServer']['error']['page']='/src/AdaptixServer/404page.html'
    Path('/framework/profile.yaml').write_text(yaml.safe_dump(profile))
    context=ssl.create_default_context(cafile=str(certificates/'ca.pem'))
    with (out/'teamserver.log').open('wb') as log:
        server=subprocess.Popen(['/framework/adaptixserver','-profile','/framework/profile.yaml'],cwd='/framework',stdout=log,stderr=log)
        try:
            wait_for(lambda: api('login',{'username':'research','password':password,'version':'research'},context=context),60)
            receipts=[]
            for tls in (False,True):
                for profile in range(3):
                    for arm in ('scenario','control'):
                        receipts.append(capture_arm(out,profile,tls,arm,certificates,context,password,args.path_profile))
                        print(json.dumps({k:receipts[-1][k] for k in ('transport','profile','arm','verified')}),flush=True)
            save(out/'COMPLETE.json',{'receipts':receipts,'client_routes':topology_routes,
                'runtime_network':'none','production_training_ready':False})
        finally:
            server.terminate();server.wait(timeout=10)
            if CLIENT_NAMESPACE is not None:
                CLIENT_NAMESPACE.terminate();CLIENT_NAMESPACE.wait(timeout=5)


if __name__=='__main__':main()
