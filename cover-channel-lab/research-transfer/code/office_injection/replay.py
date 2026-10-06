"""Bounded replay on a private Linux namespace. No production interfaces accepted."""
from __future__ import annotations
import getpass
import json
import signal
import subprocess
import time
import uuid
from collections import Counter
from pathlib import Path
from .source import read_pcap,sha256


def match_capture(source,observed):
    expected=list(read_pcap(source));actual=list(read_pcap(observed,max_regression=0.00001))
    ec=Counter(frame for _,frame in expected);ac=Counter(frame for _,frame in actual)
    missing=sum((ec-ac).values());unknown=sum((ac-ec).values())
    # Packet order must be preserved within every transport flow.
    from .source import transport
    seq=lambda frames:[(transport(f)['key'],sha256_bytes(f)) for _,f in frames if transport(f)]
    es={};rs={}
    for k,h in seq(expected):es.setdefault(str(k),[]).append(h)
    for k,h in seq(actual):rs.setdefault(str(k),[]).append(h)
    ordered=es==rs
    times={};monotone=True
    for ts,frame in actual:
        p=transport(frame)
        if p:
            key=p['key']
            if key in times and ts<times[key]:monotone=False
            times[key]=ts
    return {'expected_packets':len(expected),'rx_packets':len(actual),'missing_packets':missing,
            'unknown_or_duplicate_packets':unknown,'per_flow_order_preserved':ordered,
            'per_flow_time_monotone':monotone,'passed':missing==0 and unknown==0 and ordered and monotone,'tcp_stack_adapted':False,
            'source_duration':expected[-1][0]-expected[0][0] if expected else 0,
            'rx_duration':max(t for t,_ in actual)-min(t for t,_ in actual) if actual else 0}


def sha256_bytes(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def replay(pcap,out_dir,expected_sha256,max_duration=35,min_free_gb=2):
    import shutil
    pcap=Path(pcap).resolve();root=Path(out_dir).resolve()
    if sha256(pcap)!=expected_sha256:raise ValueError('replay source hash mismatch')
    frames=list(read_pcap(pcap))
    if not frames or frames[-1][0]-frames[0][0]>max_duration-3:raise ValueError('replay duration budget exceeded')
    if any(len(f)>65000 for _,f in frames):raise ValueError('replay MTU unsupported')
    root.mkdir(parents=True,exist_ok=False)
    if shutil.disk_usage(root).free<min_free_gb*2**30:raise ValueError('replay disk budget exceeded')
    ns='ccinj-'+uuid.uuid4().hex[:12]
    def call(*args):return subprocess.run(['sudo','-n',*args],check=True,capture_output=True,text=True,timeout=15)
    proc=None;capture_log=root/'capture.log';rx=root/'rx.pcap'
    try:
        call('ip','netns','add',ns)
        call('ip','-n',ns,'link','add','tx0','type','veth','peer','name','rx0')
        call('ip','netns','exec',ns,'sysctl','-q','-w','net.ipv6.conf.all.disable_ipv6=1')
        for iface in ('tx0','rx0'):call('ip','-n',ns,'link','set',iface,'mtu','65535','up')
        addresses=call('ip','-n',ns,'-j','addr','show').stdout
        if any(x.get('addr_info') for x in json.loads(addresses)):raise ValueError('namespace unexpectedly has IP addresses')
        with capture_log.open('w') as log:
            proc=subprocess.Popen(['sudo','-n','ip','netns','exec',ns,'tcpdump','-i','rx0','-s','0',
                                   '--immediate-mode','-U','-Z',getpass.getuser(),'-w',str(rx)],stdout=log,stderr=log)
            deadline=time.monotonic()+5
            while 'listening on' not in capture_log.read_text():
                if proc.poll() is not None:raise RuntimeError('capture failed: '+capture_log.read_text())
                if time.monotonic()>deadline:raise TimeoutError('capture readiness timed out')
                time.sleep(0.05)
            result=subprocess.run(['sudo','-n','ip','netns','exec',ns,'tcpreplay','--intf1=tx0',str(pcap)],
                                   capture_output=True,text=True,timeout=max_duration)
            (root/'tcpreplay.log').write_text(result.stdout+result.stderr)
            if result.returncode:raise RuntimeError('tcpreplay failed; see tcpreplay.log')
            time.sleep(0.15)
            for pid in call('ip','netns','pids',ns).stdout.split():call('kill','-INT',pid)
            proc.wait(timeout=5)
        report=match_capture(pcap,rx)
        report.update({'source_sha256':expected_sha256,'rx_sha256':sha256(rx),'namespace':ns,
                       'mode':'isolated_original_speed','production_network_connected':False})
        (root/'replay.json').write_text(json.dumps(report,indent=2)+'\n')
        if not report['passed']:raise RuntimeError('RX membership failed; partial capture retained')
        return rx,report
    finally:
        if proc is not None and proc.poll() is None:
            for pid in call('ip','netns','pids',ns).stdout.split():
                try:call('kill','-TERM',pid)
                except subprocess.CalledProcessError:pass
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:pass
        subprocess.run(['sudo','-n','ip','netns','del',ns],capture_output=True,timeout=15)
