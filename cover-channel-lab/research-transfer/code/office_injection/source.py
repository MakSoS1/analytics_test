"""Conservative Stage M slices: reject cross-campaign transport instances."""
from __future__ import annotations
import bisect
import hashlib
import ipaddress
import json
import math
import struct
from collections import defaultdict
from datetime import datetime
from pathlib import Path


def sha256(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        while b:=f.read(1<<20):h.update(b)
    return h.hexdigest()


def read_pcap(path,max_regression=0):
    with Path(path).open('rb') as f:
        head=f.read(24)
        if len(head)!=24:raise ValueError('truncated pcap header')
        magic=head[:4]
        if magic==b'\xd4\xc3\xb2\xa1':endian='<';scale=1e6
        elif magic==b'\xa1\xb2\xc3\xd4':endian='>';scale=1e6
        elif magic==b'\x4d\x3c\xb2\xa1':endian='<';scale=1e9
        elif magic==b'\xa1\xb2\x3c\x4d':endian='>';scale=1e9
        else:raise ValueError('classic pcap required')
        if struct.unpack(endian+'I',head[20:24])[0]!=1:raise ValueError('Ethernet PCAP required')
        last=-math.inf
        while h:=f.read(16):
            if len(h)!=16:raise ValueError('truncated pcap record')
            sec,frac,cap,orig=struct.unpack(endian+'IIII',h)
            if cap!=orig or cap>262144:raise ValueError('truncated or oversized frame')
            data=f.read(cap)
            if len(data)!=cap:raise ValueError('truncated frame')
            ts=sec+frac/scale
            if ts<last-max_regression:raise ValueError('PCAP timestamp regression')
            last=max(last,ts);yield ts,data


def write_pcap(path,frames,offset=0):
    with Path(path).open('wb') as f:
        f.write(struct.pack('<IHHiIII',0xa1b2c3d4,2,4,0,0,262144,1))
        for ts,data in frames:
            us=round((ts+offset)*1e6)
            if us<0:raise ValueError('negative timestamp')
            sec,frac=divmod(us,1000000)
            f.write(struct.pack('<IIII',sec,frac,len(data),len(data)));f.write(data)


def transport(frame):
    if len(frame)<14:return None
    eth=struct.unpack_from('!H',frame,12)[0];off=14
    while eth in (0x8100,0x88a8):
        if len(frame)<off+4:return None
        eth=struct.unpack_from('!H',frame,off+2)[0];off+=4
    if eth==0x800 and len(frame)>=off+20:
        ihl=(frame[off]&15)*4
        if ihl<20 or struct.unpack_from('!H',frame,off+6)[0]&0x3fff:return None
        proto=frame[off+9];a=str(ipaddress.ip_address(frame[off+12:off+16]));b=str(ipaddress.ip_address(frame[off+16:off+20]));l4=off+ihl
    elif eth==0x86dd and len(frame)>=off+40:
        proto=frame[off+6];a=str(ipaddress.ip_address(frame[off+8:off+24]));b=str(ipaddress.ip_address(frame[off+24:off+40]));l4=off+40
    else:return None
    if proto not in (6,17) or len(frame)<l4+(20 if proto==6 else 8):return None
    sp,dp=struct.unpack_from('!HH',frame,l4);flags=frame[l4+13] if proto==6 else 0
    endpoints=tuple(sorted(((a,sp),(b,dp))))
    return {'key':(*endpoints,proto),'src':a,'dst':b,'flags':flags,'proto':proto}


def epoch(value):return datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()


def slice_campaigns(pcap,campaign_manifest,out_dir,expected_sha256,limit=12):
    if sha256(pcap)!=expected_sha256:raise ValueError('source PCAP SHA256 mismatch')
    rows=[json.loads(x) for x in Path(campaign_manifest).read_text().splitlines() if x.strip()]
    rows.sort(key=lambda c:epoch(c['started_at']))
    if not rows or any(c.get('metadata_revision',0)<2 or c.get('positive_only') is not True or
                       c.get('label_binary')!=1 or c.get('status')!='success' for c in rows):
        raise ValueError('corrected successful positive contract required')
    starts=[epoch(c['started_at']) for c in rows]
    ends=[epoch(c['ended_at']) for c in rows]
    # Whole transport instances: do not truncate at campaign timestamp boundaries.
    live={};flows=[]
    for ts,frame in read_pcap(pcap,max_regression=0.00001):
        p=transport(frame)
        if not p:continue
        key=p['key'];bare=p['proto']==6 and p['flags']&0x12==2
        old=live.get(key)
        if old and ((bare and old['closed']) or ts-old['frames'][-1][0]>(30 if p['proto']==17 else 10)):
            flows.append(old);old=None
        if old is None:
            old={'frames':[],'key':key,'syn':bare,'closed':False};live[key]=old
        old['frames'].append((ts,frame))
        old['closed']|=bool(p['flags']&5)
    flows.extend(live.values());selected=defaultdict(list);rejected=0
    for flow in flows:
        a=flow['frames'][0][0];b=flow['frames'][-1][0]
        if any(y[0]<x[0] for x,y in zip(flow['frames'],flow['frames'][1:])):
            rejected+=1;continue
        # Millisecond campaign bounds: strict inner containment avoids boundary ambiguity.
        candidates=[i for i in range(len(rows))
                    if starts[i]<=a and b<ends[i] and
                    rows[i]['source_ip'] in (flow['key'][0][0],flow['key'][1][0])]
        if len(candidates)!=1 or (flow['key'][2]==6 and not flow['syn']):rejected+=1;continue
        i=candidates[0]
        # Reject any overlap with another campaign from the same source endpoint.
        if any(j!=i and rows[j]['source_ip']==rows[i]['source_ip'] and starts[j]<b and ends[j]>a
               for j in range(len(rows))):rejected+=1;continue
        selected[i].extend(flow['frames'])
    root=Path(out_dir);root.mkdir(parents=True,exist_ok=True);catalog=[]
    for i,frames in selected.items():
        c=rows[i]
        if c.get('channel_mechanism')=='timing':continue
        frames.sort(key=lambda x:x[0]);duration=frames[-1][0]-frames[0][0]
        if duration<=0 or duration>30:continue
        path=root/(c['campaign_id']+'.pcap');write_pcap(path,frames)
        catalog.append({'campaign_id':c['campaign_id'],'technique':c['scenario_id'],'path':str(path),
                        'duration':duration,'source_start':frames[0][0],'packets':len(frames),
                        'sha256':sha256(path),'parent_campaign_id':c.get('parent_campaign_id') or c['campaign_id'],
                        'training_eligible':c.get('training_eligible',False),
                        'timing_training_eligible':c.get('timing_training_eligible',False),
                        'timing_fidelity':c.get('timing_fidelity'),'netem_profile':c.get('netem_profile'),
                        'membership':'whole_transport_instance_inside_unique_campaign',
                        'slice_scope':'transport_session_positive_campaign','source_pcap_sha256':expected_sha256,'source_reorder_policy':'interflow<=10us;intraflow_rejected'})
        if len(catalog)>=limit:break
    if not catalog:raise ValueError('no unambiguous complete campaign transport slices')
    (root/'catalog.json').write_text(json.dumps({'campaigns':catalog,'rejected_flows':rejected,
        'source_campaigns':len(rows),'role':'challenge_only'},indent=2)+'\n')
    return catalog
