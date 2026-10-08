"""Loss-accounted wire evidence; unsupported carriers remain research rows."""
from __future__ import annotations
import hashlib
import ipaddress
import json
import struct
from pathlib import Path
from .source import read_pcap, sha256, epoch
from .cover_registry import digest

VERSION='cover-wire-observation-v1'


def _header(frame):
    row={'supported':False, 'reason':'non_ip_or_short'}
    if len(frame)<14:return row
    eth=struct.unpack_from('!H',frame,12)[0];off=14
    while eth in (0x8100,0x88a8):
        if len(frame)<off+4:return row
        eth=struct.unpack_from('!H',frame,off+2)[0];off+=4
    if eth==0x800 and len(frame)>=off+20:
        ihl=(frame[off]&15)*4
        if ihl<20 or len(frame)<off+ihl:return row
        row.update(src=str(ipaddress.ip_address(frame[off+12:off+16])),dst=str(ipaddress.ip_address(frame[off+16:off+20])),
                   ipv4_id=struct.unpack_from('!H',frame,off+4)[0],proto=frame[off+9])
        frag=struct.unpack_from('!H',frame,off+6)[0]&0x3fff
        if frag:return {**row,'reason':'ip_fragment'}
        l4=off+ihl;ipend=min(len(frame),off+struct.unpack_from('!H',frame,off+2)[0])
    elif eth==0x86dd and len(frame)>=off+40:
        row.update(src=str(ipaddress.ip_address(frame[off+8:off+24])),dst=str(ipaddress.ip_address(frame[off+24:off+40])),proto=frame[off+6]);l4=off+40
        ipend=min(len(frame),l4+struct.unpack_from('!H',frame,off+4)[0])
    else:return row
    proto=row['proto']
    if proto==1 and len(frame)>=l4+8:
        row.update(icmp_type=frame[l4],icmp_id=struct.unpack_from('!H',frame,l4+4)[0],icmp_sequence=struct.unpack_from('!H',frame,l4+6)[0],reason='icmp_research_carrier')
    elif proto in (6,17) and len(frame)>=l4+(20 if proto==6 else 8):
        row.update(src_port=struct.unpack_from('!H',frame,l4)[0],dst_port=struct.unpack_from('!H',frame,l4+2)[0],supported=True,reason=None)
        if proto==6:
            hlen=(frame[l4+12]>>4)*4
            if hlen<20 or len(frame)<l4+hlen:return {**row,'supported':False,'reason':'bad_tcp_header'}
            row.update(tcp_sequence=struct.unpack_from('!I',frame,l4+4)[0],tcp_flags=frame[l4+13],tcp_payload_bytes=max(0,ipend-l4-hlen))
            options=frame[l4+20:l4+hlen];i=0
            while i<len(options):
                kind=options[i]
                if kind==0:break
                if kind==1:i+=1;continue
                if i+1>=len(options) or options[i+1]<2 or i+options[i+1]>len(options):break
                if kind==8 and options[i+1]==10:row['tcp_timestamp'],row['tcp_timestamp_echo']=struct.unpack_from('!II',options,i+2)
                i+=options[i+1]
    else:row['reason']='other_l4_or_extension'
    return row


def observe_capture(pcap: Path, campaign: dict, out: Path) -> dict:
    pcap=Path(pcap).resolve();campaigns=campaign if isinstance(campaign,list) else [campaign]
    actual=sha256(pcap)
    if not campaigns or any(c.get('capture_sha256')!=actual for c in campaigns):raise ValueError('capture source hash required and must match')
    ids=[c['campaign_id'] for c in campaigns]
    if len(ids)!=len(set(ids)):raise ValueError('duplicate campaign IDs')
    packets=[]
    def ts(x):return epoch(x) if isinstance(x,str) else float(x)
    for ordinal,(stamp,frame) in enumerate(read_pcap(pcap)):
        header=_header(frame)
        members=[c for c in campaigns if ts(c['started_at'])<=stamp<ts(c['ended_at']) and c['source_ip'] in (header.get('src'),header.get('dst'))]
        if len(members)>1:raise ValueError('ambiguous overlapping packet membership')
        packets.append({**header,'packet_ordinal':ordinal,'timestamp':stamp,'frame_bytes':len(frame),'frame_sha256':hashlib.sha256(frame).hexdigest(),
                        'campaign_id':members[0]['campaign_id'] if members else None,
                        'membership_role':'campaign' if members else 'auxiliary_or_unassigned'})
    body={'version':VERSION,'capture_path':str(pcap),'capture_sha256':actual,'campaigns':campaigns,'observed_packets':len(packets),'packets':packets}
    result={**body,'sha256':digest(body)}
    out=Path(out);out.mkdir(parents=True,exist_ok=True)
    (out/'observation.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def convert_supported_rows(observation: dict, out: Path) -> dict:
    from export_full_packets import export_with_payload
    body={k:v for k,v in observation.items() if k!='sha256'}
    if observation.get('sha256')!=digest(body):raise ValueError('observation was modified')
    pcap=Path(observation['capture_path'])
    if sha256(pcap)!=observation['capture_sha256']:raise ValueError('capture changed after observation')
    out=Path(out);out.mkdir(parents=True,exist_ok=True)
    rows=out/'capture.pkts';pay=out/'capture.pay'
    # A synthetic-only salt; no office sensor salt is accessed or changed.
    with rows.open('wb') as packets,pay.open('wb') as payload:
        stats=export_with_payload(pcap,packets,payload,b'cover-isolated-research-v1')
    supported=[p['packet_ordinal'] for p in observation['packets'] if p['supported']]
    count=rows.stat().st_size//35
    if count!=len(supported):raise ValueError('wire/exporter protocol accounting mismatch')
    result={'version':VERSION,'observation_sha256':observation['sha256'],'supported_rows':count,
            'separate_observation_rows':len(observation['packets'])-count,'packet_ordinals':supported,
            'pkts_path':str(rows),'pay_path':str(pay),'pkts_sha256':sha256(rows),'pay_sha256':sha256(pay),'export_stats':stats}
    (out/'conversion.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
