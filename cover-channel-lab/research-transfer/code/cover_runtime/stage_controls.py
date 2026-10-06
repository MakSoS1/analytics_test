"""Benign application controls for positive-only Stage M implementations.

These are isolated application fixtures, not sampled office benign traffic.
They retain each declared client/transport/topology and native cadence. Their
status does not authorize training or claim office domain equivalence.
"""
import json
import random
import time
from pathlib import Path

VERSION='stage-m-benign-fixture-control-v1'


def business_payload(r, mode, i, size=48):
    if mode=='fragment_2_6':return f'item-{i}'.encode()
    if mode=='low_entropy':return f'status-ok-{i}'.encode()
    return json.dumps({'event':'health','sequence':i,'status':'ok','queue_depth':r.randrange(5)},separators=(',',':')).encode()


def install(sm):
    original_state=sm._set_server_state
    def state(source_ip,family,seed,campaign_id):
        original_state(source_ip,family,seed,campaign_id)
        path=Path('/tmp/coverlab_server_state.json');raw=json.loads(path.read_text())
        raw['clients'][source_ip]['suspicious']=False;raw['default']['suspicious']=False
        path.write_text(json.dumps(raw))
    original_payload=sm._payload
    def payload(r,mode,i,size=48):
        # Preserve the generator RNG consumption so payload semantics cannot
        # accidentally alter the paired native jitter schedule.
        original_payload(r,mode,i,size)
        return business_payload(random.Random(i),mode,i,size)
    sm._set_server_state=state;sm._payload=payload
    # Business lookup names, not base32-encoded payload fragments. Used by
    # DNS, DoH and DoQ while their genuine client stacks remain unchanged.
    query=sm._dns_wire_query;counter=iter(range(1000))
    def dns_query(qname,qtype):return query('service-'+str(next(counter))+'.stage-m.test.',qtype)
    sm._dns_wire_query=dns_query
    wss=sm._wss_events
    def ws_events(spec,r,seed,tunnel=False):return wss(spec,r,seed,tunnel=False)
    sm._wss_events=ws_events
    def raw_events(spec,seed,source_ip):
        from scapy.all import IP,UDP,TCP,ICMP,Raw,send
        from coverlab.stage_m_raw import packet as positive_packet
        mode=spec.network_topology;r=random.Random(seed);events=[]
        if mode not in ('ipv4_id_udp','udp_source_port','icmp_id_seq','tcp_initial_seq','tcp_timestamp'):
            raise ValueError('unknown raw control mode')
        for i in range(spec.event_count):
            positive_packet(mode,source_ip,i,r)  # consume the same schedule RNG
            ip=IP(src=source_ip,dst='10.20.0.20',id=(100+i)&65535)
            if mode in ('ipv4_id_udp','udp_source_port'):
                packet=ip/UDP(sport=40000,dport=9091)/Raw(b'health=ok')
            elif mode=='icmp_id_seq':packet=ip/ICMP(type=8,id=1234,seq=i)/Raw(b'health=ok')
            else:
                options=[('MSS',1460),('SAckOK',b''),('WScale',7)]
                if mode=='tcp_timestamp':options.append(('Timestamp',(int(time.monotonic()*1000)&0xffffffff,0)))
                packet=ip/TCP(sport=40000+i,dport=8080,flags='S',seq=random.Random(seed+i).randrange(2**32),options=options)
            started=sm.now_iso();send(packet,verbose=False)
            events.append({'event_id':f'e{i:03d}','event_type':'benign_diagnostic_probe','sent_at':started,
                           'completed_at':sm.now_iso(),'encoded_length':len(bytes(packet)),'control_version':VERSION})
            sm._requested_sleep(spec,r,i)
        return events
    sm._raw_header_events=raw_events
    return {'version':VERSION,'payload':'business_health_telemetry','dns':'service_lookup',
            'wss':'application_messages','raw':'diagnostic_probe','fidelity':'benign_application_fixture',
            'office_domain_equivalence':False}
