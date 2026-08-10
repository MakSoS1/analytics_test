from __future__ import annotations
import json
from pathlib import Path
import pandas as pd
from coverlab.scenarios import SCENARIOS


def main(out: Path):
    g=out/'gold'/'model-v3-smoke'; b=out/'bronze'/'model-v3-smoke'/'manifests'; g.mkdir(parents=True,exist_ok=True); b.mkdir(parents=True,exist_ok=True)
    reps={}
    for s in SCENARIOS:reps.setdefault(s.family,s)
    wanted=[x for x in ('header','websocket','timing','http3','tunnel','body','uri','http2') if x in reps]
    sessions=[];splits=[];tx=[];packet_seq=[];fields=[];manifests=[]
    n=320
    for i in range(n):
        # Adjacent benign/suspicious records share the same scenario family so
        # every LOFO smoke cell can measure both attack recall and benign FPR.
        cid=f'mv3-{i:04d}';label=i%2;scenario=reps[wanted[(i//2)%len(wanted)]]
        split='train' if i<160 else 'validation' if i<256 else 'test' if i<288 else 'challenge'
        encrypted_transport=scenario.transport in {'https','h2','h3','wss','quic'}
        opaque=int(encrypted_transport and ((i//2)%2==0))
        inspection='bypass' if opaque else ('inspect' if encrypted_transport else 'not_applicable')
        sessions.append({'campaign_id':cid,'label_binary':label,'label_family':'synthetic' if label else 'benign','protocol':scenario.transport,
                         'persona':'smoke','client_impl':'python_httpx','visibility_mode':'opaque_and_ground_truth' if opaque else 'content',
                         'inspection_policy':inspection,'sni_visibility':'clear',
                         'packet_count':20+label*6+i%3,'byte_count':2000+label*900+i%17,'wire_duration_s':1.0+label*.35+(i%7)*.01,
                         'packet_size_mean':100+label*18,'packet_size_std':10+label*7,'interarrival_mean':.05+label*.025,
                         'interarrival_std':.01+label*.009,'up_bytes':1000+label*500,'down_bytes':1000+label*400,'tcp_packets':20,'udp_packets':0,
                         'suricata_events':2,'zeek_events':2,'tls_parser_events':int(encrypted_transport),'http_parser_events':int(not opaque),
                         'suricata_parser_ok':1,'zeek_parser_ok':1,'capture_tail_pass':1,'telemetry_exported':1,'opaque_packet_sequence_available':1})
        splits.append({'campaign_id':cid,'split':split})
        manifests.append({'campaign_id':cid,'scenario_id':scenario.scenario_id,'label_binary':label,'experiment_stage':'model_v3_smoke','dataset_role':'smoke','training_eligible':True,'attack_mapping':list(scenario.attack_mapping) if label else []})
        base=i*10.0
        for j in range(8):
            ts=base+j*(1.0 if label else 1.7)+(0.05*(j%2) if label else 0);req=30+label*55+(j%3)*5;resp=45+(1-label)*30+(j%2)*7
            tx.append({'campaign_id':cid,'ts':ts,'kind':'poll' if j%2==0 else 'result','method':'POST' if label and j%3==0 else 'GET','protocol':scenario.transport,'request_body_length':req,'response_body_length':resp,'response_status':200 if j%5 else 204,'path_length':20+label*8,'query_length':label*16,'header_count':6+label,'header_bytes':200+label*80,'header_entropy':3.0+label*1.2,'request_body_entropy':2.0+label*2.0})
            fields.append({'campaign_id':cid,'ts':ts,'field_name':'Authorization' if label else 'Accept','field_role':'request_header','raw_length':40+label*35,'byte_length':40+label*35,'entropy':2.8+label*1.8,'printable_ratio':1.0,'unique_char_ratio':.5+label*.2,'digit_ratio':.1,'alpha_ratio':.7,'hex_ratio':.2+label*.2,'b64_ratio':.4+label*.4,'b64url_ratio':.4+label*.4,'delimiter_ratio':.05,'uuid_like':0,'jwt_like':label,'etag_like':0,'encoded_token_like':label})
        prev=base
        for j in range(24):
            ts=base+j*(.16 if label else .23)+(0.01*((j*3)%5));direction=1 if (j%3!=1) else -1
            packet_seq.append({'campaign_id':cid,'ts':ts,'direction':direction,'packet_size':120+(j%5)*22+label*(35 if j%4==0 else 5),'delta_t':0.0 if j==0 else ts-prev,'transport':'udp' if scenario.transport in {'h3','quic'} else 'tcp','tcp_syn':int(j==0 and scenario.transport not in {'h3','quic'}),'tcp_ack':int(j>0 and scenario.transport not in {'h3','quic'}),'tcp_fin':int(j==23 and scenario.transport not in {'h3','quic'}),'tcp_rst':0,'tcp_psh':int(label and j%4==0),'tcp_retransmit':int(label and j in {11,19}),'flow_boundary':int(j in {0,12})})
            prev=ts
    pd.DataFrame(sessions).to_parquet(g/'session_features.parquet',index=False)
    pd.DataFrame(splits).to_parquet(g/'campaign_splits.parquet',index=False)
    pd.DataFrame(tx).to_parquet(g/'transaction_features.parquet',index=False)
    pd.DataFrame(packet_seq).to_parquet(g/'packet_sequence_features.parquet',index=False)
    pd.DataFrame(fields).to_parquet(g/'field_features.parquet',index=False)
    (b/'campaigns.jsonl').write_text('\n'.join(json.dumps(x,separators=(',',':')) for x in manifests)+'\n')
    print(json.dumps({'campaigns':n,'transactions':len(tx),'packet_sequence_rows':len(packet_seq),'out':str(out)}))

if __name__=='__main__':
    import argparse;ap=argparse.ArgumentParser();ap.add_argument('--out',required=True);a=ap.parse_args();main(Path(a.out))
