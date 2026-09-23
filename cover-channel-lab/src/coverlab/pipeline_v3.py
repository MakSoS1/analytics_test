from __future__ import annotations

import json
import hashlib
from collections import defaultdict
from pathlib import Path
from typing import Any

import pandas as pd
from scapy.all import PcapReader, IP, IPv6, TCP, UDP

from . import pipeline as _base
from . import pipeline_v2 as _v2  # installs Stage G correctness first

_v2_assign = _v2.assign_split
_v2_audit = _v2.leakage_audit
_v2_build_gold = _v2.build_gold


def assign_split(row: pd.Series) -> str:
    stage=str(row.get('experiment_stage','')).lower(); role=str(row.get('dataset_role','')).lower(); cid=str(row.get('campaign_id',''))
    training=row.get('training_eligible', True)
    # Stage M uses an explicit implementation holdout.  Do not let historical
    # client/carrier holdout rules silently reshape this positive-only split.
    if stage=='m_positive_diversity' or cid.startswith('m-'):
        if role=='implementation_holdout' or str(row.get('primary_split','')).lower()=='implementation_holdout' or training is False or str(training).lower()=='false':
            return 'challenge'
        x=int(hashlib.sha256(cid.encode()).hexdigest()[:8],16)%100
        return 'train' if x<80 else 'validation' if x<90 else 'test'
    if training is False or str(training).lower()=='false' or stage in {'j_framework_holdout','l_long_timing'} or role in {'external_framework_holdout','long_timing_challenge'} or cid.startswith(('j-','l-')):
        return 'challenge'
    return _v2_assign(row)


def leakage_audit(df: pd.DataFrame, split_counts: dict[str,int]) -> dict[str,Any]:
    report=_v2_audit(df,split_counts); split=df.apply(assign_split,axis=1)
    training=df.get('training_eligible',pd.Series([True]*len(df),index=df.index))
    ineligible=training.astype(str).str.lower().eq('false') | training.eq(False)
    bad=df.loc[ineligible & ~split.eq('challenge'),'campaign_id'].astype(str).tolist()
    report['training_ineligible_outside_challenge']=bad
    stage_m_leaks=[]
    if {'scenario_id','implementation_id','primary_split'}.issubset(df.columns):
        m=df[df.get('experiment_stage',pd.Series(['']*len(df),index=df.index)).astype(str).str.lower().eq('m_positive_diversity')]
        if not m.empty:
            train_pairs=set(zip(m.loc[m.primary_split.astype(str).eq('train_candidate'),'scenario_id'].astype(str),m.loc[m.primary_split.astype(str).eq('train_candidate'),'implementation_id'].astype(str)))
            hold_pairs=set(zip(m.loc[m.primary_split.astype(str).eq('implementation_holdout'),'scenario_id'].astype(str),m.loc[m.primary_split.astype(str).eq('implementation_holdout'),'implementation_id'].astype(str)))
            stage_m_leaks=sorted(f'{a}:{b}' for a,b in train_pairs & hold_pairs)
    report['stage_m_implementation_holdout_leakage']=stage_m_leaks
    report['passed']=bool(report.get('passed',False)) and not bad and not stage_m_leaks
    return report


def _packet_sequence_features(stage_dir: Path, pcap: Path) -> pd.DataFrame:
    """Build a packet-only temporal table suitable for opaque TLS inference.

    This intentionally never reads decrypted_transactions, HTTP fields, SNI,
    request bodies, server-side traces, or any other plaintext.  Every value is
    derived from packet framing/timestamps and transport headers visible at the
    NDR observation point.
    """
    campaigns=_base.read_jsonl(stage_dir/'campaigns.jsonl')
    if not campaigns or not pcap.exists():
        return pd.DataFrame()
    cdf=pd.DataFrame(campaigns)
    index=_base.campaign_intervals(cdf)
    previous_ts: dict[str,float]={}
    seen_flows: dict[str,set[tuple]] = defaultdict(set)
    seen_tcp_seq: dict[tuple,set[tuple[int,int]]] = defaultdict(set)
    rows=[]
    with PcapReader(str(pcap)) as rd:
        for pkt in rd:
            try:
                ts=float(pkt.time); size=len(pkt)
                if IP in pkt:
                    src,dst=str(pkt[IP].src),str(pkt[IP].dst)
                elif IPv6 in pkt:
                    src,dst=str(pkt[IPv6].src),str(pkt[IPv6].dst)
                else:
                    continue
                persona=src if src in index else dst if dst in index else None
                if not persona:
                    continue
                cid=_base.lookup_campaign(index,persona,ts)
                if not cid:
                    continue
                direction=1 if src==persona else -1
                transport='other'; sport=0; dport=0
                syn=ack=fin=rst=psh=urg=0; retransmit=0
                if TCP in pkt:
                    transport='tcp'; sport=int(pkt[TCP].sport); dport=int(pkt[TCP].dport)
                    flags=str(pkt[TCP].flags)
                    syn=int('S' in flags); ack=int('A' in flags); fin=int('F' in flags)
                    rst=int('R' in flags); psh=int('P' in flags); urg=int('U' in flags)
                    flow=(min(src,dst),max(src,dst),min(sport,dport),max(sport,dport),'tcp')
                    directional=(cid,src,dst,sport,dport)
                    key=(int(pkt[TCP].seq),max(0,len(bytes(pkt[TCP].payload))))
                    retransmit=int(key in seen_tcp_seq[directional] and key[1] > 0)
                    seen_tcp_seq[directional].add(key)
                elif UDP in pkt:
                    transport='udp'; sport=int(pkt[UDP].sport); dport=int(pkt[UDP].dport)
                    flow=(min(src,dst),max(src,dst),min(sport,dport),max(sport,dport),'udp')
                else:
                    flow=(min(src,dst),max(src,dst),0,0,'other')
                boundary=int(flow not in seen_flows[cid] or syn)
                seen_flows[cid].add(flow)
                dt=max(0.0,ts-previous_ts[cid]) if cid in previous_ts else 0.0
                previous_ts[cid]=ts
                rows.append({
                    'campaign_id':str(cid),'ts':ts,'direction':direction,
                    'packet_size':size,'delta_t':dt,'transport':transport,
                    'tcp_syn':syn,'tcp_ack':ack,'tcp_fin':fin,'tcp_rst':rst,
                    'tcp_psh':psh,'tcp_urg':urg,'tcp_retransmit':retransmit,
                    'flow_boundary':boundary,
                })
            except Exception:
                continue
    return pd.DataFrame(rows)


def build_gold(stage_dir: Path, silver: Path, gold: Path, pcap: Path):
    result=_v2_build_gold(stage_dir,silver,gold,pcap)
    packet_seq=_packet_sequence_features(stage_dir,pcap)
    if not packet_seq.empty:
        packet_seq.to_parquet(gold/'packet_sequence_features.parquet',index=False)
    session_path=gold/'session_features.parquet'
    if session_path.exists():
        df=pd.read_parquet(session_path)
        p_root=stage_dir/'parser'
        def rc(path:Path):
            try:return int(path.read_text().strip())
            except Exception:return -1
        df['suricata_parser_ok']=int(rc(p_root/'suricata'/'exit_code.txt')==0)
        df['zeek_parser_ok']=int(rc(p_root/'zeek'/'exit_code.txt')==0)
        df['telemetry_exported']=1
        df['capture_tail_pass']=1
        df['opaque_packet_sequence_available']=int(not packet_seq.empty)
        df.to_parquet(session_path,index=False)
    diag=gold/'mapping_diagnostics.json'
    if diag.exists():
        data=json.loads(diag.read_text()); data['contract_revision']=3; data['training_ineligible_forced_challenge']=True
        data['opaque_packet_sequence']='packet_only_no_plaintext'
        data['opaque_packet_sequence_rows']=int(len(packet_seq))
        diag.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')
    return result


_base.assign_split=assign_split
_base.leakage_audit=leakage_audit
_base.build_gold=build_gold

if __name__=='__main__': _base.main()
