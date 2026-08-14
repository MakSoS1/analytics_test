from __future__ import annotations

import math
from collections import Counter,defaultdict,deque
from typing import Any
import pandas as pd


def _num(row:dict[str,Any],name:str)->float:
    value=row.get(name,0)
    try: return 0.0 if value in (None,'-','') else float(value)
    except (TypeError,ValueError): return 0.0


def _entropy(counter:Counter[str])->float:
    total=sum(counter.values())
    if not total:return 0.0
    return float(-sum((n/total)*math.log2(n/total) for n in counter.values() if n))


def build_production_flow_features(mapped_conn:pd.DataFrame)->pd.DataFrame:
    required={'session_id','ts','id.orig_h','id.resp_h','id.resp_p'}
    missing=required-set(mapped_conn.columns)
    if missing: raise ValueError(f'mapped conn missing: {sorted(missing)}')
    rows=mapped_conn.sort_values(['ts','session_id']).to_dict('records')
    src_history:dict[str,deque[tuple[float,str,str]]]=defaultdict(deque)
    seen_dst:dict[str,set[str]]=defaultdict(set); pair_seen:Counter[tuple[str,str]]=Counter()
    graph:deque[tuple[float,str,str,bool]]=deque(); out_edges:dict[str,Counter[str]]=defaultdict(Counter); in_edges:dict[str,Counter[str]]=defaultdict(Counter); new_edges:Counter[str]=Counter(); ever_edges:set[tuple[str,str]]=set()
    output=[]
    for idx,row in enumerate(rows):
        ts=_num(row,'ts'); src=str(row['id.orig_h']); dst=str(row['id.resp_h']); dport=int(_num(row,'id.resp_p')); proto=str(row.get('service') or row.get('proto') or 'unknown'); sid=str(row['session_id'])
        hist=src_history[src]
        while hist and hist[0][0]<ts-3600: hist.popleft()
        history=list(hist)
        def recent(seconds:int): return [e for e in history if e[0]>=ts-seconds]
        h60,h300,h900,h3600=recent(60),recent(300),recent(900),history
        pair=(src,dst); new_dst=dst not in seen_dst[src]; new_pair=pair_seen[pair]==0
        while graph and graph[0][0]<ts-3600:
            _,osrc,odst,was_new=graph.popleft(); out_edges[osrc][odst]-=1; in_edges[odst][osrc]-=1
            if out_edges[osrc][odst]<=0: del out_edges[osrc][odst]
            if in_edges[odst][osrc]<=0: del in_edges[odst][osrc]
            if was_new:new_edges[osrc]-=1
        ob=_num(row,'orig_bytes'); rb=_num(row,'resp_bytes'); op=_num(row,'orig_pkts'); rp=_num(row,'resp_pkts')
        uid=str(row.get('uid') or f'flow-{idx:012d}')
        output.append({
          'flow_uid':uid,'session_id':sid,
          'flow_count':1,'duration':_num(row,'duration'),'src_bytes':ob,'dst_bytes':rb,'src_packets':op,'dst_packets':rp,'bytes_total':ob+rb,'packets_total':op+rp,'bytes_ratio':ob/(rb+1.0),'packets_ratio':op/(rp+1.0),'app_proto':proto,'dst_port':dport,
          'connections_1m':len(h60),'connections_5m':len(h300),'connections_15m':len(h900),'connections_1h':len(h3600),'unique_dst_ip_5m':len({e[1] for e in h300}),'unique_dst_ip_15m':len({e[1] for e in h900}),'unique_protocols_1h':len({e[2] for e in h3600}),'new_dst_for_src':int(new_dst),'new_src_dst_pair':int(new_pair),'pair_seen_count':int(pair_seen[pair]),'src_out_degree_1h':len(out_edges[src]),'dst_in_degree_1h':len(in_edges[dst]),'new_edge_count_1h':int(new_edges[src]),'protocol_entropy_1h':_entropy(Counter(e[2] for e in h3600)),
        })
        was_new=pair not in ever_edges; hist.append((ts,dst,proto)); seen_dst[src].add(dst); pair_seen[pair]+=1; ever_edges.add(pair); graph.append((ts,src,dst,was_new)); out_edges[src][dst]+=1; in_edges[dst][src]+=1
        if was_new:new_edges[src]+=1
    return pd.DataFrame(output)
