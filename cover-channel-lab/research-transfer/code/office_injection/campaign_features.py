"""Packet-attributed campaign windows, using only causal experiment history."""
import copy
import math
from .cover_registry import digest

FEATURES=('packet_count','up_bytes','down_bytes','session_starts','distinct_peers','new_peers','history_available')
CONTRACT={'name':'network_campaign_v1','features':FEATURES,'grain':'host_event_time_window',
          'serving_source':'mapped_packet_events','history':'observed_prefix_only','observed_instance_idle_seconds':30,'instance_start':'new tuple or idle30s or SYN following FIN/RST','packet_identity':'monotone ordered source ordinal for streaming; exact IDs otherwise'}
CONTRACT_SHA256=digest(CONTRACT)


def extract_campaign_windows(records, window_seconds: int, state: dict):
    if window_seconds<=0:raise ValueError('positive window required')
    s=copy.deepcopy(state);flush=s.pop('flush',False)
    if s.get('window_seconds',window_seconds)!=window_seconds:raise ValueError('window contract changed across restart')
    s.update(window_seconds=window_seconds)
    s.setdefault('pending',{});s.setdefault('seen_packets',[]);s.setdefault('peers',{});s.setdefault('sessions',[])
    seen=set(s['seen_packets']);sessions=set(s['sessions']);out=[]
    def emit(before):
        for key,b in sorted(list(s['pending'].items()),key=lambda kv:(kv[1]['window_start'],kv[1]['host_key'])):
            if b['window_start']>=before:continue
            row={k:v for k,v in b.items() if k!='peers'};row['distinct_peers']=len(b['peers']);row['contract_sha256']=CONTRACT_SHA256
            out.append(row);del s['pending'][key]
    for event in records:
        t=float(event['timestamp']);ident=event['packet_id']
        if not math.isfinite(t) or t<s.get('last_timestamp',-math.inf):raise ValueError('event-time regression')
        sequence=event.get('packet_sequence')
        policy='monotone_ordinal' if sequence is not None else 'exact_ids'
        if s.setdefault('packet_id_policy',policy)!=policy:raise ValueError('packet identity policy changed across restart')
        if sequence is not None:
            if not isinstance(sequence,int) or sequence<=s.get('last_packet_sequence',-1):raise ValueError('duplicate or regressed packet sequence')
            s['last_packet_sequence']=sequence;seen.clear()
        if ident in seen:raise ValueError('duplicate packet attribution')
        if event['direction'] not in ('up','down') or event['frame_bytes']<0:raise ValueError('invalid packet direction/bytes')
        start=math.floor(t/window_seconds)*window_seconds
        if start>s.get('last_window_start',-math.inf):emit(start);s['last_window_start']=start
        host=event['host_key'];peer=event['server_key'];key=host+'|'+str(start)
        history=s['peers'].setdefault(host,[])
        b=s['pending'].setdefault(key,{'host_key':host,'window_start':start,'packet_count':0,'up_bytes':0,'down_bytes':0,
            'session_starts':0,'peers':[],'new_peers':0,'history_available':bool(history)})
        b['packet_count']+=1;b[event['direction']+'_bytes']+=event['frame_bytes']
        if peer not in b['peers']:b['peers'].append(peer)
        if peer not in history:b['new_peers']+=1;history.append(peer)
        session=host+'|'+event['session_id']
        if session not in sessions:b['session_starts']+=1;sessions.add(session)
        seen.add(ident);s['last_timestamp']=t
    if flush:emit(math.inf)
    s['seen_packets']=sorted(seen);s['sessions']=sorted(sessions)
    return out,s


def packet_events(paths,salt):
    """Causal observed instances, independently of completed-session assembly.

    A 30s idle gap starts another observed flow; a new SYN following FIN/RST
    starts another instance immediately. This policy is part of this contract,
    not a claim to reproduce completed-session timeout semantics.
    """
    import heapq
    from .records import iter_rows,flow_key
    from extract_office_sessions import _hkey
    flows={};keys={};sequence=0
    def key(raw):
        if raw not in keys:keys[raw]=_hkey(salt,raw.hex())
        return keys[raw]
    streams=[(x for x,raw in iter_rows(p)) for p in paths]
    for x in heapq.merge(*streams,key=lambda r:r[0]):
        a_private=bool(x[9]&1);b_private=bool(x[9]&2)
        if not a_private and not b_private:continue
        client_a=a_private and not b_private or a_private and b_private and (x[4]>x[5])
        h,p=(x[1],x[2]) if client_a else (x[2],x[1])
        flow=flow_key(x);old=flows.get(flow);syn=x[7]==6 and x[8]&0x12==2
        if old is None or x[0]-old['last']>30 or syn and old['closed']:
            old={'last':x[0],'closed':False,'instance':0 if old is None else old['instance']+1};flows[flow]=old
        old['last']=x[0];old['closed']|=bool(x[7]==6 and x[8]&5)
        yield {'packet_id':str(sequence),'packet_sequence':sequence,'timestamp':x[0],'host_key':key(h),'server_key':key(p),
            'frame_bytes':x[3],'direction':'up' if client_a else 'down','session_id':repr(flow)+':'+str(old['instance'])}
        sequence+=1


def build_packet_windows(branch,out,window_seconds=20):
    import json
    from pathlib import Path
    import pyarrow as pa,pyarrow.parquet as pq
    root=Path(branch);out=Path(out);out.mkdir(parents=True,exist_ok=False)
    paths=sorted(root.glob('batches/*/rows/mixed.pkts'))
    salt=(root/'session_salt').read_bytes()
    rows,state=extract_campaign_windows(packet_events(paths,salt),window_seconds,{'flush':True})
    pq.write_table(pa.Table.from_pylist(rows),out/'network_campaign_windows.parquet',compression='zstd')
    manifest={'contract':CONTRACT,'contract_sha256':CONTRACT_SHA256,'window_seconds':window_seconds,'windows':len(rows),
        'attributed_packets':sum(r['packet_count'] for r in rows),'up_bytes':sum(r['up_bytes'] for r in rows),
        'down_bytes':sum(r['down_bytes'] for r in rows),'serving_parity':'same packet-event extractor; restart unit equivalence',
        'training_eligible':False,'history_scope':'observed experiment prefix; first window has no pre-experiment history'}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');return manifest
