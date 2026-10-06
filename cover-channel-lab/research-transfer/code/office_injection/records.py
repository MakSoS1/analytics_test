"""Streaming packet-row composition and event-time office sampling."""
from __future__ import annotations
import heapq
import math
import random
import struct
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

RECORD=struct.Struct('<d8s8sHHHHBBB')


def iter_rows(path):
    last=-math.inf
    with Path(path).open('rb') as f:
        while data:=f.read(RECORD.size*32768):
            if len(data)%RECORD.size: raise ValueError(f'truncated packet rows: {path}')
            for off in range(0,len(data),RECORD.size):
                raw=data[off:off+RECORD.size]; fields=RECORD.unpack(raw)
                if not math.isfinite(fields[0]) or fields[0]<last:
                    raise ValueError(f'non-monotone timestamp in {path}')
                last=fields[0]
                yield fields,raw


def flow_key(fields):
    a=(fields[1].hex(),fields[4]); b=(fields[2].hex(),fields[5])
    return (*min(a,b),*max(a,b),fields[7])


def profile_rows(paths,interval_seconds=20):
    if interval_seconds<=0: raise ValueError('interval_seconds must be positive')
    try:
        from .reference_scan import profile_bins
        bins=profile_bins(paths,interval_seconds)
    except ImportError:
        bins={}
        for path in paths:
            for x,_ in iter_rows(path):
                t=math.floor(x[0]/interval_seconds)*interval_seconds
                b=bins.setdefault(t,{'packets':0,'bytes':0,'hosts':set(),'first':x[0],'last':x[0]})
                b['first']=min(b['first'],x[0]);b['packets']+=1; b['bytes']+=x[3];b['hosts'].update((x[1],x[2]));b['last']=max(b['last'],x[0])
    out=[]
    for t,b in sorted(bins.items()):
        dt=datetime.fromtimestamp(t,ZoneInfo('Europe/Moscow'))
        out.append({'start':t,'end':t+interval_seconds,'observed_first':b['first'],'observed_last':b['last'],
                    'packets':b['packets'],'bytes':b['bytes'],'pps':b['packets']/interval_seconds,
                    'bps':b['bytes']*8/interval_seconds,'hosts':len(b['hosts']),
                    'moscow_hour':dt.hour,'moscow_date':dt.date().isoformat(),'weekday':dt.weekday()})
    rates=sorted(x['pps'] for x in out)
    if rates:
        lo=rates[int((len(rates)-1)/3)];hi=rates[int(2*(len(rates)-1)/3)]
        for b in out: b['load_stratum']='low' if b['pps']<=lo else ('high' if b['pps']>hi else 'normal')
    return out


def choose_placements(profile,campaigns,seed=0,repeats=1,guard=0.05,max_positive_fraction=0.01):
    if repeats<1 or not campaigns: raise ValueError('campaigns and positive repeats required')
    rng=random.Random(seed);groups=defaultdict(list)
    for b in profile: groups[(b['moscow_hour'],b['load_stratum'])].append(b)
    if not groups: raise ValueError('no sealed office intervals')
    if not 0<max_positive_fraction<=0.1:raise ValueError('positive fraction must be in (0, 0.1]')
    keys=sorted(groups);rng.shuffle(keys);out=[];used=defaultdict(int)
    def window(b,c):
        # Start inside the observed interval; the end may run on to the end of
        # the owning batch (batch_last), which long generated sessions need.
        if 'batch_last' in b:latest=min(b['observed_last'],b['batch_last']-c['duration']-guard)
        else:latest=b['observed_last']-c['duration']-guard
        return b['observed_first']+guard,latest
    for i in range(repeats):
        c=campaigns[i%len(campaigns)]
        hour=c.get('moscow_hour')
        fitting={key:[b for b in groups[key] if window(b,c)[1]>=window(b,c)[0] and used[b['start']]+c.get('packets',0)<=b['packets']*max_positive_fraction]
                 for key in keys if hour is None or key[0]==hour}
        available=[key for key in keys if fitting.get(key)]
        if not available: raise ValueError(f'campaign {c["campaign_id"]} cannot fit any observed office interval'+(f' of Moscow hour {hour}' if hour is not None else ''))
        key=available[i%len(available)];eligible=fitting[key]
        b=rng.choice(eligible);used[b['start']]+=c.get('packets',0)
        t=rng.uniform(*window(b,c))
        out.append({**c,'injection_id':f'cc-{i:05d}','placed_start':t,
                    'placed_end':t+c['duration'],'office_interval_start':b['start'],
                    'office_batch':b.get('office_batch'),'office_observed_last':b.get('batch_last',b['observed_last']),
                    'load_stratum':b['load_stratum'],'moscow_hour':b['moscow_hour'],
                    'moscow_date':b['moscow_date'],'office_pps':b['pps'],'seed':seed,'max_positive_fraction':max_positive_fraction,
                    'timing_policy':'original-speed RX plus constant event-time offset'})
    return out


def choose_paired_placements(profile, campaigns, seed=0, repeats=None, guard=0.05,
                             max_positive_fraction=0.01):
    """Place whole pairs in one event-time context; repeats counts sessions.

    The combined packet budget and longest arm reserve the interval once.
    Host-level causal comparisons must instead use two alternative branches.
    """
    pairs = defaultdict(list)
    for c in campaigns:
        pid = c.get('parent_campaign_id')
        if not pid:raise ValueError('paired placement requires parent_campaign_id')
        pairs[pid].append(c)
    units = []
    for pid, members in sorted(pairs.items()):
        if len(members) != 2 or {m.get('arm') for m in members} != {'scenario', 'control'}:
            raise ValueError('each pair requires exactly one scenario and one control')
        hours = {m.get('moscow_hour') for m in members}
        if len(hours) != 1:raise ValueError('paired arms require the same nominal hour')
        if any(m['duration'] < 0 or m.get('packets', 0) < 0 for m in members):
            raise ValueError('negative duration or packet budget')
        units.append({'campaign_id': pid, 'duration': max(m['duration'] for m in members),
                      'packets': sum(m.get('packets', 0) for m in members),
                      'moscow_hour': next(iter(hours))})
    repeats = len(campaigns) if repeats is None else repeats
    if repeats < 2 or repeats % 2:raise ValueError('repeats must count a positive even number of sessions')
    placed = choose_placements(profile, units, seed, repeats // 2, guard, max_positive_fraction)
    out = []
    for i, context in enumerate(placed):
        for j, c in enumerate(sorted(pairs[context['campaign_id']], key=lambda m: m['arm'])):
            out.append({**c, **context, 'campaign_id':c['campaign_id'], 'duration':c['duration'],
                        'packets':c['packets'], 'injection_id': f'cc-{2*i+j:05d}',
                        'placed_end': context['placed_start'] + c['duration'],
                        'placement_policy': 'paired_event_time_v2'})
    return out


def merge_rows(office_paths,positives,out_path):
    office_flows=set();count=0
    for p in office_paths:
        for x,_ in iter_rows(p):office_flows.add(flow_key(x));count+=1
    positive_flows={}
    for source in positives:
        for x,_ in iter_rows(source['path']):
            k=flow_key(x)
            if k in office_flows or (k in positive_flows and positive_flows[k]!=source['injection_id']):
                raise ValueError('flow collision: source attribution would be ambiguous')
            positive_flows[k]=source['injection_id']
    # A positive session is a few dozen rows and was already read whole above, so hold it in
    # memory: a lazy generator per file keeps every file open until its last row is merged,
    # which hit `Too many open files` at ~1000 positive sessions (2026-09-30, 1362 sessions).
    streams=[(iter_rows(p),None) for p in office_paths]+[(iter(list(iter_rows(s['path']))),s) for s in positives]
    heap=[]
    for i,(it,meta) in enumerate(streams):
        try:x,raw=next(it);heapq.heappush(heap,(x[0],i,0,x,raw))
        except StopIteration:pass
    ordinal=0;gt={};positive_count=0
    target=Path(out_path);partial=target.with_suffix(target.suffix+'.partial')
    try:
        with partial.open('wb') as f:
            while heap:
                ts,i,local,x,raw=heapq.heappop(heap);f.write(raw)
                it,meta=streams[i]
                if meta:
                    gt[ordinal]={k:v for k,v in meta.items() if k!='path'}
                    positive_count+=1
                ordinal+=1
                try:
                    nx,nraw=next(it);heapq.heappush(heap,(nx[0],i,local+1,nx,nraw))
                except StopIteration:pass
        partial.replace(target)
    except BaseException:
        partial.unlink(missing_ok=True);raise
    if ordinal!=count+positive_count:raise ValueError('packet accounting failed')
    return {'office_packets':count,'positive_packets':positive_count,'merged_packets':ordinal},gt
