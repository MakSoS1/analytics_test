"""Explicit bounded cross-flow ordering projection; immutable raw PCAP retained."""
from collections import defaultdict
from pathlib import Path
import shutil
from .source import read_pcap,write_pcap,sha256,transport

MAX_REGRESSION_SECONDS=.00001

def canonicalize(source,target):
    source=Path(source);target=Path(target)
    if target.exists():raise FileExistsError('retain ordering projection')
    pin=sha256(source);frames=list(read_pcap(source,max_regression=MAX_REGRESSION_SECONDS))
    order=sorted(range(len(frames)),key=lambda i:frames[i][0]);before=defaultdict(list);after=defaultdict(list)
    for sequence,groups in ((range(len(frames)),before),(order,after)):
        for i in sequence:
            h=transport(frames[i][1])
            if h is None:raise ValueError('unsupported frame for bounded ordering projection')
            groups[(h['key'],h['src'])].append(i)
    if before!=after:raise ValueError('sorting changes order inside a transport direction')
    target.parent.mkdir(parents=True,exist_ok=True)
    if order==list(range(len(frames))):shutil.copyfile(source,target)
    else:write_pcap(target,[frames[i] for i in order])
    if list(read_pcap(target))!=[frames[i] for i in order] or sha256(source)!=pin:raise ValueError('ordering projection changed source, bytes or times')
    high=float('-inf');regressions=0;max_regression=0.
    for t,_ in frames:
        if t<high:regressions+=1;max_regression=max(max_regression,high-t)
        high=max(high,t)
    return {'source_sha256':pin,'projection_sha256':sha256(target),'packet_count':len(frames),'regressions':regressions,'max_regression_us':max_regression*1e6,'reordered_record_count':sum(i!=j for i,j in enumerate(order)),'packet_bytes_and_timestamps_preserved':True,'flow_direction_order_preserved':True,'global_capture_order_preserved':order==list(range(len(frames))),'policy':'stable timestamp order, <=10us regression; reject any per-direction order change'}
