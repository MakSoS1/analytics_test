"""Exact block scans of already-retained binary rows; no sampling or time changes."""
import math
from pathlib import Path
import numpy as np
from .records import RECORD

DTYPE=np.dtype([('ts','<f8'),('src','V8'),('dst','V8'),('length','<u2'),
                ('sport','<u2'),('dport','<u2'),('payload','<u2'),('proto','u1'),('flags','u1'),('meta','u1')])
if DTYPE.itemsize!=RECORD.size:raise RuntimeError('packet record schema differs')


def chunks(paths, size=1000000):
    for path in paths:
        path=Path(path)
        if path.stat().st_size % RECORD.size:raise ValueError('truncated packet rows: '+str(path))
        if not path.stat().st_size:continue
        rows=np.memmap(path,dtype=DTYPE,mode='r');last=-math.inf
        for start in range(0,len(rows),size):
            part=rows[start:start+size];ts=part['ts']
            if not np.isfinite(ts).all() or ts[0]<last or np.any(np.diff(ts)<0):
                raise ValueError('non-monotone timestamp in '+str(path))
            last=float(ts[-1]);yield part


def profile_bins(paths, interval):
    result={}
    for part in chunks(paths):
        ticks=np.floor(part['ts']/interval).astype(np.int64)
        starts=np.flatnonzero(np.r_[True,ticks[1:]!=ticks[:-1]])
        stops=np.r_[starts[1:],len(ticks)]
        for lo,hi in zip(starts,stops):
            rows=part[lo:hi];t=int(ticks[lo])*interval
            b=result.setdefault(t,{'packets':0,'bytes':0,'hosts':set(),'first':float(rows['ts'][0]),'last':float(rows['ts'][-1])})
            b['packets']+=int(hi-lo);b['bytes']+=int(rows['length'].sum(dtype=np.uint64))
            b['first']=min(b['first'],float(rows['ts'][0]));b['last']=max(b['last'],float(rows['ts'][-1]))
            b['hosts'].update(v.tobytes() for v in np.unique(np.concatenate([rows['src'],rows['dst']])))
    return result


def endpoint_counts(paths):
    from collections import Counter
    hosts,peers=Counter(),Counter()
    for part in chunks(paths):
        for side,bit in (('src',1),('dst',2)):
            private=(part['meta'] & bit)!=0
            for counter,mask in ((hosts,private),(peers,~private)):
                values,counts=np.unique(part[side][mask],return_counts=True)
                counter.update({v.tobytes().hex():int(n) for v,n in zip(values,counts)})
    return hosts,peers
