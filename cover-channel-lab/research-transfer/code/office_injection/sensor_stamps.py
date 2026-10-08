"""Empirical timestamp observation model for retained office contexts.

Equal timestamps are measured capture facts; they do not establish which driver,
ring or polling mechanism caused them. This bounded approximation places whole
ordered groups onto existing stamps with remaining capacity. Capacity is shared
across all campaigns in one alternative branch. Unallocated packets retain their
original times unless their tick is full; a bounded additional microsecond
readout is then tried without splitting equal-time groups. Capture bytes, sizes and order stay unchanged; each individual
interval may change by at most CAP_SECONDS, including millisecond intervals.
Source captures and unobserved packet rows remain immutable.
"""
from __future__ import annotations
import json
import struct
from pathlib import Path

import numpy as np

from .records import RECORD, iter_rows

VERSION = 'office-stamps-v4'
BURST_CAPACITY = 8          # empirical target, not a proven hardware limit
CAP_SECONDS = 0.0005        # ~p99 of gaps between office burst stamps (437 us)
_DTYPE = np.dtype([('ts', '<f8'), ('rest', 'V%d' % (RECORD.size - 8))])


class StampGrid:
    """Office burst stamps (with packet counts) inside one placement window."""

    def __init__(self, stamps, counts, capacity=BURST_CAPACITY, cap=CAP_SECONDS):
        self.stamps = np.asarray(stamps, dtype='<f8')
        self.counts = np.array(counts, dtype=np.int64, copy=True)
        self.capacity, self.cap = capacity, cap
        self.baseline_counts = self.counts.copy()
        self.fallback_counts = {}
        self.extra_counts = {}
        self.spill_packets = 0
        if len(self.stamps) != len(self.counts) or np.any(np.diff(self.stamps) <= 0):
            raise ValueError('stamps must be strictly increasing with one count each')
        self.last_mapping = {}
        if capacity < 1 or not np.isfinite(cap) or cap < 0 or np.any(self.counts < 0) or not np.all(np.isfinite(self.stamps)):
            raise ValueError('invalid capacity, cap or stamps/counts')
        # next_open[i]: first burst at or after i that is not already full
        open_ = self.counts < capacity
        n = len(self.stamps)
        nxt = np.full(n + 1, n, dtype=np.int64)
        for i in range(n - 1, -1, -1):
            nxt[i] = i if open_[i] else nxt[i + 1]
        self.next_open = nxt

    @classmethod
    def from_office(cls, paths, start, end, capacity=BURST_CAPACITY, cap=CAP_SECONDS):
        """Scan the retained office row files for [start, end]; rows are time-monotone per file."""
        parts = []
        for path in paths:
            size = Path(path).stat().st_size
            if size % RECORD.size:
                raise ValueError('truncated packet rows: %s' % path)
            if not size:
                continue
            mm = np.memmap(path, dtype=_DTYPE, mode='r')
            ts = mm['ts']
            if ts[-1] < start or ts[0] > end:
                continue
            lo = int(np.searchsorted(ts, start, 'left'))
            hi = int(np.searchsorted(ts, end, 'right'))
            parts.append(np.array(ts[lo:hi]))
        if not parts:
            return cls([], [], capacity, cap)
        stamps, counts = np.unique(np.concatenate(parts), return_counts=True)
        return cls(stamps, counts, capacity, cap)

    def observe(self, times, bound=None):
        """Allocate sorted packets once; never move past a following unallocated packet."""
        t = np.asarray(times, dtype='<f8')
        if not np.all(np.isfinite(t)) or np.any(np.diff(t) < 0):
            raise ValueError('finite sorted packet times required')
        out = t.copy()
        allocated = np.zeros(len(t), dtype=bool)
        i = 0
        while i < len(t) and len(self.stamps):
            pick = int(self.next_open[np.searchsorted(self.stamps, t[i], 'left')])
            found = False
            while pick < len(self.stamps):
                stamp = self.stamps[pick]
                if stamp-t[i] > self.cap or (bound is not None and stamp > bound):break
                # Moving the entire prefix avoids reversing a following fallback.
                stop = int(np.searchsorted(t, stamp, 'right'))
                count = stop-i
                if count <= self.capacity-self.counts[pick]-self.fallback_counts.get(pick,0):
                    out[i:stop] = stamp
                    allocated[i:stop] = True
                    self.counts[pick] += count
                    i = stop
                    found = True
                    break
                pick = int(self.next_open[pick + 1])
            if not found:
                i = int(np.searchsorted(t, t[i], 'right'))
        # An unchanged capture tick can collide with an already full office
        # tick. Model a further readout at the observed microsecond precision;
        # never stretch past the next packet, placement bound or shift cap.
        i = 0
        while i < len(t):
            if allocated[i]:
                i += 1
                continue
            stop = int(np.searchsorted(t, t[i], 'right'))
            stamp = float(t[i]);count = stop-i
            def occupancy(value):
                k = int(np.searchsorted(self.stamps, value))
                if k < len(self.stamps) and self.stamps[k] == value:
                    return int(self.counts[k])+self.fallback_counts.get(k,0)
                return self.extra_counts.get(value,0)
            if occupancy(stamp)+count > self.capacity:
                limit = min(stamp+self.cap, float(out[stop]) if stop<len(out) else float('inf'),
                            float(bound) if bound is not None else float('inf'))
                tick = int(np.floor(stamp*1e6))+1
                while count <= self.capacity:
                    candidate = tick/1e6
                    if candidate > limit or candidate-stamp > self.cap:break
                    if candidate > stamp and occupancy(candidate)+count <= self.capacity:
                        out[i:stop] = candidate
                        stamp = candidate
                        self.spill_packets += count
                        break
                    tick += 1
            k = int(np.searchsorted(self.stamps, stamp))
            if k < len(self.stamps) and self.stamps[k] == stamp:
                self.fallback_counts[k] = self.fallback_counts.get(k,0)+count
            else:
                self.extra_counts[stamp] = self.extra_counts.get(stamp,0)+count
            i = stop
        self.last_mapping = dict(zip(map(float, t), map(float, out)))
        return out

    def capacity_report(self):
        overflow = sum(max(0, int(self.counts[i])+n-max(self.capacity,int(self.baseline_counts[i])))
                       for i,n in self.fallback_counts.items()) + sum(max(0,n-self.capacity) for n in self.extra_counts.values())
        return {'allocated_packets':int((self.counts-self.baseline_counts).sum()),
                'capacity_scope':'shared office and extra microsecond ticks, including every fallback group',
                'spill_packets':self.spill_packets,'extra_stamp_count':len(self.extra_counts),
                'unmodelled_over_capacity_packets':overflow,
                'baseline_bursts_above_target':int(np.count_nonzero(self.baseline_counts > self.capacity)),
                'empirical_model_complete':overflow == 0}

    def require_complete(self):
        report=self.capacity_report()
        if not report['empirical_model_complete']:
            raise ValueError('sensor capacity unresolved: %d packets; retain failed run' % report['unmodelled_over_capacity_packets'])

    def payload_times(self, times):
        """Reuse actual row allocation; payload records do not consume extra slots."""
        try:
            return [self.last_mapping[float(t)] for t in times]
        except KeyError as exc:
            raise ValueError('payload timestamp missing from allocated packet rows') from exc


def observe_rows(source, target, grid, bound=None):
    """Rewrite only the first field (time) of packet rows; everything else is copied bit for bit."""
    rows = [(fields, raw) for fields, raw in iter_rows(source)]
    times = np.array([f[0] for f, _ in rows])
    new = grid.observe(times, bound)
    if np.any(np.diff(new) < 0):
        raise ValueError('observed stamps must keep packet order')
    shift = new - times
    with Path(target).open('wb') as f:
        for (fields, raw), t in zip(rows, new):
            f.write(struct.pack('<d', float(t)) + raw[8:])
    stats = {'packets': len(rows), 'moved_packets': int(np.count_nonzero(shift)),
             'max_shift_us': float(shift.max() * 1e6) if len(rows) else 0.0,
             'mean_shift_us': float(shift.mean() * 1e6) if len(rows) else 0.0,
             'tied_adjacent_after': int(np.count_nonzero(np.diff(new) == 0)),
             'tied_adjacent_before': int(np.count_nonzero(np.diff(times) == 0)),
             'first_after': float(new[0]) if len(rows) else None, 'last_after': float(new[-1]) if len(rows) else None}
    return stats


def observe_payload_times(source, target, grid, bound=None):
    """Same time map for the first/last time of each payload record (fields 6 and 7)."""
    import payload_sidecar as pay
    blob = Path(source).read_bytes()
    pos = 8
    out = bytearray(blob[:8])
    while pos < len(blob):
        start = pos
        fields = list(pay._HEAD.unpack_from(blob, pos))
        pos += pay._HEAD.size
        labels = fields[19] * pay._LABEL.size
        types = fields[33] * pay._QTYPE.size
        pos += labels + types
        nu, nd = struct.unpack_from('<HH', blob, pos)
        pos += 4 + nu + nd
        fields[6], fields[7] = (float(x) for x in grid.payload_times([fields[6], fields[7]]))
        out += pay._HEAD.pack(*fields) + blob[start + pay._HEAD.size:pos]
    Path(target).write_bytes(bytes(out))
    list(pay.read_sidecar(target))
    return {'records_checked': True}


def write_report(path, stats):
    Path(path).write_text(json.dumps({'version': VERSION, 'burst_capacity': BURST_CAPACITY, 'cap_seconds': CAP_SECONDS, **stats}, indent=2) + '\n')
