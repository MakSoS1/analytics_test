"""Show that sensor observation changed only the time stamps of injected packets, and by how much.

Read-only. Compares every `placed.unobserved.pkts` with its observed `placed.pkts`:
all bytes except the time field identical, forward shifts within the cap, packet order
kept, and the effect on inter-packet gaps by size of the gap.
"""
import argparse
import json
from pathlib import Path

import numpy as np

from office_injection.records import iter_rows
from office_injection.sensor_stamps import CAP_SECONDS


def compare(unobserved, observed):
    before = list(iter_rows(unobserved))
    after = list(iter_rows(observed))
    if len(before) != len(after):
        raise ValueError('packet count changed')
    if any(raw[8:] != araw[8:] for (_, raw), (_, araw) in zip(before, after)):
        raise ValueError('a field other than time changed')
    t0 = np.array([r[0] for r, _ in before])
    t1 = np.array([r[0] for r, _ in after])
    shift = t1 - t0
    if np.any(shift < -1e-12) or np.any(shift > CAP_SECONDS + 1e-9):
        raise ValueError('shift outside [0, cap]')
    if np.any(np.diff(t1) < 0):
        raise ValueError('packet order changed')
    return t0, t1


def audit(directories):
    shifts, gap_before, gap_after, packets, tied = [], [], [], 0, 0
    for d in directories:
        t0, t1 = compare(Path(d) / 'placed.unobserved.pkts', Path(d) / 'placed.pkts')
        shifts.append(t1 - t0)
        gap_before.append(np.diff(t0))
        gap_after.append(np.diff(t1))
        packets += len(t0)
        tied += int(np.count_nonzero(np.diff(t1) == 0))
    shift = np.concatenate(shifts) * 1e6
    gb, ga = np.concatenate(gap_before), np.concatenate(gap_after)
    report = {'positives': len(directories), 'packets': packets, 'fields_other_than_time_identical': True,
              'order_preserved': True, 'shift_us': {'max': float(shift.max()), 'p50': float(np.percentile(shift, 50)),
              'p90': float(np.percentile(shift, 90)), 'moved_share': float(np.mean(shift > 0))},
              'adjacent_equal_stamp_share_after': tied / max(len(ga), 1), 'gaps_by_size': {}}
    for name, low, high in (('under_50us', 0, 50e-6), ('50us_to_1ms', 50e-6, 1e-3), ('1ms_to_100ms', 1e-3, 0.1), ('over_100ms', 0.1, 1e9)):
        mask = (gb >= low) & (gb < high)
        if mask.any():
            change = np.abs(ga[mask] - gb[mask])
            relative = change / np.maximum(gb[mask], 1e-9)
            report['gaps_by_size'][name] = {'gaps': int(mask.sum()), 'max_abs_change_us': float(change.max() * 1e6),
                                           'p99_relative_change': float(np.percentile(relative, 99))}
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--positive-dirs', type=Path, nargs='+', required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    report = audit(a.positive_dirs)
    with a.out.open('x') as f:
        f.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=1))


if __name__ == '__main__':
    main()
