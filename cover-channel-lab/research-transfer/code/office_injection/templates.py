"""Office session skeletons: the environment a generated session is played through.

A skeleton is taken from one real office TLS session's packet sequence and
keeps only what belongs to the path and the cover application, never the
content: handshake RTT, path MTU, client TCP-timestamp use, when activity
resumes after silence, how long the server takes to answer, and when and how
the connection is closed. A generator replays a technique's own requests on
that skeleton, and a matched control uses the same skeleton, so whatever the
environment contributes is identical in both arms.

The store is keyed by Moscow date and hour. New office days are added by
`ingest` (called from the tee hook after every baseline batch), so later
injections draw on the latest observed office behaviour of the same hour.
A template must never come from the office window it is injected into:
the positive would get a timing twin in its own background.
"""
from __future__ import annotations
import argparse
import csv
import gzip
import hashlib
import json
import random
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

csv.field_size_limit(1 << 30)
MSK = ZoneInfo('Europe/Moscow')
VERSION = 1
SYN, FIN, RST, PSH, ACK = 2, 1, 4, 8, 16
MAX_PURE_ACK = 66          # 54 bare, 60 padded, 66 with TCP timestamps


def _is_data(length, flags):
    return not flags & (SYN | FIN | RST) and (abs(length) > MAX_PURE_ACK or bool(flags & PSH))


def skeleton(row, min_idle=0.3, idle_rtts=3.0, max_duration=180.0):
    """One office session -> skeleton dict, or (None, reason)."""
    if row.get('proto') != 'tcp':return None, 'not_tcp'
    if str(row.get('dest_port')) != '443':return None, 'not_443'
    if float(row.get('tls_sni_len') or 0) <= 0:return None, 'no_sni'
    if str(row.get('start_observed')) != '1':return None, 'start_not_observed'
    if str(row.get('bidirectional_visible', '1')) != '1':return None, 'one_sided'
    if str(row.get('segment_index', '0')) != '0' or str(row.get('session_continues', '0')) != '0':
        return None, 'segmented'
    if str(row.get('truncated_at_capture_end', '0')) == '1':return None, 'truncated'
    try:
        lens = [int(x) for x in row['seq_signed_len'].split()]
        gaps = [int(x) for x in row['seq_iat_us'].split()]
        flags = [int(x) for x in row['seq_flags'].split()]
    except (KeyError, ValueError):
        return None, 'no_sequence'
    if not lens or not len(lens) == len(gaps) == len(flags):return None, 'no_sequence'
    times, t = [], 0
    for g in gaps:
        t += g; times.append(t / 1e6)
    if lens[0] <= 0 or flags[0] & (SYN | ACK) != SYN:return None, 'no_client_syn'
    synack = next((i for i, (l, f) in enumerate(zip(lens, flags)) if l < 0 and f & (SYN | ACK) == SYN | ACK), None)
    if synack is None:return None, 'no_synack'
    rtt = times[synack] - times[0]
    if rtt <= 0:return None, 'zero_rtt'
    close = next((i for i, f in enumerate(flags) if f & (FIN | RST)), None)
    if close is None:return None, 'no_close'
    duration = times[-1]
    if duration > max_duration:return None, 'too_long'
    idle = max(min_idle, idle_rtts * rtt)
    exchanges = []
    last = times[0]
    for i, (l, f, ts) in enumerate(zip(lens, flags, times)):
        if i >= close:break
        if l > 0 and _is_data(l, f) and (not exchanges or ts - last >= idle):
            reply = next((times[j] for j in range(i + 1, close) if lens[j] < 0 and _is_data(lens[j], flags[j])), None)
            think = None if reply is None else max(0.0, reply - ts - rtt)
            exchanges.append({'at': round(ts, 6), 'server_think': None if think is None else round(think, 6)})
        last = ts
    if not exchanges:return None, 'no_client_data'
    up_acks = [l for l, f in zip(lens, flags) if l > 0 and f == ACK and l <= MAX_PURE_ACK]
    frame_max = max(abs(l) for l in lens)
    return {
        'rtt': round(rtt, 6),
        'exchanges': exchanges,
        'close_at': round(times[close], 6),
        'closer': 'client' if lens[close] > 0 else 'server',
        'close_kind': 'rst' if flags[close] & RST else 'fin',
        'duration': round(duration, 6),
        'frame_max': frame_max,
        'client_tcp_timestamps': bool(up_acks) and max(up_acks) == 66,
        'packets': len(lens),
        'start_epoch': float(row['session_start_epoch']),
    }, 'ok'


def _rows(path):
    path = Path(path)
    if path.suffix == '.parquet':
        import pyarrow.parquet as pq
        for batch in pq.ParquetFile(path).iter_batches(batch_size=4096):
            for r in batch.to_pylist():
                for k in ('seq_signed_len', 'seq_iat_us', 'seq_flags'):
                    if isinstance(r.get(k), list):r[k] = ' '.join(map(str, r[k]))
                yield r
        return
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rt', newline='') as f:
        yield from csv.DictReader(f)


def ingest(session_files, store, **kw):
    """Add skeletons from office session tables; idempotent per source file."""
    store = Path(store); store.mkdir(parents=True, exist_ok=True)
    reports = []
    for path in map(Path, session_files):
        digest = hashlib.sha256(f'{path.resolve()}:{path.stat().st_size}:{path.stat().st_mtime_ns}'.encode()).hexdigest()[:16]
        marker = store / 'sources' / f'{digest}.json'
        if marker.exists():
            reports.append(json.loads(marker.read_text()));continue
        buckets, reasons, total = {}, {}, 0
        for row in _rows(path):
            total += 1
            s, why = skeleton(row, **kw)
            reasons[why] = reasons.get(why, 0) + 1
            if s is None:continue
            dt = datetime.fromtimestamp(s['start_epoch'], MSK)
            s['moscow_date'] = dt.date().isoformat(); s['moscow_hour'] = dt.hour
            s['source'] = digest
            buckets.setdefault((s['moscow_date'], dt.hour), []).append(s)
        for (day, hour), items in buckets.items():
            target = store / day / f'{hour:02d}.{digest}.jsonl.gz'
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_suffix('.partial')
            with gzip.open(tmp, 'wt') as f:
                for s in items:f.write(json.dumps(s, separators=(',', ':')) + '\n')
            tmp.replace(target)
        report = {'version': VERSION, 'source': str(path.resolve()), 'digest': digest, 'rows': total,
                  'accepted': sum(len(v) for v in buckets.values()), 'reasons': reasons,
                  'buckets': {f'{d}T{h:02d}': len(v) for (d, h), v in sorted(buckets.items())},
                  'filters': {'tls_443_sni': True, 'start_observed': True, 'bidirectional': True,
                              'first_segment_only': True, 'close_observed': True, **kw}}
        marker.parent.mkdir(exist_ok=True)
        marker.write_text(json.dumps(report, indent=2) + '\n')
        reports.append(report)
    return reports


def load(store, hour, exclude=(), before=None, days=7):
    """Skeletons of one Moscow hour, newest days first.

    exclude: (start, end) epoch windows whose sessions are the injected
    background; templates starting inside them are dropped. before: only days
    strictly before this date (the 'previous days' policy), if given.
    """
    store = Path(store); out = []
    dated = sorted((p for p in store.iterdir() if p.is_dir() and p.name[:2] == '20'), reverse=True)
    if before:dated = [p for p in dated if p.name < before]
    for day in dated[:days]:
        for f in sorted(day.glob(f'{hour:02d}.*.jsonl.gz')):
            with gzip.open(f, 'rt') as fh:
                for line in fh:
                    s = json.loads(line)
                    if any(a <= s['start_epoch'] <= b for a, b in exclude):continue
                    out.append(s)
    return out


def sample(store, hours, n_per_hour, seed, exclude=(), before=None, days=7, keep=None):
    """Seeded draw per hour; the selection bias of max_duration is reported by ingest.

    keep: optional predicate on a skeleton. Applied to the pool BEFORE the draw, so a
    technique that cannot replay some skeletons still gets n_per_hour usable ones
    instead of losing pairs after the fact. Without it the draw is unchanged.
    """
    rng = random.Random(seed); picked = []
    for hour in sorted(hours):
        pool = load(store, hour, exclude, before, days)
        if keep:pool = [s for s in pool if keep(s)]
        if not pool:raise ValueError(f'no office templates for Moscow hour {hour}; ingest office sessions of that hour first')
        pool.sort(key=lambda s: (s['start_epoch'], s['rtt']))
        for s in rng.sample(pool, min(n_per_hour, len(pool))):
            picked.append({**s, 'template_id': hashlib.sha256(json.dumps(s, sort_keys=True).encode()).hexdigest()[:12],
                           'pool_size': len(pool)})
    return picked


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--store', required=True, type=Path)
    p.add_argument('--sessions', nargs='+', required=True, type=Path)
    p.add_argument('--max-duration', type=float, default=180.0)
    a = p.parse_args()
    print(json.dumps(ingest(a.sessions, a.store, max_duration=a.max_duration), indent=2))


if __name__ == '__main__':main()
