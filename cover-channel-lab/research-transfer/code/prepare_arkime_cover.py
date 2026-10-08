"""Prepare retained source captures on VM only; no sensor/network/upload calls.

Independent captures occupy separate time windows, separated by 1201 seconds.
Only pcap timestamps change; frame bytes and all intra-capture intervals remain
identical. This prevents unrelated experiments with reused tuples being joined.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def packets(path):
    with path.open('rb') as f:
        header = f.read(24)
        magic = header[:4]
        endian = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
        if magic not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
            raise ValueError('unsupported pcap')
        nano = magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
        link = struct.unpack(endian + 'I', header[20:24])[0]
        if link != 1:
            raise ValueError('Ethernet captures required; no silent link conversion')
        while h := f.read(16):
            if len(h) != 16:
                raise ValueError('truncated header')
            sec, sub, cap, wire = struct.unpack(endian + 'IIII', h)
            frame = f.read(cap)
            if len(frame) != cap or cap != wire:
                raise ValueError('truncated packet cannot supply full features')
            yield sec * 10**9 + sub * (1 if nano else 1000), frame


def prepare(root, out, office_seconds):
    import pyarrow.parquet as pq
    out.mkdir(parents=True, exist_ok=False)
    base = root / 'cover_research_20261004'
    framework = root / 'framework_capture_20261004/wire_v4'
    training = framework / 'research_training_v2'
    if sha(training / 'COMPLETE.json') != 'a0c2171d27e0622c65b67a1375d649ca5a17c81ff074a55e382fb764aef417d2':
        raise ValueError('source Parquet revision mismatch')
    complete = json.loads((training / 'COMPLETE.json').read_text())
    if sha(training / 'labels_metadata.parquet') != complete['files']['labels_metadata.parquet']:
        raise ValueError('labels identity mismatch')
    labels = pq.read_table(training / 'labels_metadata.parquet').to_pylist()
    by_campaign = {}
    for label in labels:
        by_campaign.setdefault(label['campaign_id'], []).append(label)
    compositions = [base / 'composition_day22_v1', base / 'composition_day28_v1', framework / 'composition_day28_v1']
    registry = []
    for composition in compositions:
        registry.extend(json.loads((composition / 'full_campaign_registry.json').read_text()))
    sources = []
    for composition in (compositions[0], compositions[2]):
        observations = json.loads((composition / 'observation_manifest.json').read_text())['observations']
        for observation in observations:
            path = composition / observation['sealed_capture_path']
            digest = sha(path)
            obs = json.loads((composition / observation['sealed_observation_path']).read_text())
            if digest != obs['capture_sha256']:
                raise ValueError('sealed source capture hash mismatch')
            contexts = [c for c in registry if c.get('source_capture_sha256') == digest]
            if not contexts:
                contexts = [c for c in registry if c.get('actual_source_campaign_id') == observation['campaign_id'] or c['campaign_id'] == observation['campaign_id']]
            matched = [label for c in contexts for label in by_campaign.get(c['campaign_id'], [])]
            # Some full captures have no supported TCP/UDP feature segment in
            # the old extractor. Retain them without inventing a binary label.
            matched = list({r['global_segment_uid']: r for r in matched}.values())
            values = {r['label_binary'] for r in matched}
            states = {r['label_state'] for r in matched}
            if matched and (len(values) != 1 or len(states) != 1):
                raise ValueError('ambiguous capture labels; no forced label')
            sources.append(dict(path=str(path), sha256=digest, dataset='generated_cover',
                                observation_path=str(composition / observation['sealed_observation_path']),
                                campaign_id=observation['campaign_id'], technique=matched[0]['technique'] if matched else contexts[0]['technique'],
                                arm=observation['arm'], label_binary=values.pop() if matched else None,
                                label_state=states.pop() if matched else 'generated_without_original_segment',
                                original_contexts=matched))
    office = sorted((root / 'check-pcaps-check10m-20260923T161229Z').rglob('*.pcap'))[0]
    sources.insert(0, dict(path=str(office), sha256=sha(office), dataset='office_background_20260923',
                           label_binary=None, label_state='unlabelled_office', original_contexts=[]))
    mixed = out / 'source_isolated_mix.pcap'
    total = 0
    cursor = None
    with mixed.open('wb') as handle:
        handle.write(struct.pack('<IHHIIII', 0xa1b23c4d, 2, 4, 0, 0, 262144, 1))
        for index, source in enumerate(sources):
            # Laboratory captures are small; stable sort handles capture clock
            # inversions without changing any original packet timestamp.
            rows = packets(Path(source['path']))
            if index == 0:
                selected = []
                start = None
                for stamp, frame in rows:
                    start = stamp if start is None else start
                    if stamp > start + int(office_seconds * 10**9):
                        break
                    selected.append((stamp, frame))
                rows = selected
            else:
                rows = list(rows)
            rows = sorted(rows, key=lambda row: row[0])
            if not rows:
                raise ValueError('empty source capture')
            first, last = rows[0][0], rows[-1][0]
            target = first if cursor is None else cursor + 1201 * 10**9
            shift = target - first
            source.update(original_first_ns=first, original_last_ns=last,
                          mixed_first_ms=target // 10**6, mixed_last_ms=(last + shift) // 10**6,
                          shift_ms=shift // 10**6, packets=len(rows),
                          selected_window_seconds=office_seconds if index == 0 else None)
            if shift % 10**6:
                # Round to whole milliseconds so reversing Arkime's ms timestamps
                # is exact; all within-capture nanosecond deltas still unchanged.
                shift -= shift % 10**6
                source.update(mixed_first_ms=(first + shift)//10**6,
                              mixed_last_ms=(last + shift)//10**6, shift_ms=shift//10**6)
            for stamp, frame in rows:
                sec, ns = divmod(stamp + shift, 10**9)
                handle.write(struct.pack('<IIII', sec, ns, len(frame), len(frame)))
                handle.write(frame)
            cursor = last + shift
            total += len(rows)
    metadata = dict(version=1, source_training_complete_sha256=sha(training/'COMPLETE.json'),
                    original_labelled_segments=len(labels), unique_source_captures=len(sources)-1,
                    input_packets=total, office_seconds=office_seconds,
                    isolation_gap_seconds=1201, mix_kind='corpus mixture with isolated time windows',
                    frame_bytes_changed=False, within_capture_intervals_changed=False,
                    sources=sources, mixed_sha256=sha(mixed), cosmolake_uploads=0)
    (out/'PROVENANCE.json').write_text(json.dumps(metadata,indent=2)+'\n')
    (out/'files.txt').write_text(str(mixed)+'\n')
    print(json.dumps({k: metadata[k] for k in ('original_labelled_segments','unique_source_captures','input_packets','office_seconds','cosmolake_uploads')}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--office-seconds', type=float, default=20)
    a = p.parse_args()
    prepare(a.root, a.out, a.office_seconds)
