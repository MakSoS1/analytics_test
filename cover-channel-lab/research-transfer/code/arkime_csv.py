"""Lossless CSV view of the local Arkime SQLite store; run on the VM.

Every populated SPI leaf is retained. Cells contain JSON values: missing is an
empty cell, explicit null is `null`, strings are JSON strings, arrays stay arrays.
The fragment CSV remains authoritative for ordering and scalar observations.
"""
import argparse
import bisect
import csv
import hashlib
import json
import ipaddress
from pathlib import Path
import sqlite3

SUM_FIELDS = {'network.packets', 'network.bytes', 'source.packets',
              'destination.packets', 'source.bytes', 'destination.bytes',
              'client.bytes', 'server.bytes', 'totDataBytes'} | {
                  'tcpflags.' + k for k in ('syn', 'syn-ack', 'ack', 'psh',
                  'fin', 'rst', 'urg', 'ece', 'cwr', 'ae', 'srcZero', 'dstZero')}


def cell(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False)


def flatten(obj, prefix=''):
    for key, value in obj.items():
        path = prefix + '.' + key if prefix else key
        if isinstance(value, dict) and value:
            yield from flatten(value, path)
        else:
            yield path, value


def aggregate(records):
    values, arrays, sums, latest = {}, set(), {}, {}
    first, last, seq = None, None, -1
    for record in records:
        order = record.get('office', {}).get('seq', 0)
        if order >= seq:
            seq = order
            latest = {p: v for p, v in flatten(record)
                      if p.startswith('officeEntropy.')}
        for path, value in flatten(record):
            if path in SUM_FIELDS and isinstance(value, int) and not isinstance(value, bool):
                sums[path] = sums.get(path, 0) + value
            atoms = value if isinstance(value, list) else [value]
            if isinstance(value, list):
                arrays.add(path)
            unique = values.setdefault(path, {})
            for atom in atoms:
                unique[cell(atom)] = atom
        if record.get('firstPacket') is not None:
            first = min(first, record['firstPacket']) if first is not None else record['firstPacket']
        if record.get('lastPacket') is not None:
            last = max(last, record['lastPacket']) if last is not None else record['lastPacket']
    result = {}
    for path, unique in values.items():
        atoms = [unique[k] for k in sorted(unique)]
        result[path] = atoms if path in arrays or len(atoms) != 1 else atoms[0]
    for path in arrays:
        if path + 'Cnt' in result:
            result[path + 'Cnt'] = len(values[path])
    result.update(sums)
    result.update(latest)
    if first is not None:
        result['firstPacket'] = first
    if last is not None:
        result['lastPacket'] = last
    return result


def membership(data, packets, shift_ms):
    def key(src, dst, sport, dport, proto):
        return proto, tuple(sorted(((str(ipaddress.ip_address(src)), sport or 0),
                                    (str(ipaddress.ip_address(dst)), dport or 0))))
    try:
        target = key(data['source.ip'], data['destination.ip'],
                     data.get('source.port'), data.get('destination.port'), data['ipProtocol'])
    except (KeyError, ValueError, TypeError):
        return 0, 0, data.get('network.packets', 0)
    campaign = auxiliary = 0
    for packet in packets:
        stamp = int(packet['timestamp'] * 1000) + shift_ms
        if not data['firstPacket'] - 1 <= stamp <= data['lastPacket'] + 1:
            continue
        try:
            actual = key(packet['src'], packet['dst'], packet.get('src_port'),
                         packet.get('dst_port'), packet['proto'])
        except (KeyError, ValueError, TypeError):
            continue
        if actual != target:
            continue
        if packet['membership_role'] == 'campaign':
            campaign += 1
        else:
            auxiliary += 1
    unmatched = abs(data.get('network.packets', 0) - campaign - auxiliary)
    return campaign, auxiliary, unmatched


def export(state, catalog, provenance, out):
    # Packet position arrays / lossless SPI can exceed Python's 128 KiB default.
    csv.field_size_limit(256 * 1024 * 1024)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    db = sqlite3.connect(f'file:{Path(state).resolve()}?mode=ro', uri=True)
    definitions = json.loads(Path(catalog).read_text())
    sources = json.loads(Path(provenance).read_text())['sources']
    starts = [r['mixed_first_ms'] for r in sources]
    paths = set()
    observations = {}
    label_counts = {}
    for definition in definitions:
        spec = definition['definition']
        field = spec.get('fieldECS') or spec.get('dbField2') or spec.get('dbField')
        if isinstance(field, str) and field and not field.startswith('regex:'):
            paths.add(field)
    for (raw,) in db.execute('select source_json from fragments'):
        paths.update(path for path, value in flatten(json.loads(raw)))
    paths = sorted(paths)
    metadata = ['session_key', 'dataset', 'label_binary', 'label_state',
                'campaign_id', 'technique', 'arm', 'source_sha256',
                'source_first_ms', 'source_last_ms', 'time_shift_ms',
                'capture_boundary_limited', 'original_contexts_json',
                'fragments', 'start_observed', 'natural_end_observed',
                'campaign_packets', 'auxiliary_packets', 'membership_count_difference']
    count = 0
    with (out / 'arkime_sessions_all_fields.csv').open('w', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow(metadata + ['arkime.' + p for p in paths])
        for key, summary, started, ended in db.execute(
                'select session_key,summary_json,started,end_reason from session_totals order by session_key'):
            data = aggregate(json.loads(r[0]) for r in db.execute(
                'select source_json from fragments where session_key=? order by json_extract(source_json,\'$.office.seq\')', (key,)))
            first, last = data['firstPacket'], data['lastPacket']
            position = bisect.bisect_right(starts, first) - 1
            if position < 0:
                raise ValueError('session outside source timeline')
            source = sources[position]
            if first < source['mixed_first_ms'] or last > source['mixed_last_ms'] + 1:
                raise ValueError('session crosses independent capture boundary')
            label, label_state = source.get('label_binary'), source['label_state']
            campaign = auxiliary = unmatched = None
            if source.get('observation_path'):
                name = source['observation_path']
                if name not in observations:
                    observations[name] = json.loads(Path(name).read_text())['packets']
                campaign, auxiliary, unmatched = membership(data, observations[name], source['shift_ms'])
                if unmatched:
                    label, label_state = None, 'unmatched_packet_membership'
                elif auxiliary and campaign:
                    label, label_state = None, 'mixed_campaign_and_auxiliary'
                elif auxiliary:
                    label, label_state = None, 'auxiliary_generated_capture'
            label_counts[label_state] = label_counts.get(label_state, 0) + 1
            row = [key, source['dataset'], label, label_state,
                   source.get('campaign_id'), source.get('technique'), source.get('arm'),
                   source['sha256'], first - source['shift_ms'], last - source['shift_ms'],
                   source['shift_ms'], True, cell(source.get('original_contexts', [])),
                   json.loads(summary)['fragments'], bool(started), bool(ended),
                   campaign, auxiliary, unmatched]
            writer.writerow(row + [cell(data[p]) if p in data else '' for p in paths])
            count += 1
    fragments = 0
    with (out / 'arkime_fragments_full_spi.csv').open('w', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow(['session_key', 'index_name', 'document_id', 'revision', 'source_json'])
        for row in db.execute('select session_key,index_name,id,revision,source_json from fragments order by rowid'):
            writer.writerow(row)
            fragments += 1
    with (out / 'arkime_fields_catalog.csv').open('w', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow(['field_id', 'definition_json'])
        for record in definitions:
            writer.writerow([record['field_id'], cell(record['definition'])])
    manifest = {'sessions': count, 'fragments': fragments, 'arkime_columns': len(paths),
                'catalog_definitions': len(definitions), 'cosmolake_uploads': 0,
                'label_states': label_counts,
                'cell_encoding': 'JSON; empty cell means absent, null means explicit null',
                'scalar_aggregation': 'distinct observations except documented counter sums, min/max packet times, latest cumulative entropy',
                'scope': 'full observed sessions within each original capture; capture boundaries may limit completeness',
                'files': {}}
    for path in out.glob('*.csv'):
        with path.open(newline='') as handle:
            reader = csv.reader(handle)
            width = len(next(reader))
            rows = 0
            for row in reader:
                if len(row) != width:
                    raise ValueError('CSV width mismatch')
                rows += 1
        digest = hashlib.sha256()
        with path.open('rb') as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(block)
        manifest['files'][path.name] = {'rows': rows, 'columns': width,
                                      'bytes': path.stat().st_size, 'sha256': digest.hexdigest()}
    (out / 'COMPLETE.json').write_text(json.dumps(manifest, indent=2) + '\n')
    db.close()
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('state', 'catalog', 'provenance', 'out'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    print(cell(export(args.state, args.catalog, args.provenance, args.out)))
