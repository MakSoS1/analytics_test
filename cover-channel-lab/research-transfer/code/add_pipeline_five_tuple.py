"""Add original IP endpoints and ports from verified dictionaries."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

import pyarrow as pa
import pyarrow.parquet as pq


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def enrich(root):
    target = root / 'pipeline_office_sessions.parquet'
    backup = root / 'pipeline_office_sessions_annotated_175.parquet'
    if backup.exists():
        raise ValueError('Backup exists; inspect before rerunning')
    original = pq.read_table(target)
    addresses = json.loads((root / 'ip_key_dictionary.json').read_text())
    ports = json.loads((root / 'session_port_dictionary.json').read_text())
    proof = json.loads((root / 'SESSION_PORT_VERIFICATION.json').read_text())
    assert digest(root / 'session_port_dictionary.json') == proof['dictionary_sha256']
    assert len(ports) == original.num_rows
    endpoint_rows = []
    for row in original.select(['global_segment_uid', 'host_key', 'server_key',
                                'dest_port', 'proto']).to_pylist():
        pair = ports[row['global_segment_uid']]
        assert pair['server_port'] == row['dest_port']
        assert row['proto'].lower() in ('tcp', 'udp')
        endpoint_rows.append({
            'source_ip': addresses[row['host_key']],
            'source_port': pair['client_port'],
            'destination_ip': addresses[row['server_key']],
            'destination_port': pair['server_port'],
            'ip_protocol': 6 if row['proto'].lower() == 'tcp' else 17})
    schema = pa.schema([('source_ip', pa.string()), ('source_port', pa.int64()),
                        ('destination_ip', pa.string()), ('destination_port', pa.int64()),
                        ('ip_protocol', pa.int64())])
    endpoints = pa.Table.from_pylist(endpoint_rows, schema=schema)
    result = original
    for name in endpoints.column_names:
        assert name not in original.column_names
        result = result.append_column(name, endpoints[name])
    # Independent check against native Arkime, reversing its endpoints when
    # its first-packet direction differs from the pipeline's chosen client.
    wide = pq.read_table(root / 'matched_pipeline_arkime.parquet', columns=[
        'pipeline.global_segment_uid', 'comparison.same_direction',
        'arkime.source.ip', 'arkime.source.port', 'arkime.destination.ip',
        'arkime.destination.port', 'arkime.ipProtocol'])
    lookup = dict(zip(original['global_segment_uid'].to_pylist(), endpoint_rows))
    reverse = 0
    for row in wide.to_pylist():
        own = lookup[row['pipeline.global_segment_uid']]
        same = row['comparison.same_direction']
        reverse += not same
        src = 'source' if same else 'destination'
        dst = 'destination' if same else 'source'
        assert own == {'source_ip': row[f'arkime.{src}.ip'],
                       'source_port': row[f'arkime.{src}.port'],
                       'destination_ip': row[f'arkime.{dst}.ip'],
                       'destination_port': row[f'arkime.{dst}.port'],
                       'ip_protocol': row['arkime.ipProtocol']}
    tmp = root / 'pipeline_office_sessions.five_tuple.tmp.parquet'
    pq.write_table(result, tmp, compression='zstd')
    reread = pq.read_table(tmp)
    assert reread.select(original.column_names).equals(original)
    assert reread.select(endpoints.column_names).equals(endpoints)
    assert all(reread[name].null_count == 0 for name in endpoints.column_names)
    report = {'rows': reread.num_rows, 'columns': reread.num_columns,
              'original_columns_preserved': original.num_columns,
              'explicit_five_tuple_columns': endpoints.column_names,
              'all_rows_have_full_five_tuple': True,
              'independent_arkime_matches_verified': wide.num_rows,
              'arkime_direction_reversed_for_verification': reverse,
              'original_sha256': digest(target), 'enriched_sha256': digest(tmp),
              'orientation': 'source is pipeline client; destination is pipeline server',
              'unmatched_sessions': '3 DHCP instances verified using original pipeline indexes',
              'protocol_values': {'tcp': 6, 'udp': 17},
              'cosmolake_uploads': 0}
    shutil.copy2(target, backup)
    tmp.replace(target)
    (root / 'FIVE_TUPLE_VERIFICATION.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    enrich(parser.parse_args().directory)
