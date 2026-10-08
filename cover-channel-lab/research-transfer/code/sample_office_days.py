"""Sample complete office session groups from a verified clean reference.

Selection uses only TCP/web eligibility and a fixed SHA-256 rank, never a
classifier score. All segments of the selected session are retained, including
segments that do not independently pass the packet-count eligibility filter.
Run against saved clean tables, not scenario/control compositions.
"""
import argparse
import hashlib
import json
from pathlib import Path
import pyarrow as pa
import pyarrow.parquet as pq

RANK_DOMAIN = 'office-additional-days-v1:'


def select_session_ids(rows, limit):
    if limit < 1: raise ValueError('limit must be positive')
    candidates = set()
    for r in rows:
        if r['proto'] == 'tcp' and r['dest_port'] in (80, 443) and (r['pkt_count'] or 0) >= 6:
            if not r['global_session_uid'] or not r['host_key']:
                raise ValueError('eligible sessions require real source session and host keys')
            candidates.add(r['global_session_uid'])
    return set(sorted(candidates, key=lambda uid: (hashlib.sha256((RANK_DOMAIN + uid).encode()).digest(), uid))[:limit])


def sample(reference, out, day_id, limit):
    reference, out = Path(reference), Path(out)
    if out.exists(): raise FileExistsError('retain existing export')
    ref = json.loads(reference.read_text())
    root = Path(ref['path'])
    rel = 'batches/b00000/parquet/office_sessions.parquet'
    source = root / rel
    digest = hashlib.file_digest(source.open('rb'), 'sha256').hexdigest()
    if digest != ref['files'][rel]: raise ValueError('clean reference SHA mismatch')
    if pq.read_table(root/'batches/b00000/parquet/segment_gt.parquet').num_rows:
        raise ValueError('reference contains injected ground truth')
    fields = ['global_session_uid', 'host_key', 'proto', 'dest_port', 'pkt_count']
    meta = pq.read_table(source, columns=fields).to_pylist()
    selected = select_session_ids(meta, limit)
    pieces=[]
    for batch in pq.ParquetFile(source).iter_batches(batch_size=8192):
        mask=pa.array([v in selected for v in batch.column(batch.schema.get_field_index('global_session_uid')).to_pylist()])
        filtered=pa.Table.from_batches([batch]).filter(mask)
        if filtered.num_rows: pieces.append(filtered)
    table=pa.concat_tables(pieces)
    if table.num_columns != 155: raise ValueError('expected full 155-column office contract')
    table=table.append_column('capture_day_id', pa.array([day_id]*table.num_rows))
    table=table.append_column('independent_source_group', pa.array([day_id+':client:'+str(v) for v in table['host_key'].to_pylist()]))
    table=table.append_column('source_session_group', table['global_session_uid'])
    out.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table,out,compression='zstd')
    tls=table['tls_version'].to_pylist()
    report={'selection_version':'office-additional-days-v1','source_sha256':digest,
            'source_rows':len(meta),'selected_sessions':len(selected),'rows':table.num_rows,
            'client_day_groups':len(set(table['independent_source_group'].to_pylist())),
            'tls_version_nonzero_rows':sum(bool(v) for v in tls), 'tls_version_null_rows':sum(v is None for v in tls),
            'rows_with_payload_matched':sum(bool(v) for v in table['payload_matched'].to_pylist()),
            'selected_sha256':hashlib.file_digest(out.open('rb'),'sha256').hexdigest(),
            'selection':'TCP, destination port 80 or 443, at least 6 packets in any segment; first N unique source sessions by SHA256 rank; retain all their segments',
            'clean_reference_sha_verified':True,'injected_ground_truth_rows':0}
    out.with_suffix('.selection.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--reference',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--day-id',required=True)
    p.add_argument('--limit',type=int,default=4000)
    a=p.parse_args(); print(json.dumps(sample(a.reference,a.out,a.day_id,a.limit)))
