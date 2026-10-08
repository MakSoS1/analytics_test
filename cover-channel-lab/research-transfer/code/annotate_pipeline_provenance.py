"""Attach capture provenance to an already verified pipeline comparison export."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil

import pyarrow as pa
import pyarrow.parquet as pq


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def annotate(root):
    target = root / 'pipeline_office_sessions.parquet'
    backup = root / 'pipeline_office_sessions_original_155.parquet'
    if backup.exists():
        raise ValueError('Original backup already exists; inspect before rerunning')
    own = pq.read_table(target)
    native = pq.read_table(root / 'arkime_sessions_all_fields.parquet')
    bridge = pq.read_table(root / 'session_comparison.parquet').to_pylist()
    metadata = [name for name in native.column_names
                if not name.startswith('arkime.')
                and name not in ('session_key', 'arkime_present_fields')]
    rows = native.select(['session_key'] + metadata).to_pylist()
    by_key = {row['session_key']: row for row in rows}
    assert len(by_key) == native.num_rows
    matches = {}
    for row in bridge:
        if row['status'] != 'exact':
            continue
        for uid in row['pipeline_segment_uids']:
            assert uid not in matches, 'Ambiguous segment provenance'
            matches[uid] = row['arkime_session_key']
    office = [r for r in rows if r['dataset'] == 'office_background_20260923']
    bounds = (min(r['source_first_ms'] for r in office),
              max(r['source_last_ms'] for r in office))
    # Existing source preparation isolates each generated capture in time.
    # Require every generated session to be outside the entire office window.
    assert all(r['source_last_ms'] < bounds[0] or r['source_first_ms'] > bounds[1]
               for r in rows if r['dataset'] == 'generated_cover')
    additions = []
    statuses = []
    keys = []
    for row in own.select(['global_segment_uid', 'segment_start_ts',
                           'segment_end_ts']).to_pylist():
        key = matches.get(row['global_segment_uid'])
        if key is not None:
            additions.append(by_key[key])
            statuses.append('exact_session_match')
        else:
            start = row['segment_start_ts'].timestamp() * 1000
            end = row['segment_end_ts'].timestamp() * 1000
            if bounds[0] - 2 <= start <= end <= bounds[1] + 2:
                additions.append({'dataset': 'office_background_20260923',
                                  'label_state': 'unlabelled_office'})
                statuses.append('isolated_office_time_window_no_session_match')
            else:
                additions.append({})
                statuses.append('unresolved')
        keys.append(key)
    assert 'unresolved' not in statuses, 'Unresolved origin; do not invent labels'
    result = own
    names = {}
    for name in metadata:
        output_name = 'origin_' + name if name in own.column_names else name
        assert output_name not in result.column_names
        names[name] = output_name
        result = result.append_column(output_name, pa.array(
            [r.get(name) for r in additions], type=native.schema.field(name).type))
    result = result.append_column('provenance_match_status', pa.array(statuses))
    result = result.append_column('arkime_session_key', pa.array(keys, pa.large_string()))
    tmp = root / 'pipeline_office_sessions.annotated.tmp.parquet'
    pq.write_table(result, tmp, compression='zstd')
    reread = pq.read_table(tmp)
    assert reread.select(own.column_names).equals(own)
    for index, key in enumerate(keys):
        if key is None:
            assert reread['label_binary'][index].as_py() is None
            assert reread['technique'][index].as_py() is None
            continue
        for source_name, output_name in names.items():
            assert reread[output_name][index].as_py() == by_key[key][source_name]
    # Independently verify against the already exported wide comparison table.
    wide = pq.read_table(root / 'matched_pipeline_arkime.parquet')
    annotated_index = {uid: i for i, uid in enumerate(reread['global_segment_uid'].to_pylist())}
    aligned = reread.take(pa.array([annotated_index[uid] for uid in
                                  wide['pipeline.global_segment_uid'].to_pylist()]))
    for source_name, output_name in names.items():
        assert aligned[output_name].equals(wide['arkime_meta.' + source_name])
    report = {'rows': reread.num_rows, 'original_columns': own.num_columns,
              'annotated_columns': reread.num_columns,
              'original_sha256': sha(target), 'annotated_sha256': sha(tmp),
              'all_original_columns_unchanged': True,
              'all_exact_metadata_cells_verified': True,
              'independent_wide_table_metadata_verified': True,
              'match_status_counts': dict(Counter(statuses)),
              'dataset_counts': dict(Counter(reread['dataset'].to_pylist())),
              'label_state_counts': dict(Counter(reread['label_state'].to_pylist())),
              'adaptix_counts': dict(Counter(
                  f"{r.get('technique')}|{r.get('arm')}|{r.get('label_state')}"
                  for r in additions if str(r.get('technique')).startswith('ADAPTIX_'))),
              'metadata_column_mapping': names,
              'office_interval_ms': list(bounds),
              'unmatched_office_label_binary': None,
              'original_production_labels_preserved': True,
              'source_hashes': {n: sha(root / n) for n in
                  ('arkime_sessions_all_fields.parquet', 'session_comparison.parquet',
                   'matched_pipeline_arkime.parquet')},
              'cosmolake_uploads': 0}
    shutil.copy2(target, backup)
    tmp.replace(target)
    (root / 'PROVENANCE_ANNOTATION.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    annotate(parser.parse_args().directory)
