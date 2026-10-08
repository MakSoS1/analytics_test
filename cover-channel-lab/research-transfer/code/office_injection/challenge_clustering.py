"""Export verified generated sessions for exploratory, technique-labelled clustering.

Only generated scenario/control sessions with immutable observed ground truth
are included. Office background without ground truth remains unknown and is
excluded. The technique/arm labels are stored separately from the feature
matrix and must not be supplied to the clustering algorithm.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from . import training_contract as contract
from .training_contract import source_identity
from .pipeline import dump
from .source import sha256


def export(run, out, *, min_pairs_per_technique=10, min_techniques=10):
    run, out = Path(run), Path(out)
    if out.exists():
        raise FileExistsError('clustering output must be a new directory')
    validated_path, registry_path = run / 'validated.json', run / 'positive_registry.json'
    if not validated_path.is_file() or not registry_path.is_file():
        raise ValueError('validated run and generated-session registry are required')
    validated = json.loads(validated_path.read_text())
    if validated.get('status') != 'validated_local':
        raise ValueError('only a completed validated_local run is eligible')
    registry = json.loads(registry_path.read_text())
    if not registry:
        raise ValueError('empty generated-session registry')

    campaigns, pairs = {}, defaultdict(dict)
    expected_by_uid, expected_by_campaign = {}, defaultdict(set)
    for item in registry:
        campaign, arm, parent = item.get('campaign_id'), item.get('arm'), item.get('parent_campaign_id')
        template = item.get('ancestor_group_id') or item.get('template_id')
        if not campaign or campaign in campaigns or arm not in ('scenario', 'control') or not parent or not template:
            raise ValueError('registry has missing or duplicate campaign lineage')
        if item.get('generated') is not True:
            raise ValueError('challenge clustering requires locally generated sessions')
        if item.get('control_kind') != 'benign_application':
            raise ValueError('only matched benign-application controls are admissible')
        if item.get('label_scope') != 'transport_session_generated_on_office_skeleton':
            raise ValueError('unsupported generated-session label scope')
        if item.get('semantic_scope') != 'application_message_fixture':
            raise ValueError('unsupported application-semantic scope')
        campaigns[campaign] = item
        if arm in pairs[parent]:
            raise ValueError('duplicate arm in matched pair')
        pairs[parent][arm] = item
    if any(set(arms) != {'scenario', 'control'} for arms in pairs.values()):
        raise ValueError('every matched template must have one scenario and one control')
    for arms in pairs.values():
        if len({str(item.get('technique')) for item in arms.values()}) != 1:
            raise ValueError('matched arms disagree on technique')
        if len({str(item.get('template_id')) for item in arms.values()}) != 1:
            raise ValueError('matched arms do not share the same office skeleton')

    gt_packets = 0
    for path in sorted(run.glob('batches/*/parquet/segment_gt.parquet')):
        for row in pq.read_table(path).to_pylist():
            item = campaigns.get(row.get('campaign_id'))
            if item is None or row.get('arm') != item.get('arm') or row.get('injection_id') != item.get('injection_id'):
                raise ValueError('ground-truth campaign/arm differs from generated registry')
            expected_state = 'positive_confirmed' if row['arm'] == 'scenario' else 'negative_control_confirmed'
            if row.get('label_state') != expected_state or int(row.get('positive_packet_count') or 0) < 1:
                raise ValueError('ground-truth packet membership is incomplete or class is inconsistent')
            uid, segment = row.get('global_session_uid'), row.get('global_segment_uid')
            if not uid or not segment or uid in expected_by_uid:
                raise ValueError('ground-truth session membership is missing or duplicated')
            expected_by_uid[uid] = row
            expected_by_campaign[row['campaign_id']].add(uid)
            gt_packets += int(row['positive_packet_count'])
    if not expected_by_uid or gt_packets != int(validated.get('gt_positive_packets', -1)):
        raise ValueError('packet totals do not match the immutable generated ground truth')
    if gt_packets != int(validated.get('positive_packets', -2)):
        raise ValueError('generated packet totals do not match ground truth')
    if set(expected_by_campaign) != set(campaigns) or any(len(v) != 1 for v in expected_by_campaign.values()):
        raise ValueError('every generated campaign must map to exactly one observed feature session')

    feature_names = list(contract.SESSION_FEATURES)
    feature_contract = contract.validate_training_contract(feature_names)
    feature_rows = {}
    for path in sorted(run.glob('batches/*/parquet/office_sessions.parquet')):
        reader = pq.ParquetFile(path)
        needed = ['global_session_uid', 'global_segment_uid', *feature_names]
        if any(name not in reader.schema_arrow.names for name in needed):
            raise ValueError('session feature table does not implement the pinned 89-feature contract')
        for batch in reader.iter_batches(batch_size=4096, columns=needed):
            for row in pa.Table.from_batches([batch]).to_pylist():
                uid = row['global_session_uid']
                if uid not in expected_by_uid:
                    continue  # office rows have no confirmed label and stay out of X/y
                if row['global_segment_uid'] != expected_by_uid[uid]['global_segment_uid']:
                    raise ValueError('feature session and generated ground-truth segment keys disagree')
                if uid in feature_rows:
                    raise ValueError('generated session has duplicate feature rows')
                feature_rows[uid] = {name: row[name] for name in feature_names}
    if set(feature_rows) != set(expected_by_uid):
        raise ValueError('verified generated sessions and extracted feature rows do not match')

    per_technique = Counter(item['technique'] for item in campaigns.values() if item['arm'] == 'scenario')
    missing = {tech: count for tech, count in per_technique.items() if count < min_pairs_per_technique}
    if len(per_technique) < min_techniques or missing:
        raise ValueError(f'insufficient matched data for technique clustering: '
                         f'{len(per_technique)} techniques; underfilled={missing}; '
                         f'require {min_techniques} techniques x {min_pairs_per_technique} pairs')

    ordered = []
    for parent in sorted(pairs):
        for arm in ('scenario', 'control'):
            item = pairs[parent][arm]
            uid = next(iter(expected_by_campaign[item['campaign_id']]))
            gt = expected_by_uid[uid]
            ordered.append({
                'uid': uid, 'features': feature_rows[uid],
                'label': 1 if arm == 'scenario' else 0,
                'arm': arm, 'technique': item['technique'],
                'campaign': item['campaign_id'], 'parent': parent,
                'template': str(item.get('ancestor_group_id') or item['template_id']),
                'template_day': str(item.get('template_moscow_date') or ''),
                'gt_state': gt['label_state'],
            })
    if len(ordered) != len(expected_by_uid) or {r['label'] for r in ordered} != {0, 1}:
        raise ValueError('export rows do not cover exactly the two verified classes')

    out.mkdir(parents=True)
    x_schema = pa.schema([(name, pa.float64()) for name in feature_names])
    x_table = pa.Table.from_pylist([row['features'] for row in ordered], schema=x_schema)
    metadata_schema = pa.schema([
        ('row_index', pa.int64()), ('label_binary', pa.int64()), ('arm', pa.string()),
        ('technique', pa.string()), ('global_session_uid', pa.string()),
        ('campaign_id', pa.string()), ('parent_campaign_id', pa.string()),
        ('template_group_id', pa.string()), ('template_source_day', pa.string()),
        ('ground_truth_state', pa.string()),
    ])
    metadata_table = pa.Table.from_pylist([{
        'row_index': index, 'label_binary': row['label'], 'arm': row['arm'],
        'technique': row['technique'], 'global_session_uid': row['uid'],
        'campaign_id': row['campaign'], 'parent_campaign_id': row['parent'],
        'template_group_id': row['template'], 'template_source_day': row['template_day'],
        'ground_truth_state': row['gt_state'],
    } for index, row in enumerate(ordered)], schema=metadata_schema)
    x_path, metadata_path = out / 'features.parquet', out / 'metadata.parquet'
    pq.write_table(x_table, x_path, compression='zstd')
    pq.write_table(metadata_table, metadata_path, compression='zstd')
    if pq.ParquetFile(x_path).metadata.num_rows != pq.ParquetFile(metadata_path).metadata.num_rows:
        raise ValueError('feature and interpretation metadata row counts differ')

    label_counts = Counter(row['label'] for row in ordered)
    technique_counts = {}
    for technique in sorted(per_technique):
        selected = [row for row in ordered if row['technique'] == technique]
        technique_counts[technique] = {
            'sessions': len(selected), 'pairs': len(selected) // 2,
            'scenario': sum(row['label'] == 1 for row in selected),
            'control': sum(row['label'] == 0 for row in selected),
        }
    manifest = {
        'status': 'exploratory_clustering_ready', 'experiment_role': 'challenge_only',
        'source_run': validated.get('run_id'),
        'source_identity': source_identity(run),
        'feature_contract': feature_contract, 'feature_order': feature_names,
        'rows': len(ordered), 'pairs': len(pairs), 'technique_count': len(per_technique),
        'label_counts': {'control_0': label_counts[0], 'scenario_1': label_counts[1]},
        'per_technique': technique_counts,
        'template_source_days': sorted({row['template_day'] for row in ordered if row['template_day']}),
        'feature_file': {'path': 'features.parquet', 'sha256': sha256(x_path), 'columns': feature_names},
        'interpretation_file': {'path': 'metadata.parquet', 'sha256': sha256(metadata_path)},
        'row_alignment': 'metadata.row_index aligns positionally with features.parquet; remove metadata before clustering',
        'clustering_scope': 'all verified generated scenario/control sessions; no train/test split by user request',
        'background_policy': 'office rows without generated ground truth are unknown and excluded',
        'production_training_ready': False,
        'transfer_status': 'unverified; source templates cover one day and no office positive holdout exists',
        'notice': 'Technique, arm, label, IDs, source day, and lineage are metadata only; never include them in X.',
    }
    dump(out / 'manifest.json', manifest)
    files = [x_path, metadata_path, out / 'manifest.json']
    dump(out / 'COMPLETE.json', {'manifest_sha256': sha256(out / 'manifest.json'),
                                 'files': {str(path.relative_to(out)): sha256(path) for path in files}})
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--min-pairs-per-technique', type=int, default=10)
    parser.add_argument('--min-techniques', type=int, default=10)
    args = parser.parse_args()
    result = export(args.run, args.out, min_pairs_per_technique=args.min_pairs_per_technique,
                    min_techniques=args.min_techniques)
    print(json.dumps({key: result[key] for key in ('status', 'rows', 'pairs', 'technique_count',
                                                   'label_counts', 'per_technique', 'production_training_ready')}, indent=2))


if __name__ == '__main__':
    main()
