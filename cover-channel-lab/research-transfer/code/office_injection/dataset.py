"""Export separate features/labels with session-level positive membership.

Office background is unlabelled, and the current Stage M CI captures cannot
pass --for-training. Source lineage never enters the feature matrices.
"""
import argparse
import json
from pathlib import Path
from datetime import timezone
from zoneinfo import ZoneInfo
import pyarrow as pa
import pyarrow.parquet as pq
from .feature_contract import is_feature
from .pipeline import dump
from .training_contract import (is_training_feature, validate_training_contract,
                                training_authorized_for_run, label_for_memberships, VERSION)
from .training_contract import source_identity
from .source import sha256


def seal_bundle(run, out):
    """Copy exact research exports into an immutable, content-addressed bundle."""
    import shutil
    from .cover_registry import digest
    run=Path(run);out=Path(out)
    required=('cover_registry.json','source_lock.json','runtime_manifest.json','mapping_manifest.json',
              'source_split_manifest.json','positive_registry.json','validated.json','observation_manifest.json')
    missing=[name for name in required if not (run/name).is_file()]
    if missing:raise ValueError('incomplete bundle contracts: '+', '.join(missing))
    tables=sorted(run.glob('batches/*/parquet/*.parquet'))
    if not tables:raise ValueError('no tables to seal')
    inputs=[run/n for n in required]+tables+sorted((run/'evaluation-v2').glob('*.json'))
    inputs+=sorted((run/'exports').rglob('*.parquet'))+sorted((run/'exports').rglob('*.json'))
    inputs+=sorted((run/'campaign_windows').rglob('*.parquet'))+sorted((run/'campaign_windows').rglob('*.json'))
    inputs+=[run/n for n in ('full_campaign_registry.json','coverage.json','mechanic_evidence.json','source_prerequisites.json','offline_checks.json','pipeline_code_manifest.json','clean_reference.json') if (run/n).is_file()]
    inputs+=sorted((run/'wire_evidence').rglob('*'))
    inputs=[p for p in inputs if p.is_file()]
    inputs=sorted(set(inputs))
    files=[{'path':str(p.relative_to(run)),'sha256':sha256(p),'bytes':p.stat().st_size} for p in inputs]
    manifest={'version':'cover-bundle-v1','source_identity':source_identity(run),'files':files,'production_ready':False}
    manifest={**manifest,'sha256':digest(manifest)}
    if out.exists():
        saved=json.loads((out/'bundle.json').read_text())
        if saved!=manifest:raise ValueError('sealed bundle already holds another revision')
        for f in files:
            if sha256(out/f['path'])!=f['sha256']:raise ValueError('sealed bytes modified')
        return manifest
    out.mkdir(parents=True)
    for item in files:
        target=out/item['path'];target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(run/item['path'],target)
    (out/'bundle.json').write_text(json.dumps(manifest,indent=2)+'\n');return manifest

def export(run,out,for_training=False,exploratory_all=False):
    if for_training and exploratory_all:raise ValueError("exploratory matrix cannot be a training export")
    run=Path(run);out=Path(out)
    report=json.loads((run/'validated.json').read_text())
    gate=run/'evaluation-v2'/'naturalness.json'
    if not gate.exists():gate=run/'naturalness.json'  # legacy diagnostics, never authorizes training
    nat=json.loads(gate.read_text()) if gate.exists() else {}
    passed=training_authorized_for_run(nat,run)
    # admitted_features = technique_marker_features: comparable across origin
    # AND informative about the covert value on held-out pairs (see naturalness.py).
    # A run whose decision is no_signal_in_current_features exports zero columns,
    # by design -- there is nothing here a downstream model could learn honestly.
    admitted=set(nat.get('admitted_features',[])) if nat and not exploratory_all else None
    if for_training and not passed:
        raise ValueError('not training-ready: a current, frozen signal/domain evaluation and explicit contract are required')
    if for_training and nat['source_identity'] != source_identity(run):
        raise ValueError('source rows or ground truth changed after evaluation')
    out.mkdir(parents=True,exist_ok=False)
    registry=json.loads((run/'positive_registry.json').read_text())
    parents={r['campaign_id']:r.get('parent_campaign_id',r['campaign_id']) for r in registry}
    ancestors={r['campaign_id']:r.get('ancestor_group_id') or r.get('template_id') or parents[r['campaign_id']] for r in registry}
    split_path=run/'source_split_manifest.json'
    splits=json.loads(split_path.read_text()).get('campaign_splits',{}) if split_path.exists() else {}
    gt={};segment_sessions={}
    for p in run.glob('batches/*/parquet/office_sessions.parquet'):
        for batch in pq.ParquetFile(p).iter_batches(columns=['global_segment_uid','global_session_uid']):
            for row in batch.to_pylist():
                if row['global_segment_uid'] in segment_sessions:raise ValueError('duplicate feature segment identity')
                segment_sessions[row['global_segment_uid']]=row['global_session_uid']
    feature_sessions=set(segment_sessions.values())
    for p in run.glob('batches/*/parquet/segment_gt.parquet'):
        for r in pq.ParquetFile(p).read().to_pylist():
            if r['global_session_uid'] not in feature_sessions or 'global_segment_uid' in r and segment_sessions.get(r['global_segment_uid'])!=r['global_session_uid']:raise ValueError('GT session identity differs from feature segment')
            gt.setdefault(r['global_session_uid'],[]).append(r)
    manifest={'source_run':report['run_id'],'role':report.get('source_role','challenge_only'),
              'production_training_ready':False,'naturalness_gate':'passed' if passed else 'not_passed',
              'feature_admission':'exploratory_safe_only' if exploratory_all else 'admitted_only' if admitted is not None else 'all_pinned',
              'admitted_feature_count':len(admitted) if admitted is not None else None,
              'decision':nat.get('decision'),
              'joint_domain_auc_on_admitted':(nat.get('confirmation',{}).get('joint_domain_auc_on_technique_markers') or {}).get('auc'),
              'technique_signal_auc_on_admitted':(nat.get('confirmation',{}).get('B_scenario_vs_control_on_technique_markers') or {}).get('auc'),
              'evaluation_version': VERSION, 'background_label':'office_unlabelled','batches':[],
              'split_policy':'group by template ancestor and office capture day; all derivatives stay together'}
    for p in sorted(run.glob('batches/*/parquet/office_sessions.parquet')):
        # ParquetFile avoids treating the surrounding batch directory as a
        # hive partition and adding accidental path columns.
        reader=pq.ParquetFile(p)
        columns=[n for n in reader.schema_arrow.names if is_training_feature(n) and (admitted is None or n in admitted)]
        if for_training:
            required=nat['training_contract']['features']
            if set(required) != set(columns):raise ValueError('evaluated features unavailable in dataset')
            columns=list(required)
        contract=validate_training_contract(columns) if columns else None
        if for_training and contract != nat.get('training_contract'):
            raise ValueError('serve/train feature order or availability differs from evaluated contract')
        writer=None;labels=[];batch=out/p.parents[1].name;batch.mkdir()
        try:
            for record in reader.iter_batches(batch_size=2048):
                table=pa.Table.from_batches([record])
                if columns:
                    # A zero-column table's row count does not survive a Parquet
                    # round trip (write_table on an empty schema writes num_rows=0
                    # regardless of the in-memory table): confirmed by direct
                    # reproduction 2026-09-28, caught by an external review of an
                    # earlier "ALL CHECKS PASSED" claim that never read features.parquet's
                    # own row count, only its column names. So no features.parquet
                    # is written at all when nothing is admitted -- labels.parquet
                    # alone (rows/labels/campaign metadata, unaffected) is the record.
                    features=table.select(columns)
                    if writer is None:writer=pq.ParquetWriter(batch/'features.parquet',features.schema,compression='zstd')
                    writer.write_table(features)
                for uid,seg,stamp in zip(table['global_session_uid'].to_pylist(),table['global_segment_uid'].to_pylist(),table['segment_start_ts'].to_pylist()):
                    memberships=gt.get(uid,[])
                    target,state=label_for_memberships(memberships)
                    labels.append({'global_session_uid':uid,'global_segment_uid':seg,
                        # Matched controls are the only certified negatives; office stays unlabelled.
                        'label_binary':target, 'label_state':state,
                        'campaign_ids':sorted({r['campaign_id'] for r in memberships}),
                        'parent_campaign_ids':sorted({parents[r['campaign_id']] for r in memberships}),
                        'ancestor_group_ids':sorted({ancestors[r['campaign_id']] for r in memberships}),
                        'office_capture_day':stamp.replace(tzinfo=timezone.utc).astimezone(ZoneInfo('Europe/Moscow')).date().isoformat(),
                        'source_split': next(iter({splits.get(r['campaign_id'],'challenge_only') for r in memberships}), 'office_unlabelled'),
                        'training_eligible':bool(passed and memberships)})
        finally:
            if writer is not None:writer.close()
        schema=pa.schema([('global_session_uid',pa.string()),('global_segment_uid',pa.string()),
                         ('label_binary',pa.int64()),('label_state',pa.string()),
                         ('campaign_ids',pa.list_(pa.string())),('parent_campaign_ids',pa.list_(pa.string())),
                         ('ancestor_group_ids',pa.list_(pa.string())),
                         ('office_capture_day',pa.string()),('source_split',pa.string()),('training_eligible',pa.bool_())])
        pq.write_table(pa.Table.from_pylist(labels,schema=schema),batch/'labels.parquet',compression='zstd')
        if columns and pq.ParquetFile(batch/'features.parquet').metadata.num_rows != len(labels):
            raise ValueError('feature/label row count mismatch')
        manifest['batches'].append({'batch':batch.name,'rows':len(labels),'features':columns,'training_contract':contract,
                                    'features_file':'features.parquet' if columns else None,
                                    'positive_rows':sum(x['label_binary']==1 for x in labels),
                                    'control_rows':sum(x['label_state']=='matched_control' for x in labels),
                                    'hard_negative_rows':sum(x['label_state']=='hard_negative' for x in labels),
                                    'unlabelled_rows':sum(x['label_binary'] is None for x in labels)})
    if not manifest['batches']:raise ValueError('no session parquet batches to export')
    if for_training and not all(sum(b[k] for b in manifest['batches']) for k in ('positive_rows','control_rows')):
        raise ValueError('both confirmed classes required')
    dump(out/'manifest.json',manifest)
    dump(out/'COMPLETE.json',{'manifest_sha256':sha256(out/'manifest.json'),
                            'files':{str(p.relative_to(out)):sha256(p) for p in out.glob('*/*.parquet')}})
    return manifest

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',required=True);p.add_argument('--out',required=True)
    p.add_argument('--for-training',action='store_true');p.add_argument('--exploratory-all',action='store_true',help='export all safe session candidates for exploration; no training bypass');a=p.parse_args();print(json.dumps(export(a.run,a.out,a.for_training,a.exploratory_all),indent=2))

if __name__=='__main__':main()
