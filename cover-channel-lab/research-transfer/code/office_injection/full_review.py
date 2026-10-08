"""Offline source, schema, GT and export validation. Contains no upload calls."""
from pathlib import Path
import json
from .source import sha256
from .cover_registry import digest
from .pipeline import dump


def verify_seal(root,bundle):
    root=Path(root)
    if bundle.get('sha256')!=digest({k:v for k,v in bundle.items() if k!='sha256'}):raise ValueError('bundle identity changed')
    for row in bundle['files']:
        p=root/row['path']
        if p.stat().st_size!=row['bytes'] or sha256(p)!=row['sha256']:raise ValueError('sealed bytes changed: '+row['path'])
    return {'files_verified':len(bundle['files']),'bundle_sha256':bundle['sha256']}


def audit_tables(root):
    import pyarrow as pa,pyarrow.parquet as pq,pyarrow.compute as pc
    from .training_contract import label_for_memberships
    root=Path(root);expected={r['campaign_id'] for r in json.loads((root/'positive_registry.json').read_text())}
    actual=set();gt={};segments=set();counts={'rows':0,'array_packets':0,'gt_packets':0,'feature_packets':0}
    for p in root.glob('batches/*/parquet/segment_gt.parquet'):
        for row in pq.ParquetFile(p).read().to_pylist():
            actual.add(row['campaign_id']);gt.setdefault(row['global_segment_uid'],[]).append(row);counts['gt_packets']+=row['positive_packet_count']
    if expected!=actual:raise ValueError('transport campaign ID sets differ')
    for memberships in gt.values():label_for_memberships(memberships)
    arrays=('seq_signed_len','seq_iat_us','seq_payload_len')
    # Schema itself determines the pinned payload sequence name.
    for p in root.glob('batches/*/parquet/office_sessions.parquet'):
        reader=pq.ParquetFile(p);names=reader.schema_arrow.names
        sequence_names=[n for n in names if n.startswith('seq_') and pa.types.is_list(reader.schema_arrow.field(n).type)]
        if not sequence_names:raise ValueError('packet arrays missing')
        for batch in reader.iter_batches(batch_size=1024,columns=['global_segment_uid','global_session_uid','pkt_count']+sequence_names):
            t=pa.Table.from_batches([batch]);uids=t['global_segment_uid'].to_pylist()
            if any(u in segments for u in uids) or len(set(uids))!=len(uids):raise ValueError('duplicate physical segment')
            for uid,session in zip(uids,t['global_session_uid'].to_pylist()):
                if any(r['global_session_uid']!=session for r in gt.get(uid,[])):raise ValueError('GT session identity differs from segment identity')
            segments.update(uids);counts['rows']+=len(uids)
            lengths={n:pc.list_value_length(t[n]).to_pylist() for n in sequence_names}
            expected_lengths=t['pkt_count'].to_pylist()
            if any(values!=expected_lengths for values in lengths.values()):raise ValueError('packet array lengths differ from packet count')
            counts['array_packets']+=sum(lengths[sequence_names[0]]);counts['feature_packets']+=sum(expected_lengths)
    if not set(gt)<=segments:raise ValueError('GT refers to absent segment')
    validated=json.loads((root/'validated.json').read_text())
    if counts['feature_packets']!=validated['emitted_feature_packets'] or counts['gt_packets']!=validated['positive_packets']:raise ValueError('composite feature/GT accounting differs')
    all_ids={r['campaign_id'] for r in json.loads((root/'full_campaign_registry.json').read_text())}
    research_ids={r['campaign_id'] for r in json.loads((root/'observation_manifest.json').read_text())['observations'] if r['supported_rows']==0}
    if actual|research_ids!=all_ids:raise ValueError('transport plus separate observation campaign sets differ')
    return {**counts,'campaign_ids_expected':sorted(all_ids),'campaign_ids_actual':sorted(actual|research_ids),
        'transport_campaigns':len(actual),'research_campaigns':len(research_ids),'schema_verified':True,'arrays_verified':True,'packet_accounting_verified':True}


def evaluate_offline(root):
    from .training_contract import source_identity,VERSION,measurement_status
    from .naturalness import load_groups,per_feature,paired_rows
    root=Path(root);groups,pairs,total=load_groups(root)
    scope=sorted({r['campaign_id'] for r in json.loads((root/'positive_registry.json').read_text())})
    split=json.loads((root/'source_split_manifest.json').read_text())
    ambiguous=None
    try:paired=paired_rows(groups,pairs)
    except ValueError as e:ambiguous=str(e);paired=[]
    report={'evaluation_version':VERSION,'source_identity':source_identity(root),'evaluated_campaign_ids':scope,
        'counts':{k:len(v) for k,v in groups.items()},'office_population_total':total,'paired_sessions':len(paired),
        'session_pair_aggregation_limitation':ambiguous,'component_count':split.get('component_count'),
        'decision':'insufficient_data','integrity_status':'passed','technique_status':'not_measured','domain_status':'not_measured',
        'source_split_status':split['status'],'source_split_sha256':split.get('sha256'),'source_split_applied':False,
        'admitted_features':[],'training_contract':None,'gate':'failed','production_training_ready':False,
        'confirmation':{'technique_measurement_complete':False,'B_scenario_vs_control_on_technique_markers':{'auc':None,'reason':'independent held-out day components unavailable'},
            'joint_domain_auc_on_technique_markers':{'auc':None,'reason':'independent held-out day components unavailable'}},
        'marginal_origin_diagnostics':per_feature(groups),'thresholds':{'technique_threshold':.60,'domain_threshold':.75,'admit_auc':.60,'max_missing_gap':.10},
        'policy':'no fitting/feature admission on one connected capture component; marginal AUC diagnostic only; hard negatives separate'}
    if split.get('component_count',0)>=3:raise ValueError('independent components available: execute frozen full evaluation, never substitute insufficient_data')
    report['measurement_status']=measurement_status(report,root,scope)
    dump(root/'evaluation-v2/naturalness.json',report)
    return report


def finalize_offline(root):
    from .dataset import export,seal_bundle
    root=Path(root);checks=audit_tables(root)
    checks['coverage']=audit_scope(root);checks['observations']=audit_observations(root)
    from .compare import compare
    checks['office_preservation']={a:compare(root/'alternatives/clean',root/'alternatives'/a) for a in ('scenario','control')}
    checks['publication_status']='not_attempted_user_hold'
    dump(root/'offline_checks.json',checks)
    (root/'evaluation-v2').mkdir(exist_ok=True)
    report=evaluate_offline(root)
    exports=export(root,root/'exports',exploratory_all=True)
    # Re-read each feature/label file after write: equality is row/order-bound.
    import pyarrow.parquet as pq
    for b in exports['batches']:
        p=root/'exports'/b['batch'];labels=pq.ParquetFile(p/'labels.parquet')
        if pq.ParquetFile(p/'features.parquet').metadata.num_rows!=labels.metadata.num_rows:raise ValueError('X/y rows differ after export')
        for batch in labels.iter_batches(columns=['training_eligible']):
            if any(batch.column(0).to_pylist()):raise ValueError('one component export falsely marked training eligible')
    checks['export_alignment']=audit_exports(root,exports)
    dump(root/'offline_checks.json',checks)
    bundle=seal_bundle(root,root/'sealed')
    return {'checks':checks,'measurement_status':report['measurement_status'],'bundle':bundle['sha256'],'exports':len(exports['batches'])}


def audit_scope(root):
    root=Path(root);registry=json.loads((root/'cover_registry.json').read_text());coverage=json.loads((root/'coverage.json').read_text())
    declared={(e['entry_id'],p['profile_id'],arm) for e in registry['entries'] for p in e['profiles'] for arm in ('scenario','control')}
    campaigns=json.loads((root/'full_campaign_registry.json').read_text())
    actual=[(r['technique'],r['profile_id'],r['arm']) for r in campaigns]
    if len(set(actual))!=len(actual) or set(actual)!=declared:raise ValueError('declared profile-arm coverage differs from accepted campaigns')
    if coverage.get('complete') is not True or coverage.get('registry_sha256')!=registry['sha256'] or coverage.get('expected')!=len(declared) or coverage.get('observed_success')!=len(actual):raise ValueError('coverage identity/counts incomplete')
    children={r['sha256'] for r in registry.get('source_registries',[])}
    scopes=coverage.get('scope_reports',[])
    if not scopes or {r['report']['registry_sha256'] for r in scopes}!=children:raise ValueError('coverage source registry identity differs')
    if any(r['report'].get('complete') is not True for r in scopes):raise ValueError('source coverage scope failed')
    return {'registry_sha256':registry['sha256'],'declared_keys':len(declared),'accepted_keys':len(actual),'requested_key_sha256':digest(sorted(declared)),'scope_reports_verified':True}


def audit_observations(root):
    from .wire_observation import VERSION
    root=Path(root);manifest=json.loads((root/'observation_manifest.json').read_text());packets=0;research=0
    catalog={r['campaign_id']:r for r in json.loads((root/'full_campaign_registry.json').read_text())}
    ids=[r['campaign_id'] for r in manifest['observations']]
    if len(set(ids))!=len(ids) or set(ids)!=set(catalog):raise ValueError('observation campaign coverage differs from full registry')
    for row in manifest['observations']:
        c=catalog[row['campaign_id']]
        if (row['entry_id'],row['profile_id'],row['arm'])!=(c['technique'],c['profile_id'],c['arm']):raise ValueError('observation campaign profile/arm differs')
        relative=Path(row['sealed_observation_path'])
        if relative.is_absolute() or '..' in relative.parts:raise ValueError('observation seal path must be relative')
        p=root/relative;observation=json.loads(p.read_text());body={k:v for k,v in observation.items() if k!='sha256'}
        if observation['sha256']!=digest(body) or observation['sha256']!=row['observation_sha256']:raise ValueError('sealed observation identity differs')
        capture_relative=Path(row['sealed_capture_path'])
        if capture_relative.is_absolute() or '..' in capture_relative.parts:raise ValueError('capture seal path must be relative')
        capture=root/capture_relative
        if observation['sha256']!=c['observation_sha256'] or observation['capture_sha256']!=c['sha256'] or [x['campaign_id'] for x in observation['campaigns']]!=[row['campaign_id']]:raise ValueError('observation inner campaign/hash differs from catalog')
        if sha256(capture)!=observation['capture_sha256']:raise ValueError('sealed observation capture differs')
        if observation['version']!=VERSION or len(observation['packets'])!=row['campaign_packets']:raise ValueError('sealed observation packets differ')
        from .source import read_pcap
        from .wire_observation import _header
        from itertools import zip_longest
        for ordinal,pair in enumerate(zip_longest(read_pcap(capture),observation['packets'])):
            frame_record,packet=pair
            if frame_record is None or packet is None:raise ValueError('observation/capture record counts differ')
            timestamp,frame=frame_record
            import hashlib
            if packet['packet_ordinal']!=ordinal or packet['timestamp']!=timestamp or packet['frame_sha256']!=hashlib.sha256(frame).hexdigest() or packet['campaign_id']!=row['campaign_id'] or any(packet.get(k)!=v for k,v in _header(frame).items()):raise ValueError('observed packet/header membership differs from capture')
        packets+=len(observation['packets']);research+=row['research_only_rows']
    return {'campaigns':len(manifest['observations']),'observed_packets':packets,'research_packets':research,'wire_observations_verified':True}


def audit_exports(root,exports):
    import pyarrow.parquet as pq
    from .training_contract import label_for_memberships
    root=Path(root);gt={};ordered_rows=0
    for p in root.glob('batches/*/parquet/segment_gt.parquet'):
        for r in pq.ParquetFile(p).read().to_pylist():gt.setdefault(r['global_session_uid'],[]).append(r)
    for batch in exports['batches']:
        source=pq.ParquetFile(root/'batches'/batch['batch']/'parquet/office_sessions.parquet')
        labels=pq.ParquetFile(root/'exports'/batch['batch']/'labels.parquet').read().to_pylist()
        keys=[(r['global_session_uid'],r['global_segment_uid']) for b in source.iter_batches(columns=['global_session_uid','global_segment_uid']) for r in b.to_pylist()]
        if keys!=[(r['global_session_uid'],r['global_segment_uid']) for r in labels]:raise ValueError('export ordered session/segment keys differ')
        for row in labels:
            memberships=gt.get(row['global_session_uid'],[]);target,state=label_for_memberships(memberships)
            if row['label_binary']!=target or row['label_state']!=state or row['campaign_ids']!=sorted({r['campaign_id'] for r in memberships}):raise ValueError('export label/membership/role differs')
        if batch['features']:
            actual=pq.ParquetFile(root/'exports'/batch['batch']/'features.parquet').read()
            expected=source.read(columns=batch['features'])
            if not actual.equals(expected):raise ValueError('export feature values/order differ')
        ordered_rows+=len(labels)
    return {'ordered_rows_verified':ordered_rows,'feature_values_verified':True,'labels_and_roles_verified':True}
