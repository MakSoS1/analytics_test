"""A separate sealed-input branch; never drains or deletes baseline input files."""
from __future__ import annotations
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from .source import read_pcap,write_pcap,sha256
from .records import iter_rows,profile_rows,choose_placements,choose_paired_placements,merge_rows
from .payload import availability_version,downgrade
from .replay import replay
from .audit import domain_report

csv.field_size_limit(1<<26)

ROOT=Path(__file__).resolve().parents[1]


def dump(path,value):
    path=Path(path);tmp=path.with_suffix(path.suffix+'.partial')
    tmp.write_text(json.dumps(value,indent=2,default=str)+'\n');tmp.replace(path)


def execute(command,log,env=None):
    with Path(log).open('a') as f:
        f.write('$ '+ ' '.join(map(str,command))+'\n');f.flush()
        r=subprocess.run(list(map(str,command)),stdout=f,stderr=subprocess.STDOUT,env=env)
    if r.returncode:raise RuntimeError(f'pipeline command failed ({r.returncode}); see {log}')


def validated_inputs(paths):
    out=[];versions=set()
    if len(set(map(lambda p:str(Path(p).resolve()),paths)))!=len(paths):raise ValueError('duplicate office input')
    for p in sorted(map(Path,paths)):
        p=p.resolve();q=p.with_suffix('.pay')
        if not q.is_file():raise ValueError(f'office pair missing: {q}')
        if p.stat().st_size==0:raise ValueError('empty office input')
        version=availability_version(q);versions.add(version)
        out.append({'path':str(p),'pay':str(q),'sha256':sha256(p),'pay_sha256':sha256(q),'bytes':p.stat().st_size})
    if not out or len(versions)!=1:raise ValueError('one explicit office payload availability version required')
    if versions.pop() not in (1,3,4):raise ValueError('office availability version unsupported')
    return out


def branch(catalog_path,office_paths,out_dir,run_id,repeats=6,seed=1701,files_per_batch=2,
           replay_enabled=True,skip_parquet=False,endpoint_mapping=None,placements=None,session_salt=None,sensor_observation=False,scratch_root=None):
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,60}',run_id) or run_id.startswith('check10m'):
        raise ValueError('new experiment run_id required')
    if files_per_batch<1 or repeats<0:raise ValueError('positive batch size and nonnegative repeats required')
    root=Path(out_dir).resolve();catalog_path=Path(catalog_path).resolve()
    office=validated_inputs(office_paths)
    catalog=json.loads(catalog_path.read_text())['campaigns']
    for c in catalog:
        p=Path(c['path'])
        if not p.exists():p=catalog_path.parent/p.name
        c['path']=str(p.resolve())
        if sha256(p)!=c['sha256']:raise ValueError('catalog slice hash mismatch')
    request={'run_id':run_id,'office':office,'catalog_sha256':sha256(catalog_path),'repeats':repeats,
             'seed':seed,'files_per_batch':files_per_batch,'replay_enabled':replay_enabled,'skip_parquet':skip_parquet,
             'runtime_sha256':{str(p.relative_to(ROOT)):sha256(p) for p in sorted(ROOT.glob('office_injection/*.py'))},
             'extractor_sha256':sha256(ROOT/'extract_office_sessions.py')}
    if scratch_root is not None:request['temporary_intermediates']=True
    if endpoint_mapping is not None:request['endpoint_mapping']=endpoint_mapping
    if sensor_observation:
        from .sensor_stamps import VERSION as SENSOR_VERSION,BURST_CAPACITY,CAP_SECONDS
        request['sensor_observation']={'version':SENSOR_VERSION,'burst_capacity':BURST_CAPACITY,'cap_seconds':CAP_SECONDS}
    if placements is not None:request['placements']=placements
    if session_salt is not None:
        if not isinstance(session_salt,bytes) or len(session_salt)!=32:raise ValueError('32 byte experiment session salt required')
        request['session_salt_sha256']=hashlib.sha256(session_salt).hexdigest()
    identity=hashlib.sha256(json.dumps(request,sort_keys=True).encode()).hexdigest()
    if (root/'request.json').exists():
        old=json.loads((root/'request.json').read_text())
        if old['identity']!=identity:raise ValueError('existing run has different source/config; new run required')
        if (root/'validated.json').exists():return json.loads((root/'validated.json').read_text())
        raise ValueError('incomplete run retained; inspect failure and start a new run_id/output, no destructive automatic retry')
    root.mkdir(parents=True,exist_ok=True)
    if any(root.iterdir()):raise ValueError('nonempty experiment directory without manifest')
    office_bytes=sum(x['bytes'] for x in office)
    disk_budget=max(2**30, int(office_bytes*.65)) if scratch_root is not None else max(2**30*5,office_bytes*4)
    if shutil.disk_usage(root).free<disk_budget:raise ValueError('branch disk budget exceeded')
    if scratch_root is not None and shutil.disk_usage(scratch_root).free < office_bytes*1.5:
        raise ValueError('scratch budget exceeded')
    dump(root/'request.json',{'identity':identity,**request})
    (root/'session_salt').write_bytes(session_salt if session_salt is not None else os.urandom(32));(root/'session_salt').chmod(0o600)
    version=availability_version(office[0]['pay'])
    groups=[office[i:i+files_per_batch] for i in range(0,len(office),files_per_batch)]
    profile=profile_rows([x['path'] for x in office])
    from .splits import build_split_manifest
    strata={b['start']:b['load_stratum'] for b in profile}
    placement_profile=[]
    for number,group in enumerate(groups):
        bins=profile_rows([x['path'] for x in group]);last=max(b['observed_last'] for b in bins)
        for b in bins:
            b['office_batch']=number;b['load_stratum']=strata[b['start']];b['batch_last']=last;placement_profile.append(b)
    paired = bool(catalog) and all(c.get('generated') and c.get('parent_campaign_id') for c in catalog)
    scheduler = choose_paired_placements if paired else choose_placements
    schedule=scheduler(placement_profile,catalog,seed,repeats) if repeats and placements is None else []
    if placements is not None:
        allowed={c['campaign_id'] for c in catalog}
        if any(p['campaign_id'] not in allowed for p in placements):raise ValueError('fixed placement outside catalog')
        schedule=list(placements)
    # Bind lineage to actual destination days. Shared days deliberately merge components.
    destinations = {}
    for item in schedule:destinations.setdefault(item['campaign_id'], set()).add(item['moscow_date'])
    split_rows = []
    for campaign in catalog:
        for day in sorted(destinations.get(campaign['campaign_id'], {None})):
            split_rows.append(dict(campaign, office_moscow_date=day))
    # Repeated placement across days needs a single connected campaign node.
    split_rows = [dict(r, campaign_id=r['campaign_id']+'@'+str(r.get('office_moscow_date'))) for r in split_rows]
    manifest = build_split_manifest(split_rows)
    manifest['campaign_splits'] = {k.rsplit('@',1)[0]:v for k,v in manifest['campaign_splits'].items()}
    manifest['campaign_components'] = {k.rsplit('@',1)[0]:v for k,v in manifest.get('campaign_components',{}).items()}
    body = {k:v for k,v in manifest.items() if k!='sha256'}
    manifest['sha256'] = hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest()
    dump(root/'source_split_manifest.json',manifest)
    dump(root/'office_profile.json',profile);dump(root/'schedule.json',schedule)
    positive=[];events=[]
    sensor_grid = None
    if sensor_observation and schedule:
        from .sensor_stamps import StampGrid
        sensor_grid = StampGrid.from_office([x['path'] for x in office],
            min(p['placed_start'] for p in schedule)-.001, max(p['office_observed_last'] for p in schedule))
    for placement in schedule:
        ident=placement['injection_id'];directory=root/'positive'/ident;directory.mkdir(parents=True)
        source=Path(placement['path'])
        if placement.get('generated'):
            # Already an observed capture of a live session in its own namespace;
            # replaying it through another veth would only add jitter.
            if sha256(source)!=placement['sha256']:raise ValueError('generated capture hash mismatch')
            rx=source;report={'passed':True,'mode':'generated_capture','tcp_stack_adapted':True}
        elif replay_enabled:
            rx,report=replay(source,directory/'replay',placement['sha256'])
        else:
            rx=source;report={'passed':True,'mode':'offline_fixture','tcp_stack_adapted':False}
        frames=list(read_pcap(rx,max_regression=0.00001));frames.sort(key=lambda x:x[0])
        # Same constant time offset, then re-export: payload and packet timestamps cannot diverge.
        offset=placement['placed_start']-frames[0][0]
        write_pcap(directory/'placed.pcap',frames,offset=offset)
        actual_end=frames[-1][0]+offset
        if actual_end>placement['office_observed_last']:raise ValueError('replay timing exceeded office placement bound')
        salt=directory/'salt';salt.write_bytes(os.urandom(32));salt.chmod(0o600)
        if endpoint_mapping is None:
            execute([sys.executable,ROOT/'export_full_packets.py','--pcap',directory/'placed.pcap',
                     '--out',directory/'placed.pkts','--payload-out',directory/'placed.pay','--salt-file',salt],directory/'steps.log')
        else:
            from .host_mapping import map_endpoints
            from .wire_observation import observe_capture
            mapping=endpoint_mapping[placement['campaign_id']]
            obs=observe_capture(directory/'placed.pcap',{'campaign_id':placement['campaign_id'],
                'source_ip':placement['source_ip'],'started_at':placement['placed_start'],
                'ended_at':actual_end+.000002,'capture_sha256':sha256(directory/'placed.pcap')},directory/'wire')
            mapped=map_endpoints(obs,mapping,directory/'mapped')
            shutil.copyfile(mapped['pkts_path'],directory/'placed.pkts');shutil.copyfile(mapped['pay_path'],directory/'placed.pay')
        sensor=None
        if sensor_observation:
            # Empirical observation approximation; each interval may change by up
            # to the cap. All campaigns share capacity; source captures stay intact.
            from .sensor_stamps import StampGrid,observe_rows,observe_payload_times
            grid=sensor_grid
            bound=placement['office_observed_last']
            shutil.move(directory/'placed.pkts',directory/'placed.unobserved.pkts');shutil.move(directory/'placed.pay',directory/'placed.unobserved.pay')
            sensor=observe_rows(directory/'placed.unobserved.pkts',directory/'placed.pkts',grid,bound)
            observe_payload_times(directory/'placed.unobserved.pay',directory/'placed.pay',grid,bound)
            sensor['unobserved_pkts_sha256']=sha256(directory/'placed.unobserved.pkts');sensor['grid_bursts']=int(len(grid.stamps))
            actual_end=sensor['last_after']
        downgrade(directory/'placed.pay',version)
        evidence={**placement,'placed_end':actual_end,'path':str(directory/'placed.pkts'),'pay':str(directory/'placed.pay'),
                  'sha256':sha256(directory/'placed.pkts'),'pay_sha256':sha256(directory/'placed.pay'),**({'sensor_observation':sensor} if sensor else {})}
        positive.append(evidence)
        events.append({**placement,'rx_report':report,'placed_actual_end':actual_end,'time_offset':offset,
                       'status':'observed','office_availability_version':version,
                       'tcp_stack_adapted':bool(placement.get('generated'))})
    dump(root/'positive_registry.json',positive);dump(root/'injection_events.json',events)
    if sensor_grid is not None:
        dump(root/'sensor_capacity_audit.json',sensor_grid.capacity_report())
        sensor_grid.require_complete()
    # Each original office file is assigned once. Its .pay travels with it, preserving
    # the baseline per-chunk extraction/carry behavior; boundaries occur between files.
    groups=[office[i:i+files_per_batch] for i in range(0,len(office),files_per_batch)]
    all_csv=[];all_gt=[];previous=None;assigned=set();input_packets=positive_packets=0
    for number,group in enumerate(groups):
        batch=root/'batches'/f'b{number:05d}';batch.mkdir(parents=True)
        scratch = None
        work = batch
        if scratch_root is not None:
            import tempfile
            scratch = tempfile.TemporaryDirectory(prefix='cover-intermediate-', dir=scratch_root)
            work = Path(scratch.name)
        stage=work/'rows';stage.mkdir()
        # Profiles may straddle chunk filenames; use actual row-time bounds, not filename time.
        begin=float('inf');end=float('-inf')
        for item in group:
            for row,_ in iter_rows(item['path']):begin=min(begin,row[0]);end=max(end,row[0])
        owned=[x for x in positive if x['office_batch']==number and begin<=x['placed_start'] and x['placed_end']<=end and x['injection_id'] not in assigned]
        stats,gt=merge_rows([x['path'] for x in group],owned,stage/'mixed.pkts')
        assigned.update(x['injection_id'] for x in owned)
        input_packets+=stats['office_packets'];positive_packets+=stats['positive_packets']
        dump(batch/'composition.json',{'begin':begin,'end':end,'sealed':True,**stats,
            'merged_rows_sha256':sha256(stage/'mixed.pkts'),'packet_stage_retained':scratch_root is None})
        # Sparse ordinal GT is retained for auditing; emission observer uses immutable RX evidence.
        with (batch/'packet_gt.jsonl').open('w') as f:
            for ordinal,item in gt.items():f.write(json.dumps({'ordinal':ordinal,**item})+'\n')
        for i,item in enumerate([*group,*owned]):
            (stage/f'payload-{i:05d}.pay').symlink_to(Path(item.get('pay')).resolve())
        log=batch/'steps.log';raw=work/'raw.csv';lots=work/'lots.csv';index=work/'index.csv';labels=batch/'segment_gt.jsonl'
        command=[sys.executable,'-m','office_injection.assemble','--gt-registry',root/'positive_registry.json',
                 '--gt-out',labels,'--pcap-dir',stage,'--glob','*.pkts','--min-packets','1',
                 '--salt-file',root/'session_salt','--out-sessions',raw,'--out-lots-conns',lots,
                 '--session-index',index,'--stats-json',batch/'session_stats.json']
        if previous:command+=['--state-in',previous/'session_state.pkl']
        command+=['--finalize'] if number==len(groups)-1 else ['--state-out',batch/'session_state.pkl','--live-out',batch/'live.csv']
        env=dict(os.environ,PYTHONPATH=str(ROOT)+os.pathsep+os.environ.get('PYTHONPATH',''))
        execute(command,log,env)
        if scratch is not None:(stage/'mixed.pkts').unlink()  # consumed temporary merge, hash retained
        if number==len(groups)-1:(batch/'live.csv').write_text('ip_a,port_a,ip_b,port_b,proto,seg_start\n')
        command=[sys.executable,ROOT/'merge_payload_sidecars.py','--sidecar-dir',stage,'--session-index',index,
                 '--out-csv',work/'payload.csv','--stats-json',batch/'payload_stats.json',
                 '--live',batch/'live.csv','--pending-out',batch/'pending_records.pkl']
        if previous:command+=['--pending-in',previous/'pending_records.pkl']
        execute(command,log)
        command=[sys.executable,ROOT/'finalize_tables.py','--sessions',raw,'--payload',work/'payload.csv',
                 '--lots-conns-in',lots,'--out-sessions',work/'office_sessions.csv',
                 '--out-lots-conns',work/'office_lots_conns.csv','--stats-json',batch/'finalize_stats.json']
        if previous:command+=['--facts-carry-in',previous/'facts_carry.json','--conns-carry-in',previous/'conns_carry.json']
        if number<len(groups)-1:command+=['--facts-carry-out',batch/'facts_carry.json','--conns-carry-out',batch/'conns_carry.json']
        execute(command,log)
        dump(batch/'verified.json',stats)
        if not skip_parquet:
            execute([sys.executable,ROOT/'office_to_parquet.py','--batch-dir',work,'--out-dir',batch/'parquet',
                     '--run-id',run_id,'--batch-id',batch.name],log)
            import pyarrow as pa,pyarrow.parquet as pq
            gt_rows=[json.loads(x) for x in labels.read_text().splitlines()]
            for r in gt_rows:
                r['global_session_uid']=run_id+':'+r['session_uid'];r['global_segment_uid']=run_id+':'+r['segment_uid']
            schema=pa.schema([('session_uid',pa.string()),('segment_uid',pa.string()),('segment_index',pa.int64()),
                ('injection_id',pa.string()),('campaign_id',pa.string()),('technique',pa.string()),('arm',pa.string()),('dataset_role',pa.string()),
                ('positive_packet_count',pa.int64()),('modeled_positive_packet_count',pa.int64()),('label_scope',pa.string()),('label_state',pa.string()),
                ('training_eligible',pa.bool_()),('timing_training_eligible',pa.bool_()),
                ('global_session_uid',pa.string()),('global_segment_uid',pa.string())])
            gt_file=batch/'parquet'/'segment_gt.parquet';pq.write_table(pa.Table.from_pylist(gt_rows,schema=schema),gt_file,compression='zstd')
            manifest=json.loads((batch/'parquet'/'manifest.json').read_text())
            manifest['files']['segment_gt.parquet']={'rows':len(gt_rows),'sha256':sha256(gt_file),'bytes':gt_file.stat().st_size}
            manifest['experiment_role']='challenge_only';dump(batch/'parquet'/'manifest.json',manifest)
        final_csv=batch/'office_sessions.csv'
        if scratch is not None:
            import gzip
            final_csv=batch/'office_sessions.csv.gz'
            with (work/'office_sessions.csv').open('rb') as source,gzip.open(final_csv,'wb',compresslevel=1) as target:
                shutil.copyfileobj(source,target)
            scratch.cleanup()  # only this invocation's temporary intermediates
        previous=batch;all_csv.append(final_csv);all_gt.append(labels)
    if assigned!={x['injection_id'] for x in positive}:raise ValueError('positive placement not assigned to a sealed batch')
    emitted=gt_count=wire_emitted=0;seen=set()
    for path in all_csv:
        import gzip
        stream=gzip.open(path,'rt') if path.suffix=='.gz' else path.open()
        with stream as f:
            for r in csv.DictReader(f):
                if r['segment_uid'] in seen:raise ValueError('duplicate segment UID')
                seen.add(r['segment_uid']);emitted+=int(r['pkt_count'])
    for path in all_gt:
        for line in path.read_text().splitlines():
            r=json.loads(line)
            if r['segment_uid'] not in seen:raise ValueError('GT refers to missing segment')
            gt_count+=r['positive_packet_count']  # scenario and control arms: every injected packet
    lineage_seen=set();lineage_feature_count=0
    for path in all_gt:
        for line in path.with_suffix('.lineage.jsonl').read_text().splitlines():
            r=json.loads(line)
            if r['segment_uid'] in lineage_seen:raise ValueError('duplicate wire lineage')
            lineage_seen.add(r['segment_uid']);wire_emitted+=r['wire_packet_count'];lineage_feature_count+=r['feature_packet_count']
    if lineage_seen!=seen or lineage_feature_count!=emitted:raise ValueError('feature lineage differs from CSV')
    if wire_emitted!=input_packets+positive_packets or gt_count!=positive_packets:
        raise ValueError(f'final packet/GT accounting differs: {wire_emitted} / {input_packets+positive_packets}, GT {gt_count} / {positive_packets}')
    audit=domain_report(all_csv,all_gt,profile,schedule);dump(root/'domain_audit.json',audit)
    report={'status':'validated_local','run_id':run_id,'batches':len(groups),'office_packets':input_packets,
            'positive_packets':positive_packets,'emitted_feature_packets':emitted,'emitted_wire_packets':wire_emitted,'gt_positive_packets':gt_count,
            'coalesced_expansion_packets':emitted-wire_emitted,
            'segments':len(seen),'replay':replay_enabled,'production_training_ready':False,
            'publication_status':'not_attempted','audit':audit,
            'source_role':'isolated_protocol_in_office_background' if endpoint_mapping is not None else ('office_skeleton_generated' if any(x.get('generated') for x in positive) else 'challenge_only')}
    for item in office:
        if sha256(item['path'])!=item['sha256'] or sha256(item['pay'])!=item['pay_sha256']:
            raise ValueError('office input changed during run; cannot commit')
    dump(root/'validated.json',report)
    # No source or run artifacts are deleted by this branch.
    return report
