"""Retained office background with paired alternative physical branches."""
from collections import Counter
from pathlib import Path
from .records import iter_rows


def reference_endpoint_counts(office_paths):
    try:
        from .reference_scan import endpoint_counts
        return endpoint_counts(office_paths)
    except ImportError:
        hosts,peers=Counter(),Counter()
        for path in office_paths:
            for x,_ in iter_rows(path):
                for key,private in ((x[1].hex(),x[9]&1),(x[2].hex(),(x[9]>>1)&1)):
                    (hosts if private else peers)[key]+=1
        return hosts,peers


def frozen_endpoint_mapping(office_paths,catalog,addresses):
    # Frequency ranks depend only on the retained office reference.
    hosts,peers=reference_endpoint_counts(office_paths)
    if not hosts or not peers:raise ValueError('office reference needs observed private hosts and external peers')
    h=[k for k,n in sorted(hosts.items(),key=lambda r:(-r[1],r[0]))]
    p=[k for k,n in sorted(peers.items(),key=lambda r:(-r[1],r[0]))]
    result={};assigned={}
    for c in sorted(catalog,key=lambda r:(r['parent_campaign_id'],r['campaign_id'])):
        pair=c['parent_campaign_id']
        if pair not in assigned:assigned[pair]=(h[len(assigned)%len(h)],len(assigned)//len(h))
        host,peer_offset=assigned[pair]
        source=c['source_ip'];others=[a for a in sorted(addresses) if a!=source]
        if len(p)<len(others):raise ValueError('not enough distinct reference peers')
        mapping={source:{'key':host,'private':1}}
        mapping.update({a:{'key':p[(peer_offset+i)%len(p)],'private':0} for i,a in enumerate(others)})
        result[c['campaign_id']]={'endpoints':mapping,'policy':'reference-only_frequency_order_v2_distinct_host_peer_pairs','logical_only':True}
    return result


def combine_analysis(branches,out,compressed_csv=False):
    """One background copy; all control instances, with exact global lineage."""
    import csv,json,shutil
    from .pipeline import dump
    from .source import sha256
    out=Path(out);registry=[];counts=Counter()
    for arm in ('scenario','control'):
        root=Path(branches[arm]);report=json.loads((root/'validated.json').read_text())
        if report['status']!='validated_local':raise ValueError('unvalidated alternative')
        runid=report['run_id'];registry+=json.loads((root/'positive_registry.json').read_text())
        for b in sorted(root.glob('batches/*')):
            target=out/'batches'/(arm+'_'+b.name);target.mkdir(parents=True)
            gt=[json.loads(line) for line in (b/'segment_gt.jsonl').read_text().splitlines() if line]
            keep={r['segment_uid'] for r in gt}
            import gzip
            csv_target=target/('office_sessions.csv.gz' if compressed_csv else 'office_sessions.csv')
            output_stream=gzip.open(csv_target,'wt',compresslevel=1) if compressed_csv else csv_target.open('w')
            csv_source=b/'office_sessions.csv'
            input_stream=csv_source.open() if csv_source.exists() else gzip.open(b/'office_sessions.csv.gz','rt')
            with input_stream as f,output_stream as output:
                reader=csv.DictReader(f);w=csv.DictWriter(output,fieldnames=reader.fieldnames);w.writeheader()
                for row in reader:
                    if arm=='control' and row['segment_uid'] not in keep:continue
                    row['segment_uid']=runid+':'+row['segment_uid'];row['session_uid']=runid+':'+row['session_uid']
                    w.writerow(row);counts['segments']+=1;counts['feature_packets']+=int(row['pkt_count'])
            for r in gt:r['segment_uid']=runid+':'+r['segment_uid'];r['session_uid']=runid+':'+r['session_uid'];counts['gt_packets']+=r['positive_packet_count']
            (target/'segment_gt.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in gt))
            if (b/'parquet').is_dir():
                import pyarrow as pa,pyarrow.compute as pc,pyarrow.parquet as pq
                directory=target/'parquet';directory.mkdir();files={}
                for p in sorted((b/'parquet').glob('*.parquet')):
                    if arm=='control' and p.name not in ('office_sessions.parquet','segment_gt.parquet'):continue
                    table=pq.ParquetFile(p).read()
                    if arm=='control' and p.name=='office_sessions.parquet':table=table.filter(pc.is_in(table['segment_uid'],value_set=pa.array(sorted(keep))))
                    pq.write_table(table,directory/p.name,compression='zstd')
                    q=directory/p.name;files[p.name]={'rows':table.num_rows,'bytes':q.stat().st_size,'sha256':sha256(q)}
                dump(directory/'manifest.json',{'run_id':runid,'batch_id':target.name,'files':files,'experiment_role':'challenge_only'})
    if len({r['campaign_id'] for r in registry})!=len(registry):raise ValueError('duplicate alternative campaigns')
    dump(out/'positive_registry.json',registry)
    return dict(counts)


def bounded_profile(profile, interval_seconds=20):
    """Keep whole campaigns inside one contiguous retained background block."""
    result=[dict(x,office_batch=0) for x in profile]
    first=0
    for i,row in enumerate(result):
        if i+1<len(result) and result[i+1]['start']-row['start']<=interval_seconds:
            continue
        for member in result[first:i+1]:member['batch_last']=row['observed_last']
        first=i+1
    return result


def execute_complete(catalog_path,office_paths,out,registry,runtimes,observations,source_lock,seed=20261002,clean_reference=None,run_id='cover20261002',sensor_observation=False,scratch_root=None):
    import json,os,shutil
    from .pipeline import branch,dump
    from .records import profile_rows,choose_paired_placements
    from .cover_registry import digest
    from .source import sha256
    from .splits import build_split_manifest
    root=Path(out).resolve();root.mkdir(parents=True,exist_ok=False)
    catalog=json.loads(Path(catalog_path).read_text())['campaigns']
    # Raw/ICMP campaigns keep research observation rows and campaign metadata.
    transport=[r for r in catalog if r['modeling_scope']=='standard_transport']
    profile=bounded_profile(profile_rows(office_paths))
    schedule=choose_paired_placements(profile,transport,seed,len(transport),max_positive_fraction=.05)
    addresses=set()
    for row in observations:
        for packet in json.loads(Path(row['observation_path']).read_text())['packets']:
            addresses.update(a for a in (packet.get('src'),packet.get('dst')) if a)
    mapping=frozen_endpoint_mapping(office_paths,transport,addresses)
    dump(root/'mapping_manifest.json',{'sha256':digest(mapping),'mapping':mapping,'identity':'logical endpoints from retained office reference; source packets not captured in office'})
    dump(root/'cover_registry.json',registry);dump(root/'source_lock.json',source_lock)
    dump(root/'runtime_manifest.json',{'version':'retained-runtime-set-v1','runs':runtimes})
    dump(root/'observation_manifest.json',{'version':'cover-observations-v1','observations':observations})
    dump(root/'full_campaign_registry.json',catalog)
    common=os.urandom(32);branches={}
    if clean_reference is not None:
        from .pipeline import validated_inputs
        reference=Path(clean_reference).resolve()
        req=json.loads((reference/'request.json').read_text())
        verified=json.loads((reference/'validated.json').read_text())
        if verified['status']!='validated_local' or json.loads((reference/'positive_registry.json').read_text()):raise ValueError('clean reference must be validated and injection-free')
        if req['office']!=validated_inputs(office_paths) or req['files_per_batch']!=len(office_paths):raise ValueError('clean reference input identity/boundaries differ')
        common=(reference/'session_salt').read_bytes()
        if req.get('session_salt_sha256')!=__import__('hashlib').sha256(common).hexdigest():raise ValueError('clean reference salt changed')
        dump(root/'clean_reference.json',{'path':str(reference),'files':{str(p.relative_to(reference)):sha256(p) for pattern in ('request.json','validated.json','batches/*/office_sessions.csv','batches/*/office_sessions.csv.gz','batches/*/parquet/*.parquet') for p in reference.glob(pattern)}})
    for arm in ('clean','scenario','control'):
        campaigns=[] if arm=='clean' else [r for r in transport if r['arm']==arm]
        path=root/(arm+'_catalog.json');dump(path,{'campaigns':campaigns})
        selected=[] if arm=='clean' else [r for r in schedule if r['arm']==arm]
        branchdir=root/'alternatives'/arm
        if arm=='clean' and clean_reference is not None:
            branchdir.parent.mkdir(parents=True,exist_ok=True);branchdir.symlink_to(reference,target_is_directory=True)
            branches[arm]=branchdir;dump(root/(arm+'_verified.json'),verified);continue
        report=branch(path,office_paths,branchdir,run_id+'_'+arm,repeats=0,seed=seed,files_per_batch=len(office_paths),
                      replay_enabled=False,endpoint_mapping=mapping,placements=selected,session_salt=common,sensor_observation=sensor_observation,scratch_root=scratch_root)
        branches[arm]=branchdir;dump(root/(arm+'_verified.json'),report)
    counts=combine_analysis(branches,root,compressed_csv=scratch_root is not None)
    positive=json.loads((root/'positive_registry.json').read_text())
    source_days=[dict(c,office_moscow_date=next(x['moscow_date'] for x in schedule if x['campaign_id']==c['campaign_id'])) for c in transport]
    dump(root/'source_split_manifest.json',build_split_manifest(source_days))
    dump(root/'schedule.json',schedule);dump(root/'office_profile.json',profile)
    dump(root/'request.json',{'identity':digest({'office':json.loads((branches['clean']/'request.json').read_text())['office'],'registry':registry['sha256'],'runtimes':runtimes,'mapping':digest(mapping)}),
        'office':json.loads((branches['clean']/'request.json').read_text())['office'],'source_catalog_sha256':sha256(catalog_path),'branches':{a:str(p) for a,p in branches.items()}})
    report={'status':'validated_local','run_id':run_id+'_complete','source_role':'isolated_protocol_in_office_background',
            'office_packets':json.loads((branches['clean']/'validated.json').read_text())['office_packets'],
            'positive_packets':counts['gt_packets'],'emitted_feature_packets':counts['feature_packets'],'segments':counts['segments'],
            'campaigns_transport':len(positive),'campaigns_research_only':len(catalog)-len(positive),
            'production_training_ready':False,'background_copies_in_analysis':1,'publication_status':'not_attempted'}
    if sensor_observation:
        stats=[p['sensor_observation'] for p in positive if p.get('sensor_observation')]
        from .sensor_stamps import VERSION
        report['sensor_observation']={'version':VERSION,'positives':len(stats),'packets':sum(x['packets'] for x in stats),
            'moved_packets':sum(x['moved_packets'] for x in stats),'max_shift_us':max([x['max_shift_us'] for x in stats] or [0.]),
            'tied_adjacent_before':sum(x['tied_adjacent_before'] for x in stats),'tied_adjacent_after':sum(x['tied_adjacent_after'] for x in stats),
            'scope':'observation_only: stamps only; bytes/sizes/order unchanged; interval changes bounded by cap; empirical approximation'}
    dump(root/'validated.json',report)
    return report
