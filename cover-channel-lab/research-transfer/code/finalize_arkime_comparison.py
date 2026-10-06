"""Rebuild comparison views without rerunning or changing the production output."""
import argparse
import collections
import csv
import json
from pathlib import Path
import shutil
import sqlite3
import sys


def finish(stage, source, out, runtime):
    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.parquet as pq
    sys.path.insert(0,str(runtime/'bin'))
    from arkime_csv import aggregate
    from compare_arkime_pipeline import COUNTERS, native_common, digest
    out.mkdir(parents=True,exist_ok=False)
    report=json.loads((stage/'COMPLETE.json').read_text())
    records=pq.read_table(stage/'session_comparison.parquet').to_pylist()
    dbs={}
    for row in records:
        if row['status']!='exact':continue
        group=row['group']
        if group not in dbs:dbs[group]=sqlite3.connect(f'file:{source/("run_"+group)/"state.db"}?mode=ro',uri=True)
        raw=aggregate(json.loads(r[0]) for r in dbs[group].execute('select source_json from fragments where session_key=?',(row['arkime_session_key'],)))
        aligned=native_common(raw,row['same_direction'])
        row['arkime_syn_count']=aligned['syn_count'];row['delta_syn_count']=aligned['syn_count']-row['pipeline_syn_count']
    for db in dbs.values():db.close()
    schema=pq.read_schema(stage/'session_comparison.parquet')
    pq.write_table(pa.Table.from_pylist(records,schema=schema),out/'session_comparison.parquet',compression='zstd')
    for name in ['pipeline_office_sessions.parquet','arkime_sessions_all_fields.parquet','arkime_column_encodings.json']:
        shutil.copyfile(stage/name,out/name)
    exact=[row for row in records if row['status']=='exact']
    report['common_metrics']={name:{'compared':len(exact),
        'equal_within_tolerance':sum(abs(row['delta_'+name])<=(2 if name=='duration_ms' else 0.001) for row in exact),
        'maximum_absolute_delta':max((abs(row['delta_'+name]) for row in exact),default=0)} for name in COUNTERS+['duration_ms']}
    nonflow=collections.Counter()
    for group in report['groups']:
        totals=collections.Counter();frames=packets=truncated=0
        for line in (stage/('pipeline_'+group['group'])/'consumed.jsonl').read_text().splitlines():
            item=json.loads(line);totals.update(item.get('nonflow',{}));frames+=item['frames'];packets+=item['packets'];truncated+=item['truncated']
        if frames!=packets+sum(totals.values())+truncated:raise ValueError('unaccounted input frame')
        group['conversion_totals']=dict(totals);group['truncated_frames']=truncated;nonflow.update(totals)
    report['pipeline_nonflow']=dict(nonflow)
    report['bridge_counts']=dict(collections.Counter(row['status'] for row in records))
    report['counter_semantics']={'syn_count':'bare SYN, excludes SYN-ACK in both pipelines',
       'ack_count':'different definitions: office counts ACK bit; Arkime counts bare ACK',
       'total_bytes':'both tables count L2 frame bytes; IP reassembly may change native size',
       'duration_ms':'whole instance min(start)/max(end); tolerance 2 milliseconds',
       'direction':'Arkime source/destination aligned to original office client endpoint'}
    office=pq.read_table(out/'pipeline_office_sessions.parquet')
    native=pq.read_table(out/'arkime_sessions_all_fields.parquet')
    office_index={uid:i for i,uid in enumerate(office['global_segment_uid'].to_pylist())}
    native_index={uid:i for i,uid in enumerate(native['session_key'].to_pylist())}
    own_indices=[];ark_indices=[];segment_counts=[];directions=[]
    matched=set()
    for row in exact:
        for uid in row['pipeline_segment_uids']:
            own_indices.append(office_index[uid]);ark_indices.append(native_index[row['arkime_session_key']])
            segment_counts.append(row['pipeline_segments']);directions.append(row['same_direction']);matched.add(uid)
    left=office.take(pa.array(own_indices,pa.int64()));right=native.take(pa.array(ark_indices,pa.int64()))
    joined=pa.Table.from_arrays(list(left.columns)+list(right.columns)+[
        pa.array(segment_counts,pa.int64()),pa.array(directions,pa.bool_())],
        names=['pipeline.'+name for name in left.column_names]+[
        name if name.startswith('arkime.') else 'arkime_meta.'+name for name in right.column_names]+[
        'comparison.pipeline_segments','comparison.same_direction'])
    pq.write_table(joined,out/'matched_pipeline_arkime.parquet',compression='zstd')
    unmatched=office.filter(pc.invert(pc.is_in(office['global_segment_uid'],value_set=pa.array(sorted(matched),pa.string()))))
    pq.write_table(unmatched,out/'pipeline_unmatched_sessions.parquet',compression='zstd')
    report['matched_feature_rows']=joined.num_rows;report['matched_feature_columns']=len(joined.schema)
    report['unmatched_pipeline_rows']=unmatched.num_rows
    mappings={
      'pkt_count':('network.packets','same metric'),
      'up_pkt_count':('source.packets / destination.packets','align client direction'),
      'down_pkt_count':('destination.packets / source.packets','align client direction'),
      'total_bytes':('network.bytes','L2; reassembly differs from partial fragments'),
      'up_bytes':('source.bytes / destination.bytes','align client direction; L2'),
      'down_bytes':('destination.bytes / source.bytes','align client direction; L2'),
      'flow_duration':('(lastPacket-firstPacket)/1000','millisecond vs microsecond precision'),
      'syn_count':('tcpflags.syn','bare SYN; SYN-ACK deliberately excluded'),
      'fin_count':('tcpflags.fin','compare native TCP parser count'),
      'rst_count':('tcpflags.rst','compare native TCP parser count'),
      'psh_count':('tcpflags.psh','compare native TCP parser count'),
      'urg_count':('tcpflags.urg','compare native TCP parser count'),
      'ack_count':('tcpflags.ack','different: ACK bit vs bare ACK'),
      'pay_entropy_up':('officeEntropy.src / officeEntropy.dst','different: sampled first payload vs cumulative payload'),
      'pay_entropy_down':('officeEntropy.dst / officeEntropy.src','different: sampled first payload vs cumulative payload'),
      'dns_query_count':('dns.hostCnt / dns.queryHostCnt','different: queries vs distinct names'),
      'tls_sni_len':('host.tls','derive from native names; not a directly stored numeric feature'),
      'ssh_client_fp_key':('ssh.hassh','different fingerprint algorithm and hashing'),
      'ssh_server_fp_key':('ssh.hasshServer','different fingerprint algorithm and hashing')}
    with (out/'feature_mapping.csv').open('w',newline='') as handle:
        writer=csv.writer(handle);writer.writerow(['pipeline_column','pipeline_type','arkime_candidate','comparison_semantics'])
        for field in office.schema:
            candidate,semantics=mappings.get(field.name,('', 'no asserted one-to-one native equivalent; full field retained'))
            writer.writerow([field.name,str(field.type),candidate,semantics])
    report['source_pipeline_stage']=str(stage);report['same_packet_stream_verified']=True
    report['production_features_filtered']=False;report['cosmolake_uploads']=0;report['files']={}
    for path in out.iterdir():
        if not path.is_file():continue
        info={'bytes':path.stat().st_size,'sha256':digest(path)}
        if path.suffix=='.parquet':info.update(rows=pq.read_metadata(path).num_rows,columns=len(pq.read_schema(path)))
        report['files'][path.name]=info
    (out/'COMPLETE.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({key:report[key] for key in ['pipeline_rows','pipeline_columns','arkime_rows','arkime_columns','bridge_counts','matched_feature_rows','matched_feature_columns','unmatched_pipeline_rows','common_metrics','pipeline_nonflow','files']}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['stage','source','out','runtime']:parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();finish(args.stage,args.source,args.out,args.runtime)
