"""Run the existing full Cosmolake preparation pipeline on Arkime's exact inputs.
Run on VM with --office-code pointing to the installed production scripts.
No sensor access, publication, feature selection, or source deletion.
"""
import argparse
import contextlib
import csv
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import struct
import sys
from types import SimpleNamespace

COUNTERS = ['pkt_count', 'total_bytes', 'up_pkt_count', 'down_pkt_count',
            'up_bytes', 'down_bytes', 'syn_count', 'fin_count', 'rst_count',
            'psh_count', 'ack_count', 'urg_count']


def summarize(rows):
    result = {name: sum(float(row.get(name) or 0) for row in rows) for name in COUNTERS}
    result['segments'] = len(rows)
    result['duration_ms'] = (max(float(row['session_start_epoch']) + float(row['flow_duration']) for row in rows)
                             - min(float(row['session_start_epoch']) for row in rows)) * 1000
    return result


def native_common(data, same_direction):
    up, down = ('source', 'destination') if same_direction else ('destination', 'source')
    result = {'pkt_count': data.get('network.packets', 0),
              'total_bytes': data.get('network.bytes', 0),
              'up_pkt_count': data.get(up+'.packets', 0),
              'down_pkt_count': data.get(down+'.packets', 0),
              'up_bytes': data.get(up+'.bytes', 0), 'down_bytes': data.get(down+'.bytes', 0),
              'duration_ms': data['lastPacket'] - data['firstPacket'],
              'syn_count': data.get('tcpflags.syn', 0),
              # Arkime counts bare ACK packets; the office feature counts
              # every packet with the ACK bit. Preserve this difference.
              'ack_count': data.get('tcpflags.ack', 0)}
    for name in ('fin', 'rst', 'psh', 'urg'):
        result[name+'_count'] = data.get('tcpflags.'+name, 0)
    return result


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def parquet_arkime(csv_path, destination):
    """Infer only observed compatible types; incompatible SPI shapes stay JSON."""
    import pyarrow as pa
    import pyarrow.parquet as pq
    csv.field_size_limit(256*1024*1024)
    kinds = {}
    meta_int = {'label_binary','source_first_ms','source_last_ms','time_shift_ms','fragments',
                'campaign_packets','auxiliary_packets','membership_count_difference'}
    meta_bool = {'capture_boundary_limited','start_observed','natural_end_observed'}
    def value(name, raw):
        if not raw:
            return None
        if name.startswith('arkime.'):
            return json.loads(raw)
        if name in meta_int:
            return int(raw)
        if name in meta_bool:
            return raw == 'True'
        return raw
    def kind(item):
        if item is None:return None
        if isinstance(item,bool):return 'bool'
        if isinstance(item,int):return 'int'
        if isinstance(item,float):return 'float'
        if isinstance(item,str):return 'str'
        if isinstance(item,list):
            elements={kind(x) for x in item if x is not None}
            if not elements:return 'list-empty'
            if elements <= {'int','float'}:return 'list-float' if 'float' in elements else 'list-int'
            if len(elements)==1 and next(iter(elements)) in ('str','bool'):return 'list-'+next(iter(elements))
        return 'json'
    with csv_path.open(newline='') as handle:
        reader=csv.DictReader(handle);names=reader.fieldnames
        for row in reader:
            for name,raw in row.items():
                k=kind(value(name,raw))
                if k:kinds.setdefault(name,set()).add(k)
    types={};encodings={}
    scalar={'int':pa.int64(),'float':pa.float64(),'bool':pa.bool_(),'str':pa.large_string()}
    for name in names:
        variants=kinds.get(name,set())
        nonempty=variants-{'list-empty'}
        if not variants:typ=pa.large_string();encoding='absent'
        elif variants <= {'int','float'}:typ=pa.float64() if 'float' in variants else pa.int64();encoding='typed'
        elif nonempty <= {'list-int','list-float'} and variants <= {'list-empty','list-int','list-float'}:
            typ=pa.large_list(pa.float64() if 'list-float' in variants else pa.int64());encoding='typed'
        elif len(nonempty)==1 and next(iter(nonempty)).startswith('list-'):
            typ=pa.large_list(scalar[next(iter(nonempty))[5:]]);encoding='typed'
        elif variants=={'list-empty'}:typ=pa.large_list(pa.large_string());encoding='typed'
        elif len(variants)==1 and next(iter(variants)) in scalar:
            typ=scalar[next(iter(variants))];encoding='typed'
        else:typ=pa.large_string();encoding='json'
        types[name]=typ;encodings[name]=encoding
    schema=pa.schema([(name,types[name]) for name in names]+[('arkime_present_fields',pa.large_list(pa.string()))])
    count=0
    with pq.ParquetWriter(destination,schema,compression='zstd') as writer,csv_path.open(newline='') as handle:
        pending=[]
        for row in csv.DictReader(handle):
            record={name:(row[name] if encodings[name]=='json' else value(name,row[name])) for name in names}
            record['arkime_present_fields']=[name for name in names if name.startswith('arkime.') and row[name]!='']
            pending.append(record)
            if len(pending)>=256:
                writer.write_table(pa.Table.from_pylist(pending,schema=schema));count+=len(pending);pending=[]
        if pending:writer.write_table(pa.Table.from_pylist(pending,schema=schema));count+=len(pending)
    return dict(rows=count,columns=len(schema),encodings=encodings)


def execute(office, arkime, source, out):
    import pyarrow as pa
    import pyarrow.parquet as pq
    sys.path[:0]=[str(arkime/'bin'),str(office)]
    from prepare_arkime_cover import packets
    from run_local import guard
    from export_full_packets import export_with_payload
    from pipeline import flatten
    from arkime_csv import aggregate
    from bridge import build_bridge
    import office_batches as batches
    import convert_baseline
    guard(arkime);out.mkdir(parents=True,exist_ok=False)
    code_names=['export_full_packets.py','extract_office_sessions.py','payload_sidecar.py',
                'merge_payload_sidecars.py','finalize_tables.py','office_batches.py',
                'office_to_parquet.py','office_sessions.schema.json','host_minutes.py']
    code_hashes={name:digest(office/name) for name in code_names}
    batches.INTERMEDIATE=()  # Retain audit indexes and intermediate tables in this NEW run.
    salt=secrets.token_hex(16).encode();paths=[];comparisons=[];reports=[]
    pipeline_schema=None;frame_total=0;writer=None
    for input_path in sorted((source/'inputs').glob('*.pcap')):
        group=input_path.stem;work=out/('pipeline_'+group);work.mkdir();rows=work/'rows';rows.mkdir()
        (work/'packet-salt').write_bytes(salt);(work/'packet-salt').chmod(0o600)
        chunks=work/'pcaps';chunks.mkdir();handle=None;current=None;frames=0;stream=hashlib.sha256();rechunked=hashlib.sha256()
        try:
            for stamp,frame in packets(input_path):
                bucket=(stamp//10**9)//20*20
                if bucket!=current:
                    if handle:handle.close()
                    path=chunks/('chunk-'+batches.epoch_name(bucket)+'.pcap');handle=path.open('wb')
                    handle.write(struct.pack('<IHHIIII',0xa1b23c4d,2,4,0,0,262144,1));current=bucket
                raw=struct.pack('<qI',stamp,len(frame))+frame;stream.update(raw)
                sec,ns=divmod(stamp,10**9);handle.write(struct.pack('<IIII',sec,ns,len(frame),len(frame)));handle.write(frame);frames+=1
        finally:
            if handle:handle.close()
        journal=work/'consumed.jsonl';conversion=[]
        with journal.open('w') as jf:
            for path in sorted(chunks.glob('*.pcap')):
                for stamp,frame in packets(path):rechunked.update(struct.pack('<qI',stamp,len(frame))+frame)
                with (rows/(path.stem+'.pkts')).open('wb') as packet_out,(rows/(path.stem+'.pay')).open('wb') as payload_out:
                    stats=export_with_payload(path,packet_out,payload_out,salt)
                if stats.get('truncated',0):raise ValueError('truncated input')
                conversion.append(stats);jf.write(json.dumps(dict(pcap=path.name,rows_file=path.stem+'.pkts',
                    payload_file=path.stem+'.pay',status='ok',pcap_bytes=path.stat().st_size,**stats))+'\n')
        if stream.hexdigest()!=rechunked.hexdigest():raise ValueError('rechunking changed packet bytes or timestamps')
        local=batches.local_files(rows);first=min(local);span=int(max(local)-first)+20
        args=SimpleNamespace(work=work/'batches_work',rows_dir=rows,journal=journal,
              batch_seconds=span,interval_seconds=20,min_packets=1,shards=3,
              extra_tables=False,parquet_python=sys.executable,keep_rows=True,min_free_gb=40)
        processor=batches.Batches(args)
        with (work/'processor.stdout').open('w') as log,contextlib.redirect_stdout(log):
            processor.process(first,True,local)
        batch=processor.last_processed();processor.logf.close()
        manifest=convert_baseline.convert(batch,work/'parquet','comparison_'+group,batch.name,[],20,span)
        path=work/'parquet/office_sessions.parquet';paths.append(path)
        table=pq.read_table(path)
        if pipeline_schema is None:
            pipeline_schema=table.schema;writer=pq.ParquetWriter(out/'pipeline_office_sessions.parquet',pipeline_schema,compression='zstd')
        if not table.schema.equals(pipeline_schema):raise ValueError('production schema changes across groups')
        writer.write_table(table)
        by_uid={}
        for row in table.to_pylist():by_uid.setdefault(row['session_uid'],[]).append(row)
        native=sqlite3.connect(f'file:{source/("run_"+group)/"state.db"}?mode=ro',uri=True)
        indexes=sorted(batch.glob('_session_index-*.csv'))
        clients={}
        for index in indexes:
            with index.open() as handle:
                for row in csv.DictReader(handle):clients[row['segment_uid'].rsplit('.',1)[0]]=(row['client_ip'],int(row['client_port']))
        bridge=build_bridge(SimpleNamespace(db=native),work,work/'bridge.parquet',indexes)
        matches=pq.read_table(work/'bridge.parquet').to_pylist()
        matched_uids=set()
        for match in matches:
            uid=match['office_session_uid'];key=match['arkime_session_key'];record=dict(group=group,**match)
            if match['status']=='exact':
                matched_uids.add(uid);own=by_uid[uid];summary=summarize(own)
                raw=aggregate(json.loads(row[0]) for row in native.execute('select source_json from fragments where session_key=?',(key,)))
                import ipaddress
                source_ip=hashlib.blake2s(ipaddress.ip_address(raw['source.ip']).packed,key=salt,digest_size=8).hexdigest()
                same=(source_ip,int(raw['source.port']))==clients[uid]
                aligned=native_common(raw,same)
                record.update(pipeline_global_session_uid=own[0]['global_session_uid'],
                              pipeline_segment_uids=[row['global_segment_uid'] for row in own],
                              same_direction=same,pipeline_segments=len(own))
                for name in COUNTERS+['duration_ms']:
                    record['pipeline_'+name]=summary[name];record['arkime_'+name]=aligned[name]
                    record['delta_'+name]=aligned[name]-summary[name]
            comparisons.append(record)
        native.close();frame_total+=frames
        reports.append(dict(group=group,frames=frames,input_sha256=digest(input_path),
                            packet_stream_sha256=stream.hexdigest(),rechunked_packet_stream_sha256=rechunked.hexdigest(),
                            pipeline_packet_rows=sum(s['packets'] for s in conversion),
                            conversion_totals={name:sum(s.get('nonflow',{}).get(name,0) for s in conversion) for name in ['non_ip','ip_fragment','other_l4','short_header','bad_tcp_header','runt']},
                            pipeline_rows=table.num_rows,pipeline_sessions=len(by_uid),
                            pipeline_unmatched_sessions=len(set(by_uid)-matched_uids),bridge=bridge['counts']))
        print(json.dumps(reports[-1]),flush=True)
    if writer:writer.close()
    comparison_keys=sorted({key for row in comparisons for key in row})
    pq.write_table(pa.Table.from_pylist([{key:row.get(key) for key in comparison_keys} for row in comparisons]),
                   out/'session_comparison.parquet',compression='zstd')
    typed=parquet_arkime(source/'csv/arkime_sessions_all_fields.csv',out/'arkime_sessions_all_fields.parquet')
    summary={'input_frames':frame_total,'pipeline_columns':len(pipeline_schema),
             'pipeline_schema_columns':[{'name':f.name,'type':str(f.type)} for f in pipeline_schema],
             'pipeline_rows':pq.read_metadata(out/'pipeline_office_sessions.parquet').num_rows,
             'arkime_rows':typed['rows'],'arkime_columns':typed['columns'],'groups':reports,
             'production_code_sha256':code_hashes,'cosmolake_uploads':0,'files':{}}
    exact=[row for row in comparisons if row['status']=='exact']
    summary['common_metrics']={name:{'compared':len(exact),
         'equal_within_tolerance':sum(abs(row['delta_'+name])<=(2 if name=='duration_ms' else 0.001) for row in exact),
         'maximum_absolute_delta':max((abs(row['delta_'+name]) for row in exact),default=0)} for name in COUNTERS+['duration_ms']}
    (out/'arkime_column_encodings.json').write_text(json.dumps(typed,indent=2)+'\n')
    for name,pin in code_hashes.items():
        if digest(office/name)!=pin:raise ValueError('production code changed during comparison')
    expected=json.loads((source/'csv/COMPLETE.json').read_text())['input_packets']
    if frame_total!=expected:raise ValueError('different input packet set')
    for path in out.glob('*.parquet'):
        summary['files'][path.name]={'rows':pq.read_metadata(path).num_rows,'columns':len(pq.read_schema(path)),
                                   'bytes':path.stat().st_size,'sha256':digest(path)}
    (out/'COMPLETE.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({key:summary[key] for key in ['input_frames','pipeline_columns','pipeline_rows','arkime_rows','arkime_columns','common_metrics','files']}),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('office-code','arkime','source','out'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();execute(args.office_code,args.arkime,args.source,args.out)
