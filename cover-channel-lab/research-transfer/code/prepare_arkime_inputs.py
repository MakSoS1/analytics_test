"""Generic retained-PCAP corpus for full Arkime comparison, without traffic shaping.

A constant whole-millisecond offset separates independent captures. Frame bytes
and all within-capture nanosecond intervals remain exact. This is a corpus
mixture in isolated windows, not simultaneous activity observed in an office.
"""
import argparse
import json
from pathlib import Path
import shutil
import struct
from prepare_arkime_cover import packets, sha


def prepare(spec_path, out):
    spec_path=Path(spec_path).resolve();out=Path(out)
    if out.exists():raise FileExistsError('retain previous comparison input')
    request=json.loads(spec_path.read_text());rows=request.get('sources',[])
    if not rows:raise ValueError('explicit nonempty source list required')
    sources=[];seen=set();cursor=None;total=0;references=set()
    for row in rows:
        path=(spec_path.parent/row['pcap']).resolve()
        if not path.is_file() or sha(path)!=row['sha256']:raise ValueError('source hash mismatch')
        if path in seen:raise ValueError('duplicate source capture')
        seen.add(path)
        label=row.get('label_binary');state=row.get('label_state','operator_asserted');dataset=row['dataset']
        if label is not None and (type(label) is not int or label not in (0,1)):raise ValueError('binary label must be null, zero or one')
        if dataset.startswith('office') and (label is not None or state!='unlabelled_office'):raise ValueError('office labels must remain unknown')
        first=last=None;count=0
        for ts,frame in packets(path):
            if last is not None and ts<last:raise ValueError('timestamp regression; no automatic source rewrite')
            first=ts if first is None else first;last=ts;count+=1
        if not count:raise ValueError('empty capture')
        shift=0 if cursor is None else ((cursor+1201*10**9-first+999999)//10**6)*10**6
        entry={k:row[k] for k in ('technique','campaign_id','arm') if k in row}
        entry.update(path=str(path),sha256=row['sha256'],dataset=dataset,label_binary=label,label_state=state,
                     original_first_ns=first,original_last_ns=last,mixed_first_ms=(first+shift)//10**6,
                     mixed_last_ms=(last+shift)//10**6,shift_ms=shift//10**6,packets=count,
                     original_contexts=row.get('original_contexts',[]),label_verification='operator_declared; full Arkime comparison does not certify technique execution')
        if row.get('observation_path'):
            p=(spec_path.parent/row['observation_path']).resolve()
            if not row.get('observation_sha256') or sha(p)!=row['observation_sha256']:raise ValueError('observation hash required and must match')
            entry['observation_path']=str(p);entry['observation_sha256']=row['observation_sha256']
        for context in entry['original_contexts']:references.add(context['global_segment_uid'])
        sources.append(entry);cursor=last+shift;total+=count
    required=sum(Path(r['path']).stat().st_size for r in sources)
    anchor=out.parent
    if shutil.disk_usage(anchor).free < (2<<30)+required:raise ValueError('insufficient disk reserve for corpus copy')
    out.mkdir();mixed=out/'source_isolated_mix.pcap'
    with mixed.open('wb') as f:
        f.write(struct.pack('<IHHIIII',0xa1b23c4d,2,4,0,0,262144,1))
        for source in sources:
            path=Path(source['path']);shift=source['shift_ms']*10**6
            for ts,frame in packets(path):
                sec,ns=divmod(ts+shift,10**9);f.write(struct.pack('<IIII',sec,ns,len(frame),len(frame)));f.write(frame)
            if sha(path)!=source['sha256']:raise ValueError('source changed during preparation; failed output retained')
    result={'version':'generic-arkime-corpus-v1','request_sha256':sha(spec_path),'sources':sources,'input_packets':total,
            'original_labelled_segments':len(references),'isolation_gap_seconds':1201,'mix_kind':'corpus mixture with isolated time windows; not office overlay',
            'frame_bytes_changed':False,'within_capture_intervals_changed':False,'mixed_sha256':sha(mixed),
            'naturalness_established':False,'production_ready':False,'cosmolake_uploads':0}
    (out/'PROVENANCE.json').write_text(json.dumps(result,indent=2)+'\n');(out/'files.txt').write_text(str(mixed.resolve())+'\n')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--spec',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();r=prepare(a.spec,a.out);print(json.dumps({'sources':len(r['sources']),'packets':r['input_packets'],'production_ready':False}))
