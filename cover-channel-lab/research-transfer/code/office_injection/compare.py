"""Compare a separately extracted clean control with mixed office segments."""
import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
csv.field_size_limit(1<<26)

def compare(clean,mixed):
    clean=Path(clean);mixed=Path(mixed)
    a=json.loads((clean/'request.json').read_text());b=json.loads((mixed/'request.json').read_text())
    if a['office']!=b['office'] or a['files_per_batch']!=b['files_per_batch']:
        raise ValueError('clean and mixed controls require identical office inputs and batch boundaries')
    same_salt=bool(a.get('session_salt_sha256')) and a.get('session_salt_sha256')==b.get('session_salt_sha256')
    positive=set()
    for p in mixed.glob('batches/*/segment_gt.jsonl'):
        positive.update(json.loads(x)['segment_uid'] for x in p.read_text().splitlines())
    def features(root,skip):
        out=Counter()
        import gzip
        paths=list(root.glob('batches/*/office_sessions.csv'))+list(root.glob('batches/*/office_sessions.csv.gz'))
        for p in sorted(paths):
            stream=gzip.open(p,'rt') if p.suffix=='.gz' else p.open()
            with stream as f:
                for row in csv.DictReader(f):
                    if row['segment_uid'] in skip:continue
                    # Only the run-specific salted identifiers differ; every feature,
                    # including packet arrays and payload facts, must remain equal.
                    for key in ('session_uid','segment_uid') + (() if same_salt else ('host_key','server_key')):row.pop(key)
                    out[hashlib.sha256(json.dumps(row,sort_keys=True).encode()).hexdigest()]+=1
        return out
    x=features(clean,set());y=features(mixed,positive)
    result={'clean_segments':sum(x.values()),'mixed_office_segments':sum(y.values()),
            'missing_office_segments':sum((x-y).values()),'changed_or_extra_office_segments':sum((y-x).values()),
            'office_features_preserved':x==y,'host_identity_verified':same_salt,'positive_segments':len(positive),
            'interpretation':'positive sessions add measured features; replay does not change pre-existing office flow features'}
    (mixed/'clean_mixed_comparison.json').write_text(json.dumps(result,indent=2)+'\n')
    if x!=y:raise ValueError('office feature preservation failed; see clean_mixed_comparison.json')
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--clean',required=True);p.add_argument('--mixed',required=True)
    a=p.parse_args();print(json.dumps(compare(a.clean,a.mixed),indent=2))

if __name__=='__main__':main()
