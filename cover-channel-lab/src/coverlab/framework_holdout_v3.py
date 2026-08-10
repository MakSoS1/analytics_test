from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

from .research_contract_v3 import validate_framework_records


def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def validate_source(source: Path) -> tuple[list[dict], list[str]]:
    manifest=source/'framework_holdout.jsonl'
    if not manifest.exists(): return [], ['framework_holdout.jsonl is missing']
    records=load_jsonl(manifest); errors=validate_framework_records(records)
    for i,r in enumerate(records):
        rel=r.get('pcap_file','')
        p=source/rel
        if not rel or not p.is_file(): errors.append(f'row {i}: pcap_file missing')
        elif sha256(p)!=r.get('pcap_sha256'): errors.append(f'row {i}: pcap sha256 mismatch')
    return records,errors


def import_holdout(source: Path,out: Path) -> dict:
    records,errors=validate_source(source)
    if errors: raise RuntimeError('; '.join(errors))
    out.mkdir(parents=True,exist_ok=True)
    (out/'manifests').mkdir(exist_ok=True); (out/'bronze').mkdir(exist_ok=True)
    copied=[]
    for r in records:
        src=source/r['pcap_file']; dst=out/'bronze'/src.name; shutil.copy2(src,dst); copied.append(dst.name)
    (out/'manifests'/'framework_holdout.jsonl').write_text('\n'.join(json.dumps(r,separators=(',',':')) for r in records)+'\n')
    report={'stage':'J_framework_holdout','records':len(records),'frameworks':sorted({r['framework'] for r in records}),
            'training_eligible':False,'challenge_only':True,'pcaps':copied,'validated':True}
    (out/'framework_holdout_report.json').write_text(json.dumps(report,indent=2)); return report


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--source',required=True); ap.add_argument('--out',required=True); a=ap.parse_args()
    print(json.dumps(import_holdout(Path(a.source),Path(a.out))))

if __name__=='__main__': main()
