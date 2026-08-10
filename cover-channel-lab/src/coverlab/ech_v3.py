from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from .research_contract_v3 import ECH_MODES, validate_ech_record


def curl_ech_capability() -> dict:
    cp=subprocess.run(['curl','--version'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=False)
    help_cp=subprocess.run(['curl','--help','all'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=False)
    return {'curl_version':cp.stdout.splitlines()[0] if cp.stdout else '', 'ech_option': '--ech' in help_cp.stdout,
            'version_rc':cp.returncode}


def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()


def validate_ech_import(root: Path) -> dict:
    manifest=root/'ech_holdout.jsonl'
    if not manifest.exists(): return {'available':False,'validated':False,'reason':'ech_holdout.jsonl missing','records':0}
    rows=[json.loads(x) for x in manifest.read_text().splitlines() if x.strip()]
    errors=[]
    for i,r in enumerate(rows):
        errors += [f'row {i}: {e}' for e in validate_ech_record(r)]
        p=root/str(r.get('pcap_file',''))
        if not p.is_file(): errors.append(f'row {i}: pcap missing')
        elif sha256(p)!=r.get('pcap_sha256'): errors.append(f'row {i}: pcap sha mismatch')
    modes={r.get('ech_mode') for r in rows}
    required={'grease','accepted_h2','accepted_h3','rejected','shared_frontend_benign','shared_frontend_suspicious'}
    missing=sorted(required-modes)
    if missing: errors.append('missing ECH modes: '+','.join(missing))
    return {'available':bool(rows),'validated':not errors,'records':len(rows),'modes':sorted(m for m in modes if m in ECH_MODES),'errors':errors}


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--import-root'); ap.add_argument('--out',required=True); a=ap.parse_args()
    report={'local_capability':curl_ech_capability()}
    if a.import_root: report['external_wire_real']=validate_ech_import(Path(a.import_root))
    p=Path(a.out); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(report,indent=2)); print(json.dumps(report))

if __name__=='__main__': main()
