#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,os
from pathlib import Path
from huggingface_hub import HfApi,create_repo

DEFAULT='Maksim123321/remote-admin-anomaly-v1'

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument('--folder',type=Path,required=True); ap.add_argument('--remote-path',required=True); ap.add_argument('--repo',default=DEFAULT); ap.add_argument('--status',type=Path); args=ap.parse_args()
    token=os.environ.get('HF_TOKEN','').strip(); payload={'repo':args.repo,'remote_path':args.remote_path,'token_present':bool(token)}
    if not token:
        payload.update(status='skipped',reason='HF_TOKEN missing')
    else:
        if not args.folder.is_dir() or not any(p.is_file() for p in args.folder.rglob('*')): raise SystemExit('analysis folder empty')
        create_repo(repo_id=args.repo,repo_type='dataset',private=True,exist_ok=True,token=token)
        HfApi(token=token).upload_folder(repo_id=args.repo,repo_type='dataset',folder_path=str(args.folder),path_in_repo=args.remote_path.strip('/'),token=token,commit_message='Remote Admin V1 merged analysis')
        payload.update(status='uploaded',reason='merged Gold/model analysis uploaded')
    if args.status:
        args.status.parent.mkdir(parents=True,exist_ok=True); args.status.write_text(json.dumps(payload,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps(payload,sort_keys=True)); return 0
if __name__=='__main__': raise SystemExit(main())
