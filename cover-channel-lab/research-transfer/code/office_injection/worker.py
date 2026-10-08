"""Consume processor-local sealed retention jobs; publication is a separate step."""
import argparse
import json
import os
import time
from pathlib import Path
from .pipeline import branch,dump
from .dataset import export
from .context import build

def once(spool,catalog,runs,repeats=6,seed=1701):
    runs=Path(runs);runs.mkdir(parents=True,exist_ok=True);results=[]
    for ready in sorted(Path(spool).glob('*/ready.json')):
        ident='cc-'+ready.parent.name;out=runs/ident;failure=runs/(ident+'.failed.json')
        if (out/'worker_done.json').exists() or failure.exists():continue
        try:
            job=json.loads(ready.read_text())
            if job['status']!='ready':raise ValueError('unsealed job')
            # This branch's request hash/commit detects changed inputs/config/code.
            report=branch(catalog,job['inputs'],out,ident,repeats,seed)
            if not (out/'challenge_dataset/manifest.json').exists():export(out,out/'challenge_dataset')
            if not (out/'context/manifest.json').exists():build(out,out/'context')
            dump(out/'worker_done.json',{'status':'validated_local','publication':'requires separate approval',
                                        'source_job':str(ready.resolve())})
            results.append({'run_id':ident,'status':report['status']})
        except Exception as exc:
            dump(failure,{'status':'failed_retained','error':str(exc),'output':str(out),
                          'retry':'inspect artifacts; new output/run_id required for an incomplete pipeline run'})
            results.append({'run_id':ident,'status':'failed_retained','error':str(exc)})
    return results

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for flag in ('spool','catalog','runs'):p.add_argument('--'+flag,required=True)
    p.add_argument('--repeats',type=int,default=6);p.add_argument('--seed',type=int,default=1701)
    p.add_argument('--poll-seconds',type=float,default=30);p.add_argument('--once',action='store_true')
    a=p.parse_args()
    if a.poll_seconds<1:raise ValueError('poll interval must be >= 1 second')
    os.nice(10)
    while True:
        print(json.dumps(once(a.spool,a.catalog,a.runs,a.repeats,a.seed)),flush=True)
        if a.once:return
        time.sleep(a.poll_seconds)

if __name__=='__main__':main()
