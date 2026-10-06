"""Explicit sealed-input execution, isolated from the baseline batch runner."""
import argparse
import json
from pathlib import Path
from .pipeline import branch

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--catalog',required=True)
    p.add_argument('--office-inputs',required=True,help='JSON list of existing local .pkts paths; .pay pairs required')
    p.add_argument('--out-dir',required=True)
    p.add_argument('--run-id',required=True)
    p.add_argument('--repeats',type=int,default=6)
    p.add_argument('--seed',type=int,default=1701)
    p.add_argument('--files-per-batch',type=int,default=2)
    p.add_argument('--offline-fixture',action='store_true',help='Tests only: bypass replay; report records this mode')
    p.add_argument('--skip-parquet',action='store_true')
    a=p.parse_args()
    inputs=json.loads(Path(a.office_inputs).read_text())
    result=branch(a.catalog,inputs,a.out_dir,a.run_id,a.repeats,a.seed,a.files_per_batch,
                  not a.offline_fixture,a.skip_parquet)
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
