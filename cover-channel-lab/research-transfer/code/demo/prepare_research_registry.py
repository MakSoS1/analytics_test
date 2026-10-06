"""Pin deterministic paired path/cadence settings before capturing outcomes."""
import argparse
import copy
import json
from pathlib import Path
from cover_runtime.environment import profile_config
from office_injection.cover_registry import digest


def prepare(base,seed=20261004,path_profile='office_path_v1'):
    if base['sha256']!=digest({k:v for k,v in base.items() if k!='sha256'}):
        raise ValueError('base registry identity changed')
    body=copy.deepcopy({k:v for k,v in base.items() if k!='sha256'})
    for entry in body['entries']:
        for profile in entry['profiles']:
            profile.update(profile_config(entry['entry_id'],profile['profile_id'],seed,entry.get('family'),path_profile))
    body['parent_registry_sha256']=base['sha256']
    body['research_policy']='bounded native events; predeclared paired path profile '+path_profile+'; no office equivalence claim'
    body['path_profile']=path_profile
    return {**body,'sha256':digest(body)}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--seed',type=int,default=20261004);p.add_argument('--path-profile',default='office_path_v1')
    a=p.parse_args();registry=prepare(json.loads(a.base.read_text()),a.seed,a.path_profile)
    with a.out.open('x') as f:f.write(json.dumps(registry,indent=2)+'\n')
    print(registry['sha256'])

if __name__=='__main__':main()
