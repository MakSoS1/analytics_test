"""Remote-only, bounded batch driver. Each batch writes a new retained run."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--image',default='cover-complete:20261002')
    parser.add_argument('--entry',action='append',default=[])
    parser.add_argument('--profile',action='append',default=[])
    parser.add_argument('--all',action='store_true')
    parser.add_argument('--registry',type=Path)
    parser.add_argument('--events',type=int,default=3)
    parser.add_argument('--seed',type=int,default=20261002)
    parser.add_argument('--native-interval',type=float)
    parser.add_argument('--mechanics',action='store_true')
    parser.add_argument('--timing',choices=('native','accelerated_smoke'),default='accelerated_smoke')
    a=parser.parse_args()
    if not a.all and not a.entry:parser.error('explicit --all or --entry required')
    if shutil.disk_usage(a.out.parent).free/(1<<30)<20 or os.getloadavg()[0]>=2:raise SystemExit('resource guard: defer')
    root=Path(__file__).resolve().parent
    registry=json.loads((a.registry or root/'registry.json').read_text());jobs=[]
    adapter_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob('*.py')}
    adapter_identity=hashlib.sha256(json.dumps(adapter_hashes,sort_keys=True).encode()).hexdigest()
    for e in registry['entries']:
        if not a.all and e['entry_id'] not in a.entry:continue
        for p in e['profiles']:
            if a.profile and p['profile_id'] not in a.profile:continue
            for arm in ('scenario','control'):
                body={'entry_id':e['entry_id'],'profile_id':p['profile_id'],'arm':arm,'seed':a.seed,
                      'network':'none','timing':a.timing,'registry_sha256':registry['sha256'],'entry':{**e,'dataset_role':p.get('dataset_role',e['dataset_role'])},'profile':p,'events':p.get('runtime_events',a.events),'native_interval':p.get('native_interval',a.native_interval),'mechanics':a.mechanics,
                      'runtime_adapters_sha256':adapter_identity,'timeout_seconds':180 if a.timing=='accelerated_smoke' else 900,
                      'path_rtt_ms':p.get('path_rtt_ms'),
                      **{k:p[k] for k in ('path_profile','client_mtu','client_tcp_timestamps') if p.get(k) is not None}}
                jobs.append({**body,'job_id':hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest()})
    if not jobs:raise SystemExit('no requested entries')
    a.out.mkdir(parents=True,exist_ok=False)
    snapshot=a.out.resolve()/'runtime_code';snapshot.mkdir()
    for file in ('entrypoint.py','stage_controls.py','browser_guard.py','mechanic_patch.py','browser_client.py','application_patch.py','protocol_patch.py','environment.py'):
        shutil.copyfile(root/file,snapshot/file)
    (a.out/'jobs.json').write_text(json.dumps({'jobs':jobs},indent=2)+'\n')
    image_id=subprocess.check_output(['docker','image','inspect','--format','{{.Id}}',a.image],text=True).strip()
    manifest={'image_id':image_id,'entrypoint_sha256':hashlib.sha256((snapshot/'entrypoint.py').read_bytes()).hexdigest(),
              'control_adapter_sha256':hashlib.sha256((snapshot/'stage_controls.py').read_bytes()).hexdigest(),
              'browser_guard_sha256':hashlib.sha256((snapshot/'browser_guard.py').read_bytes()).hexdigest(),
              'mechanic_patch_sha256':hashlib.sha256((snapshot/'mechanic_patch.py').read_bytes()).hexdigest(),
              'browser_client_sha256':hashlib.sha256((snapshot/'browser_client.py').read_bytes()).hexdigest(),
              'application_patch_sha256':hashlib.sha256((snapshot/'application_patch.py').read_bytes()).hexdigest(),
              'protocol_patch_sha256':hashlib.sha256((snapshot/'protocol_patch.py').read_bytes()).hexdigest(),
              'environment_sha256':hashlib.sha256((snapshot/'environment.py').read_bytes()).hexdigest(),
              'registry_sha256':registry['sha256'],'jobs':len(jobs),'network':'none','cpus':2,'memory_gib':4,
              'timing':a.timing,'started_at':time.time(),'production_ready':False}
    (a.out/'runtime_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    name='ccfull-'+hashlib.sha256(str(a.out.resolve()).encode()).hexdigest()[:16]
    command=['docker','run','--rm','--init','--name',name,'--network=none','--cpus=2','--memory=4g','--shm-size=512m','--pids-limit=512',
             '--cap-add=NET_ADMIN','--cap-add=NET_RAW','--cap-add=SYS_ADMIN','--security-opt=apparmor=unconfined',
             '--mount',f'type=bind,src={a.out.resolve()},dst=/out',
             '--mount',f'type=bind,src={snapshot / "entrypoint.py"},dst=/entrypoint.py,readonly',a.image,'/out/jobs.json']
    command[-2:-2]=['--mount',f'type=bind,src={snapshot / "stage_controls.py"},dst=/stage_controls.py,readonly']
    command[-2:-2]=['--mount',f'type=bind,src={snapshot / "browser_guard.py"},dst=/browser_guard.py,readonly']
    command[-2:-2]=['--mount',f'type=bind,src={snapshot / "mechanic_patch.py"},dst=/mechanic_patch.py,readonly']
    command[-2:-2]=['--mount',f'type=bind,src={snapshot / "browser_client.py"},dst=/browser_client.py,readonly']
    command[-2:-2]=['--mount',f'type=bind,src={snapshot / "application_patch.py"},dst=/application_patch.py,readonly']
    command[-2:-2]=['--mount',f'type=bind,src={snapshot / "protocol_patch.py"},dst=/protocol_patch.py,readonly']
    command[-2:-2]=['--mount',f'type=bind,src={snapshot / "environment.py"},dst=/environment.py,readonly']
    try:
        with (a.out/'runtime.log').open('w') as log:
            cp=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=21600)
    finally:
        subprocess.run(['docker','stop',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    manifest.update(exit_code=cp.returncode,ended_at=time.time())
    (a.out/'runtime_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'jobs':len(jobs),'exit_code':cp.returncode,'out':str(a.out)}))


if __name__=='__main__':main()
