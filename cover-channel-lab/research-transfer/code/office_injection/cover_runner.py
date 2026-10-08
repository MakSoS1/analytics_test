"""Resource-bounded launcher for the pinned isolated Cover Channels runtime."""
from __future__ import annotations
import ipaddress
import json
import re
import subprocess
from pathlib import Path
from .cover_registry import digest


def prepare_run(registry: dict, config: dict, out: Path) -> dict:
    if config.get('network') != 'none': raise ValueError('runtime must have network=none')
    for target in config.get('targets', []):
        try: valid = ipaddress.ip_address(target) in ipaddress.ip_network('10.20.0.0/24')
        except ValueError: valid = target.endswith('.test') and re.fullmatch(r'[a-z0-9.-]+',target) is not None
        if not valid: raise ValueError('target outside isolated fixture: ' + target)
    if config.get('timing') not in ('native', 'accelerated_smoke'): raise ValueError('native timing or explicit smoke required')
    if config.get('arm') not in ('scenario', 'control'): raise ValueError('unknown arm')
    entries = [e for e in registry['entries'] if e['entry_id'] == config.get('entry_id')]
    if len(entries) != 1: raise ValueError('unknown registry entry')
    profiles = [p for p in entries[0]['profiles'] if p['profile_id'] == config.get('profile_id')]
    if len(profiles) != 1: raise ValueError('unknown registry profile')
    image=config['image']
    if not re.fullmatch(r'[a-zA-Z0-9_./:@-]+', image): raise ValueError('invalid image')
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
    body={**config,'registry_sha256':registry['sha256'],'entry':entries[0],'profile':profiles[0]}
    job={**body,'profile':profiles[0],'job_id':digest(body),'output':str(out), 'timing_training_eligible':False}
    (out/'job.json').write_text(json.dumps(job,indent=2)+'\n')
    command=['docker','run','--rm','--init','--name','ccsingle-'+job['job_id'][:16],'--network=none','--cpus=2','--memory=4g','--pids-limit=512',
             '--cap-add=NET_ADMIN','--cap-add=NET_RAW','--cap-add=SYS_ADMIN',
             '--security-opt=apparmor=unconfined','--mount',f'type=bind,src={out},dst=/out',
             image,'/out/job.json']
    return {**job,'docker_command':command}


def run_campaign(job: dict, runtime: dict) -> dict:
    base={k:job[k] for k in ('entry_id','profile_id','arm','registry_sha256','job_id')}
    if runtime.get('dispatch_verified') is not True: raise ValueError('upstream package dispatch hooks not verified')
    client=job['profile']['client']
    if client not in runtime.get('clients',[]):return {**base,'status':'blocked','reason':'missing_client:'+client}
    if runtime.get('free_disk_gib',0)<20 or runtime.get('load1',2)>=2:
        return {**base,'status':'deferred','reason':'resource_guard'}
    timeout=int(runtime.get('timeout_seconds',600))
    if not 1<=timeout<=86400:raise ValueError('invalid bounded timeout')
    out=Path(job['output'])
    try:
        with (out/'runtime.log').open('w') as log:
            result=subprocess.run(job['docker_command'],stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
    except subprocess.TimeoutExpired:
        return {**base,'status':'failed','reason':'runtime_timeout'}
    finally:
        if '--name' in job['docker_command']:
            name=job['docker_command'][job['docker_command'].index('--name')+1]
            subprocess.run(['docker','stop',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
    path=out/job['job_id']/'result.json'
    if result.returncode or not path.exists():return {**base,'status':'failed','reason':'runtime_exit:'+str(result.returncode)}
    evidence=json.loads(path.read_text())
    if any(evidence.get(k)!=v for k,v in base.items()):raise ValueError('runtime result identity mismatch')
    return evidence
