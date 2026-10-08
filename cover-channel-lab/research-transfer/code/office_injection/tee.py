"""Opt-in processor-side retention before the baseline deletes sealed row pairs.

Run this entry point with the usual office_batches arguments. No sensor
transfer is added; selected files already on .18 are pinned by hard links.
The baseline processing method and its default feature extraction are unchanged.
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo
from .pipeline import dump,validated_inputs

def retain(local,start,end,spool,batch_id,budget_gb=8):
    spool=Path(spool);spool.mkdir(parents=True,exist_ok=True)
    target=spool/batch_id
    if (target/'ready.json').exists():
        manifest=json.loads((target/'ready.json').read_text())
        if validated_inputs(manifest['inputs'])!=manifest['verified_inputs']:raise ValueError('retained input changed')
        return manifest
    groups={}
    for stamp,pair in sorted(local.items()):
        if start<=stamp<end:
            hour=datetime.fromtimestamp(stamp,ZoneInfo('Europe/Moscow')).strftime('%Y-%m-%dT%H')
            groups.setdefault(hour,[]).append(pair)
    selected=[]
    for pairs in groups.values():
        # Equal-duration chunks: row count is an observed packet-load ranking.
        pairs.sort(key=lambda x:(Path(x['pkts']).stat().st_size,str(x['pkts'])))
        for i in sorted({0,len(pairs)//2,len(pairs)-1}):selected.append(pairs[i])
    size=sum(Path(p[k]).stat().st_size for p in selected for k in ('pkts','pay'))
    retained=sum(p.stat().st_size for p in spool.glob('*/rows/*') if p.is_file())
    if retained+size>budget_gb*2**30 or shutil.disk_usage(spool).free<5*2**30:
        raise ValueError('retention budget reached; no automatic dataset deletion')
    rows=target/'rows';rows.mkdir(parents=True,exist_ok=True)
    for pair in selected:
        for kind in ('pkts','pay'):
            source=Path(pair[kind]);destination=rows/source.name
            if destination.exists():
                if not os.path.samefile(source,destination):raise ValueError('incomplete retention differs; inspect manually')
            else:os.link(source,destination) # Fail closed on cross-device; never add an unbounded copy.
    inputs=[str((rows/Path(p['pkts']).name).resolve()) for p in selected]
    manifest={'status':'ready','inputs':inputs,'verified_inputs':validated_inputs(inputs),
              'source_batch_start':start,'source_batch_end':end,'selection':'per Moscow hour: low/median/high row-count chunks',
              'logical_bytes':size,'no_sensor_transfer':True,'deletion_policy':'manual; never auto-delete'}
    dump(target/'inputs.json',inputs);dump(target/'ready.json',manifest);return manifest

def ingest_templates(sessions_csv,store):
    """Office skeletons of this batch join the store; later injections use them."""
    from .templates import ingest
    if Path(sessions_csv).exists():return ingest([sessions_csv],store)
    return []

@contextmanager
def hook(baseline,spool,budget,templates=None):
    original=baseline.Batches.process
    def process(self,start,final,local):
        ident=baseline.epoch_name(start)+'-'+hashlib.sha256(str(self.work.resolve()).encode()).hexdigest()[:8]
        try:retain(local,start,start+self.a.batch_seconds,spool,ident,budget)
        except Exception as exc:
            # A disabled/full second branch must not interrupt office capture.
            try:baseline.log('injection retention unavailable: '+str(exc),self.logf)
            except Exception:pass # The baseline may still be able to process/unlink its own batch.
            try:
                Path(spool).mkdir(parents=True,exist_ok=True)
                dump(Path(spool)/(ident+'.failed.json'),{'status':'retention_failed','reason':str(exc)})
            except Exception:pass # Inaccessible/full spool must not turn a retention failure into a baseline failure.
        result=original(self,start,final,local)
        if templates:
            try:ingest_templates(self.bdir/baseline.epoch_name(start)/'office_sessions.csv',templates)
            except Exception as exc:
                # Profile refresh is best effort; the baseline batch is already done.
                try:baseline.log('injection template ingest failed: '+str(exc),self.logf)
                except Exception:pass
        return result
    baseline.Batches.process=process
    try:yield
    finally:baseline.Batches.process=original

def main():
    p=argparse.ArgumentParser(add_help=False);p.add_argument('--injection-spool',required=True)
    p.add_argument('--injection-budget-gb',type=float,default=8)
    p.add_argument('--injection-templates',help='office skeleton store refreshed after every batch (templates.py)')
    a,rest=p.parse_known_args()
    if a.injection_budget_gb<=0:raise ValueError('positive retention budget required')
    import office_batches as baseline
    sys.argv=[str(Path(baseline.__file__)),*rest]
    with hook(baseline,a.injection_spool,a.injection_budget_gb,a.injection_templates):return baseline.main()

if __name__=='__main__':raise SystemExit(main())
