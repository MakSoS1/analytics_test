from __future__ import annotations

import argparse
import json
from pathlib import Path

from .ech_v3 import validate_ech_import, curl_ech_capability
from .environment_evidence_v3 import validate as validate_environment
from .framework_holdout_v3 import validate_source as validate_framework_source
from .long_timing_evidence_v4 import validate as validate_long_timing


def framework_status(root:Path|None)->dict:
    if root is None or not root.exists():return {'validated':False,'records':0,'frameworks':[],'errors':['external framework evidence missing'],'model_metrics':{}}
    rows,errors=validate_framework_source(root);metrics={};mp=root/'framework_model_metrics.json'
    if mp.exists():
        try:metrics=json.loads(mp.read_text())
        except Exception as e:errors.append(f'framework_model_metrics.json invalid: {e}')
    return {'validated':bool(rows) and not errors,'records':len(rows),'frameworks':sorted({str(r.get('framework','')) for r in rows if r.get('framework')}),'errors':errors,'model_metrics':metrics,'model_evaluation_ready':bool(metrics)}


def environment_status(root:Path|None)->dict:
    if root is None or not root.exists():return {'validated':False,'records':0,'client_diversity_ready':False,'server_diversity_ready':False,'network_diversity_ready':False,'reason':'environment evidence missing'}
    return validate_environment(root)


def ech_status(root:Path|None)->dict:
    report={'local_capability':curl_ech_capability()};report['external_wire_real']=validate_ech_import(root) if root is not None and root.exists() else {'available':False,'validated':False,'reason':'wire-real ECH evidence missing','records':0,'model_evaluation_ready':False,'model_metrics':{}}
    return report


def long_timing_status(root:Path|None)->dict:
    if root is None or not root.exists():return {'validated':False,'records':0,'reason':'self-hosted 1200/3600s timing evidence missing'}
    return validate_long_timing(root)


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--framework-root');ap.add_argument('--ech-root');ap.add_argument('--environment-root');ap.add_argument('--long-timing-root');ap.add_argument('--out-dir',required=True);a=ap.parse_args();out=Path(a.out_dir);out.mkdir(parents=True,exist_ok=True)
    fw=framework_status(Path(a.framework_root) if a.framework_root else None);ech=ech_status(Path(a.ech_root) if a.ech_root else None);env=environment_status(Path(a.environment_root) if a.environment_root else None);long=long_timing_status(Path(a.long_timing_root) if a.long_timing_root else None)
    (out/'framework_status.json').write_text(json.dumps(fw,indent=2,sort_keys=True)+'\n');(out/'ech_status.json').write_text(json.dumps(ech,indent=2,sort_keys=True)+'\n');(out/'environment_status.json').write_text(json.dumps(env,indent=2,sort_keys=True)+'\n');(out/'long_timing_status.json').write_text(json.dumps(long,indent=2,sort_keys=True)+'\n')
    summary={'framework_ready':fw.get('validated',False),'framework_model_metrics_ready':fw.get('model_evaluation_ready',False),'wire_real_ech_ready':(ech.get('external_wire_real') or {}).get('validated',False),'ech_model_metrics_ready':(ech.get('external_wire_real') or {}).get('model_evaluation_ready',False),'environment_ready':env.get('validated',False),'external_long_timing_ready':long.get('validated',False)}
    (out/'external_evidence_summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n');print(json.dumps(summary,sort_keys=True))

if __name__=='__main__':main()
