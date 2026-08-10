from __future__ import annotations

import argparse
import json
from pathlib import Path


def _load(path: str|None) -> dict:
    return json.loads(Path(path).read_text()) if path and Path(path).exists() else {}


def metric_ok(m: dict, min_precision: float, min_recall: float, max_fpr: float) -> bool:
    if not m or int(m.get('rows',0)) <= 0: return False
    return float(m.get('precision',0)) >= min_precision and float(m.get('recall',0)) >= min_recall and float(m.get('fpr',0)) <= max_fpr


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--baseline-report',required=True); ap.add_argument('--advanced-report'); ap.add_argument('--mixed-report'); ap.add_argument('--unseen-report')
    ap.add_argument('--framework-report'); ap.add_argument('--ech-report'); ap.add_argument('--out',required=True)
    ap.add_argument('--min-precision',type=float,default=.95); ap.add_argument('--min-recall',type=float,default=.95); ap.add_argument('--max-fpr',type=float,default=50/1_000_000)
    ap.add_argument('--require-external-frameworks',action='store_true'); ap.add_argument('--require-wire-real-ech',action='store_true'); ap.add_argument('--enforce',action='store_true')
    a=ap.parse_args(); baseline=_load(a.baseline_report); advanced=_load(a.advanced_report); mixed=_load(a.mixed_report); unseen=_load(a.unseen_report); framework=_load(a.framework_report); ech=_load(a.ech_report)
    checks=[]
    for name in ('B1-content','B2-session','B3-opaque'):
        r=(baseline.get('models') or {}).get(name,{})
        for part in ('test','challenge'):
            m=r.get(part,{}) or {}
            if int(m.get('rows',0))>0 and int(m.get('positives',0))>0:
                checks.append({'name':name,'partition':part,'passed':float(m.get('precision',0))>=a.min_precision and float(m.get('recall',0))>=a.min_recall,'metrics':m})
    for key in ('sequence','fusion'):
        r=advanced.get(key,{}) or {}; m=r.get('challenge',{}) or {}
        if int(m.get('rows',0))>0:
            checks.append({'name':key,'partition':'challenge','passed':metric_ok(m,a.min_precision,a.min_recall,1.0),'metrics':m})
    mixed_accept=(mixed.get('session_acceptance') or {}).get('passed') if mixed else None
    unseen_cells=(unseen.get('leave_one_family_out') or {})
    unseen_ready=all((r or {}).get('status')=='ok' for r in unseen_cells.values()) if unseen_cells else False
    framework_ready=bool(framework.get('validated')) and {'sliver','adaptix','mythic_httpx','mythic_websocket'}.issubset(set(framework.get('frameworks',[])))
    ech_ext=ech.get('external_wire_real') or {}; ech_ready=bool(ech_ext.get('validated'))
    external_ok=(framework_ready or not a.require_external_frameworks) and (ech_ready or not a.require_wire_real_ech)
    model_quality=bool(checks) and all(c['passed'] for c in checks) and (mixed_accept is not False)
    report={
        'policy_revision':3,'dataset_valid':True,'model_quality_passed':model_quality,'model_candidate':model_quality and external_ok,
        'min_precision':a.min_precision,'min_recall':a.min_recall,'max_fpr':a.max_fpr,'expert_checks':checks,
        'mixed_session_acceptance':mixed_accept,'unseen_evaluation_ready':unseen_ready,
        'external_framework_holdout_ready':framework_ready,'wire_real_ech_ready':ech_ready,
        'external_requirements_enforced':{'frameworks':a.require_external_frameworks,'ech':a.require_wire_real_ech},
    }
    p=Path(a.out); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n'); print(json.dumps(report,sort_keys=True))
    if a.enforce and not report['model_candidate']: raise SystemExit('model candidate promotion failed')

if __name__=='__main__': main()
