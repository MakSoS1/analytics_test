from __future__ import annotations

import argparse
import json
from pathlib import Path


def _load(path: str | None) -> dict:
    return json.loads(Path(path).read_text()) if path and Path(path).exists() else {}


def _fpr(m:dict)->float:
    if 'fpr' in m:return float(m.get('fpr',1.0))
    cm=m.get('confusion_matrix')
    if cm:
        try:tn,fp=cm[0];return float(fp/max(1,tn+fp))
        except Exception:pass
    return 1.0


def metric_ok(m:dict,min_precision:float,min_recall:float,max_fpr:float,require_precision:bool=True)->bool:
    if not m or int(m.get('rows',m.get('holdout_rows',0)))<=0:return False
    recall=float(m.get('recall',0));precision=float(m.get('precision',0));fpr=_fpr(m)
    return recall>=min_recall and fpr<=max_fpr and (precision>=min_precision if require_precision else True)


def _metric_cells_ok(cells:dict,min_recall:float,max_fpr:float)->tuple[bool,list[dict]]:
    checks=[]
    if not cells:return False,checks
    for name,m in cells.items():
        passed=(m or {}).get('status')=='ok' and metric_ok(m,0.0,min_recall,max_fpr,False);checks.append({'name':name,'passed':passed,'metrics':m})
    return bool(checks) and all(x['passed'] for x in checks),checks


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--baseline-report',required=True);ap.add_argument('--advanced-report');ap.add_argument('--mixed-report');ap.add_argument('--advanced-mixed-report');ap.add_argument('--unseen-report');ap.add_argument('--framework-report');ap.add_argument('--ech-report');ap.add_argument('--environment-report');ap.add_argument('--long-timing-report');ap.add_argument('--research-readiness-report');ap.add_argument('--out',required=True)
    ap.add_argument('--min-precision',type=float,default=.95);ap.add_argument('--min-recall',type=float,default=.95);ap.add_argument('--max-fpr',type=float,default=50/1_000_000);ap.add_argument('--dataset-valid',choices=['true','false'],default='true');ap.add_argument('--require-nine-point-evidence',action='store_true');ap.add_argument('--enforce',action='store_true');a=ap.parse_args()
    baseline=_load(a.baseline_report);advanced=_load(a.advanced_report);mixed=_load(a.mixed_report);advanced_mixed=_load(a.advanced_mixed_report);unseen=_load(a.unseen_report);framework=_load(a.framework_report);ech=_load(a.ech_report);environment=_load(a.environment_report);long_external=_load(a.long_timing_report);readiness=_load(a.research_readiness_report)

    checks=[]
    for name in ('B1-content','B2-session','B3-opaque'):
        r=(baseline.get('models') or {}).get(name,{})
        for part in ('test','challenge'):
            m=r.get(part,{}) or {}
            if int(m.get('rows',0))>0 and int(m.get('positives',0))>0:checks.append({'name':name,'partition':part,'passed':metric_ok(m,a.min_precision,a.min_recall,a.max_fpr),'metrics':m})
    for key in ('opaque_sequence','visible_sequence','fusion'):
        r=advanced.get(key,{}) or {};m=r.get('challenge',{}) or {}
        if int(m.get('rows',0))>0:checks.append({'name':key,'partition':'challenge','passed':metric_ok(m,a.min_precision,a.min_recall,a.max_fpr),'metrics':m})
    mixed_accept=(mixed.get('session_acceptance') or {}).get('passed') if mixed else None
    advanced_mixed_checks=[]
    for key in ('B2-opaque-sequence','fusion-router'):
        m=advanced_mixed.get(key,{}) or {}
        if int(m.get('rows',0))>0:advanced_mixed_checks.append({'name':key,'partition':'D_mixed','passed':metric_ok(m,a.min_precision,a.min_recall,a.max_fpr),'metrics':m})

    unseen_ready,unseen_checks=_metric_cells_ok(unseen.get('leave_one_family_out') or {},a.min_recall,a.max_fpr);compositional_ready,compositional_checks=_metric_cells_ok(unseen.get('compositional_holdout') or {},a.min_recall,a.max_fpr)
    framework_presence=bool(framework.get('validated')) and {'sliver','adaptix','mythic_httpx','mythic_websocket'}.issubset(set(framework.get('frameworks',[])));fw_metrics=framework.get('model_metrics') or {};framework_metrics_ready,framework_checks=_metric_cells_ok(fw_metrics,a.min_recall,a.max_fpr);framework_ready=framework_presence and framework_metrics_ready
    ech_ext=ech.get('external_wire_real') or {};ech_metrics=ech_ext.get('model_metrics') or {};ech_suspicious=ech_metrics.get('suspicious') or {};ech_benign=ech_metrics.get('benign') or {};ech_pair_delta=float(ech_metrics.get('paired_on_off_mean_abs_delta',999.0));ech_metric_ready=metric_ok(ech_suspicious,0.0,a.min_recall,1.0,False) and int(ech_benign.get('rows',0))>0 and _fpr(ech_benign)<=a.max_fpr and ech_pair_delta<=float(ech_metrics.get('max_allowed_pair_delta',.10));ech_ready=bool(ech_ext.get('validated')) and bool(ech_ext.get('model_evaluation_ready')) and ech_metric_ready
    environment_ready=bool(environment.get('validated')) and all([environment.get('client_diversity_ready'),environment.get('server_diversity_ready'),environment.get('network_diversity_ready')]);external_long_ready=bool(long_external.get('validated'))
    benign_ready=bool(readiness.get('benign_corpus_ready')) and bool(readiness.get('benign_multi_event_ready',False));hosted_long_ready=bool(readiness.get('long_timing_ready')) and bool(readiness.get('long_timing_multi_event_ready',False));sequence_ready=(advanced.get('opaque_sequence') or advanced.get('sequence') or {}).get('status')=='ok';fusion_ready=(advanced.get('fusion') or {}).get('status')=='ok' and bool(advanced.get('opaque_plaintext_leakage_guard'))

    evidence={'external_framework_holdout':framework_ready,'benign_corpus':benign_ready,'client_server_diversity':environment_ready,'network_domain_randomization':bool(readiness.get('kernel_netem_ready')) and environment_ready,'long_term_timing':hosted_long_ready and external_long_ready,'wire_real_ech':ech_ready,'unseen_evaluation':unseen_ready and compositional_ready,'sequence_expert':sequence_ready,'visibility_fusion':fusion_ready}
    nine_point_ready=all(evidence.values());dataset_valid=a.dataset_valid=='true';quality_checks_pass=bool(checks) and all(c['passed'] for c in checks);advanced_mixed_pass=bool(advanced_mixed_checks) and all(c['passed'] for c in advanced_mixed_checks);model_quality=quality_checks_pass and (mixed_accept is True) and advanced_mixed_pass and unseen_ready and compositional_ready;promotion_evidence_ok=nine_point_ready if a.require_nine_point_evidence else True;model_candidate=dataset_valid and model_quality and promotion_evidence_ok;model_artifacts_created=bool((baseline.get('models') or {})) and sequence_ready and fusion_ready
    report={'policy_revision':4,'dataset_valid':dataset_valid,'model_artifacts_created':model_artifacts_created,'model_quality_passed':model_quality,'model_candidate':model_candidate,'nine_point_evidence_required':a.require_nine_point_evidence,'nine_point_evidence_ready':nine_point_ready,'nine_point_evidence':evidence,'min_precision':a.min_precision,'min_recall':a.min_recall,'max_fpr':a.max_fpr,'expert_checks':checks,'mixed_session_acceptance':mixed_accept,'advanced_mixed_checks':advanced_mixed_checks,'unseen_metric_checks':unseen_checks,'compositional_metric_checks':compositional_checks,'framework_metric_checks':framework_checks,'ech_metric_check':{'passed':ech_metric_ready,'metrics':ech_metrics},'external_framework_holdout_ready':framework_ready,'environment_diversity_ready':environment_ready,'hosted_long_timing_ready':hosted_long_ready,'external_long_timing_ready':external_long_ready,'wire_real_ech_ready':ech_ready}
    p=Path(a.out);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,sort_keys=True))
    if a.enforce and not report['model_candidate']:raise SystemExit('model candidate promotion failed')

if __name__=='__main__':main()
