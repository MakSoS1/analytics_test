from __future__ import annotations

import argparse
import json
from pathlib import Path


def _load(path: str | None) -> dict:
    return json.loads(Path(path).read_text()) if path and Path(path).exists() else {}


def metric_ok(m: dict, min_precision: float, min_recall: float, max_fpr: float) -> bool:
    if not m or int(m.get("rows", 0)) <= 0:
        return False
    return (
        float(m.get("precision", 0)) >= min_precision
        and float(m.get("recall", 0)) >= min_recall
        and float(m.get("fpr", 0)) <= max_fpr
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline-report", required=True)
    ap.add_argument("--advanced-report")
    ap.add_argument("--mixed-report")
    ap.add_argument("--advanced-mixed-report")
    ap.add_argument("--unseen-report")
    ap.add_argument("--framework-report")
    ap.add_argument("--ech-report")
    ap.add_argument("--environment-report")
    ap.add_argument("--research-readiness-report")
    ap.add_argument("--out", required=True)
    ap.add_argument("--min-precision", type=float, default=.95)
    ap.add_argument("--min-recall", type=float, default=.95)
    ap.add_argument("--max-fpr", type=float, default=50 / 1_000_000)
    ap.add_argument("--dataset-valid", choices=["true", "false"], default="true")
    ap.add_argument("--require-nine-point-evidence", action="store_true")
    ap.add_argument("--enforce", action="store_true")
    a = ap.parse_args()

    baseline = _load(a.baseline_report)
    advanced = _load(a.advanced_report)
    mixed = _load(a.mixed_report)
    advanced_mixed = _load(a.advanced_mixed_report)
    unseen = _load(a.unseen_report)
    framework = _load(a.framework_report)
    ech = _load(a.ech_report)
    environment = _load(a.environment_report)
    readiness = _load(a.research_readiness_report)

    checks = []
    for name in ("B1-content", "B2-session", "B3-opaque"):
        r = (baseline.get("models") or {}).get(name, {})
        for part in ("test", "challenge"):
            m = r.get(part, {}) or {}
            if int(m.get("rows", 0)) > 0 and int(m.get("positives", 0)) > 0:
                checks.append({
                    "name": name,
                    "partition": part,
                    "passed": float(m.get("precision", 0)) >= a.min_precision and float(m.get("recall", 0)) >= a.min_recall,
                    "metrics": m,
                })
    for key in ("sequence", "fusion"):
        r = advanced.get(key, {}) or {}
        m = r.get("challenge", {}) or {}
        if int(m.get("rows", 0)) > 0:
            checks.append({"name": key, "partition": "challenge", "passed": metric_ok(m, a.min_precision, a.min_recall, 1.0), "metrics": m})

    mixed_accept = (mixed.get("session_acceptance") or {}).get("passed") if mixed else None
    advanced_mixed_checks = []
    for key in ("B2-sequence", "fusion-router"):
        m = advanced_mixed.get(key, {}) or {}
        if int(m.get("rows", 0)) > 0:
            advanced_mixed_checks.append({"name": key, "partition": "D_mixed", "passed": metric_ok(m, a.min_precision, a.min_recall, a.max_fpr), "metrics": m})

    unseen_cells = unseen.get("leave_one_family_out") or {}
    unseen_ready = bool(unseen_cells) and all((r or {}).get("status") == "ok" for r in unseen_cells.values())
    compositional = unseen.get("compositional_holdout") or {}
    compositional_ready = bool(compositional) and all((r or {}).get("status") == "ok" for r in compositional.values())

    framework_ready = bool(framework.get("validated")) and {
        "sliver", "adaptix", "mythic_httpx", "mythic_websocket"
    }.issubset(set(framework.get("frameworks", [])))
    ech_ext = ech.get("external_wire_real") or {}
    ech_ready = bool(ech_ext.get("validated"))
    environment_ready = bool(environment.get("validated")) and all([
        environment.get("client_diversity_ready"),
        environment.get("server_diversity_ready"),
        environment.get("network_diversity_ready"),
    ])
    benign_ready = bool(readiness.get("benign_corpus_ready"))
    long_timing_ready = bool(readiness.get("long_timing_ready"))
    sequence_ready = (advanced.get("sequence") or {}).get("status") == "ok"
    fusion_ready = (advanced.get("fusion") or {}).get("status") == "ok"

    evidence = {
        "external_framework_holdout": framework_ready,
        "benign_corpus": benign_ready,
        "client_server_diversity": environment_ready,
        "network_domain_randomization": bool(readiness.get("kernel_netem_ready")) and environment_ready,
        "long_term_timing": long_timing_ready,
        "wire_real_ech": ech_ready,
        "unseen_evaluation": unseen_ready and compositional_ready,
        "sequence_expert": sequence_ready,
        "visibility_fusion": fusion_ready,
    }
    nine_point_ready = all(evidence.values())
    dataset_valid = a.dataset_valid == "true"
    quality_checks_pass = bool(checks) and all(c["passed"] for c in checks)
    advanced_mixed_pass = bool(advanced_mixed_checks) and all(c["passed"] for c in advanced_mixed_checks)
    model_quality = quality_checks_pass and (mixed_accept is True) and advanced_mixed_pass
    promotion_evidence_ok = nine_point_ready if a.require_nine_point_evidence else True
    model_candidate = dataset_valid and model_quality and promotion_evidence_ok

    report = {
        "policy_revision": 3,
        "dataset_valid": dataset_valid,
        "model_artifacts_created": bool((baseline.get("models") or {})) and sequence_ready and fusion_ready,
        "model_quality_passed": model_quality,
        "model_candidate": model_candidate,
        "nine_point_evidence_required": a.require_nine_point_evidence,
        "nine_point_evidence_ready": nine_point_ready,
        "nine_point_evidence": evidence,
        "min_precision": a.min_precision,
        "min_recall": a.min_recall,
        "max_fpr": a.max_fpr,
        "expert_checks": checks,
        "mixed_session_acceptance": mixed_accept,
        "advanced_mixed_checks": advanced_mixed_checks,
        "unseen_evaluation_ready": unseen_ready,
        "compositional_holdout_ready": compositional_ready,
        "external_framework_holdout_ready": framework_ready,
        "environment_diversity_ready": environment_ready,
        "wire_real_ech_ready": ech_ready,
    }
    p = Path(a.out)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    if a.enforce and not report["model_candidate"]:
        raise SystemExit("model candidate promotion failed")


if __name__ == "__main__":
    main()
