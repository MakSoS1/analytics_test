#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from huggingface_hub import HfApi


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def require_file(path: Path) -> Path:
    if not path.is_file() or path.stat().st_size <= 0:
        raise RuntimeError(f"required evidence file missing or empty: {path}")
    return path


def verify_negative_research(
    artifact_root: Path,
    *,
    source_run_id: int,
    source_artifact_id: int,
    source_artifact_name: str,
    source_artifact_digest: str,
) -> dict[str, Any]:
    required = [
        "RESEARCH_GATE.json",
        "models/M0-deterministic.metrics.json",
        "models/M1-lightgbm.metrics.json",
        "models/M2-isolation-forest.metrics.json",
        "models/shortcut-audit.json",
        "evaluation/M1-slices.json",
        "evaluation/M1-hard-benign.json",
        "evaluation/M1-learning-curve.json",
        "release/bronze/H-research-1k/captures/H-research-1k.pcap.zst",
        "release/silver/H-research-1k/suricata/eve.json.zst",
        "release/gold/H-research-1k/production_model_matrix.parquet",
        "release/quality/H-research-1k/production_flow_gold.json",
        "release/quality/H-research-1k/production_leakage.json",
        "release/quality/H-research-1k/capture_health.json",
        "release/quality/H-research-1k/parser_health.json",
    ]
    for relative in required:
        require_file(artifact_root / relative)

    gate = load_json(artifact_root / "RESEARCH_GATE.json")
    m0 = load_json(artifact_root / "models/M0-deterministic.metrics.json")
    m1 = load_json(artifact_root / "models/M1-lightgbm.metrics.json")
    m2 = load_json(artifact_root / "models/M2-isolation-forest.metrics.json")
    shortcut = load_json(artifact_root / "models/shortcut-audit.json")
    slices = load_json(artifact_root / "evaluation/M1-slices.json")
    hard = load_json(artifact_root / "evaluation/M1-hard-benign.json")
    curve = load_json(artifact_root / "evaluation/M1-learning-curve.json")
    production = load_json(artifact_root / "release/quality/H-research-1k/production_flow_gold.json")
    leakage = load_json(artifact_root / "release/quality/H-research-1k/production_leakage.json")
    capture = load_json(artifact_root / "release/quality/H-research-1k/capture_health.json")
    parser = load_json(artifact_root / "release/quality/H-research-1k/parser_health.json")

    if gate.get("automatic_gate_pass") is not False:
        raise RuntimeError(f"source is not a rejected research gate: {gate}")
    if gate.get("automatic_failures") != ["shortcut_risk"]:
        raise RuntimeError(f"unexpected automatic failure set: {gate.get('automatic_failures')}")
    if gate.get("manual_review_flags") != []:
        raise RuntimeError(f"manual review flags are unresolved: {gate.get('manual_review_flags')}")
    if shortcut.get("shortcut_risk") is not True:
        raise RuntimeError("negative finalizer requires shortcut_risk=true")
    if int(capture.get("sessions", 0)) != 1000:
        raise RuntimeError(f"expected 1000 captured sessions: {capture}")
    if capture.get("full_capture_retained") is not True:
        raise RuntimeError(f"full Bronze capture was not retained: {capture}")
    if leakage.get("ok") is not True:
        raise RuntimeError(f"leakage gate is not green: {leakage}")
    if production.get("production_source") != "suricata_eve_flow":
        raise RuntimeError(f"wrong production source: {production}")
    if production.get("train_serve_feature_code") != "adminlab.online_features.EveFeatureState":
        raise RuntimeError(f"wrong train/serve feature code: {production}")
    if float(production.get("uid_alignment_coverage", 0.0)) != 1.0:
        raise RuntimeError(f"UID alignment is incomplete: {production}")
    if float(production.get("session_mapping_coverage", 0.0)) < 0.95:
        raise RuntimeError(f"session mapping coverage is below gate: {production}")
    if float(production.get("flow_mapping_coverage", 0.0)) < 0.90:
        raise RuntimeError(f"flow mapping coverage is below gate: {production}")
    if any(float(value) < 0.90 for value in production.get("session_mapping_coverage_by_protocol", {}).values()):
        raise RuntimeError(f"per-protocol mapping coverage is below gate: {production}")
    if int(parser.get("suricata_flow_events", 0)) <= 0 or int(parser.get("zeek_conn_lines", 0)) <= 0:
        raise RuntimeError(f"parser evidence is incomplete: {parser}")

    required_reasons = {
        "temporal_future",
        "unseen_client_implementation",
        "unseen_host_pair",
        "unseen_persona",
    }
    observed_reasons = set(map(str, gate.get("challenge_reasons", [])))
    if not required_reasons <= observed_reasons:
        raise RuntimeError(f"required challenge slices missing: {required_reasons - observed_reasons}")

    val = m1["splits"]["validation"]
    test = m1["splits"]["test"]
    challenge = m1["splits"]["challenge"]
    for name, split in (("validation", val), ("test", test), ("challenge", challenge)):
        if float(split["pr_auc"]) >= 0.70:
            raise RuntimeError(f"{name} PR-AUC no longer supports the recorded rejection: {split}")
    if float(curve["last_delta_pr_auc"]) > 0.005:
        raise RuntimeError(f"learning curve supports scale; STOP_AT_1K would be invalid: {curve}")
    if curve.get("scale_recommendation") == "expand":
        raise RuntimeError(f"learning curve explicitly recommends expansion: {curve}")

    nuisance = {
        name: item
        for name, item in shortcut.get("baselines", {}).items()
        if item.get("status") == "ok" and item.get("pr_auc") is not None
    }
    if not nuisance:
        raise RuntimeError("no nuisance baselines available")
    best_name, best_item = max(nuisance.items(), key=lambda item: float(item[1]["pr_auc"]))
    if float(best_item["pr_auc"]) <= float(shortcut["full_model_pr_auc"]):
        raise RuntimeError("full model now exceeds all nuisance baselines; rejection reason is stale")

    challenge_campaign = slices.get("splits", {}).get("challenge", {}).get("campaign_detection", {})
    report: dict[str, Any] = {
        "schema_version": 1,
        "research_status": "REJECTED_MODEL_QUALITY",
        "pipeline_status": "VALIDATED_END_TO_END",
        "source_run_id": source_run_id,
        "source_run_url": f"https://github.com/MakSoS1/analytics_test/actions/runs/{source_run_id}",
        "source_artifact_id": source_artifact_id,
        "source_artifact_name": source_artifact_name,
        "source_artifact_digest": source_artifact_digest,
        "sessions": 1000,
        "scale_decision": "STOP_AT_1K",
        "allow_scale": False,
        "model_promotion": "NONE",
        "ngfw_posture": {
            "suricata_rules": "visibility_and_audit_only",
            "M1_lightgbm": "shadow_research_only_not_enforcement",
            "M2_isolation_forest": "shadow_research_only_not_enforcement",
        },
        "reason": (
            "quality gate correctly rejected the model because nuisance-only baselines "
            "outperform full M1 and the grouped learning curve does not improve at full data"
        ),
        "automatic_failures": gate["automatic_failures"],
        "manual_review_flags": gate.get("manual_review_flags", []),
        "best_nuisance_baseline": {"name": best_name, **best_item},
        "production_gold": production,
        "leakage": leakage,
        "capture_health": capture,
        "parser_health": parser,
        "M0": m0,
        "M1": m1,
        "M2": m2,
        "shortcut_audit": shortcut,
        "hard_benign": hard,
        "learning_curve": curve,
        "challenge_campaign_detection": challenge_campaign,
        "reference_validation_status": gate.get("reference_validation_status"),
        "reference_available": gate.get("reference_available"),
    }
    write_json(artifact_root / "NEGATIVE_RESEARCH_VERIFIED.json", report)
    return report


def persist_to_hf(
    artifact_root: Path,
    *,
    token: str,
    repo_id: str,
    remote_root: str,
    source_run_id: int,
    source_artifact_id: int,
) -> dict[str, Any]:
    if not token:
        raise RuntimeError("HF_TOKEN is required for final V1 quarantine persistence")
    api = HfApi(token=token)
    api.create_repo(repo_id=repo_id, repo_type="dataset", private=True, exist_ok=True)
    info = api.repo_info(repo_id=repo_id, repo_type="dataset")
    if getattr(info, "private", None) is not True:
        raise RuntimeError(f"refusing to upload rejected research to non-private HF dataset: {repo_id}")

    uploads = (
        (artifact_root / "release", f"{remote_root}/release", "recoverable release"),
        (artifact_root / "models", f"{remote_root}/models", "models"),
        (artifact_root / "evaluation", f"{remote_root}/evaluation", "evaluation"),
    )
    for local, remote, label in uploads:
        api.upload_folder(
            repo_id=repo_id,
            repo_type="dataset",
            folder_path=str(local),
            path_in_repo=remote,
            commit_message=f"quarantine rejected remote-admin research {source_run_id}: {label}",
        )
    for filename in ("RESEARCH_GATE.json", "NEGATIVE_RESEARCH_VERIFIED.json"):
        api.upload_file(
            repo_id=repo_id,
            repo_type="dataset",
            path_or_fileobj=str(artifact_root / filename),
            path_in_repo=f"{remote_root}/{filename}",
            commit_message=f"quarantine rejected remote-admin research {source_run_id}: {filename}",
        )

    files = set(api.list_repo_files(repo_id=repo_id, repo_type="dataset"))
    required = {
        f"{remote_root}/release/bronze/H-research-1k/captures/H-research-1k.pcap.zst",
        f"{remote_root}/release/silver/H-research-1k/suricata/eve.json.zst",
        f"{remote_root}/release/silver/H-research-1k/zeek/conn.log.zst",
        f"{remote_root}/release/gold/H-research-1k/production_model_matrix.parquet",
        f"{remote_root}/models/M1-lightgbm.metrics.json",
        f"{remote_root}/evaluation/M1-slices.json",
        f"{remote_root}/NEGATIVE_RESEARCH_VERIFIED.json",
    }
    missing = sorted(required - files)
    if missing:
        raise RuntimeError(f"HF quarantine verification failed, missing files: {missing}")
    status = {
        "status": "UPLOADED_AND_VERIFIED_QUARANTINE",
        "repo_id": repo_id,
        "private_verified": True,
        "path": remote_root,
        "source_run_id": source_run_id,
        "source_artifact_id": source_artifact_id,
        "required_files_verified": sorted(required),
        "promoted": False,
    }
    write_json(artifact_root / "HF_NEGATIVE_PERSISTENCE.json", status)
    return status


def generate_repo_evidence(report: dict[str, Any], hf: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    report = dict(report)
    report["hf_persistence"] = hf
    write_json(out_dir / "RESULTS_NEGATIVE_AUTOGENERATED.json", report)

    m1 = report["M1"]
    shortcut = report["shortcut_audit"]
    hard = report["hard_benign"]
    curve = report["learning_curve"]
    val = m1["splits"]["validation"]
    test = m1["splits"]["test"]
    challenge = m1["splits"]["challenge"]
    strict = val["strict_operating_points"]["operating_points"]
    campaign = report.get("challenge_campaign_detection", {})
    best = report["best_nuisance_baseline"]

    scale = {
        "allow_scale": False,
        "next_sessions": 0,
        "decision": "STOP_AT_1K",
        "reason": "MODEL_QUALITY_REJECTED_AND_LEARNING_CURVE_SATURATED",
        "source_run_id": report["source_run_id"],
        "automatic_failures": report["automatic_failures"],
        "validation_pr_auc": val["pr_auc"],
        "test_pr_auc": test["pr_auc"],
        "challenge_pr_auc": challenge["pr_auc"],
        "last_delta_pr_auc": curve["last_delta_pr_auc"],
        "scale_recommendation": curve["scale_recommendation"],
        "policy": (
            "4k/10k/20k/40k fan-out is prohibited until a materially different "
            "feature/data hypothesis passes a new 1k gate; more rows of the same "
            "distribution are not justified"
        ),
    }
    write_json(out_dir / "SCALE_DECISION_NEGATIVE.json", scale)
    write_json(out_dir / "HF_NEGATIVE_PERSISTENCE.json", hf)

    lines = [
        "# Remote Admin Anomaly V1 — Evidence-verified negative research result",
        "",
        "This is a **validated negative result**, not a failed pipeline and not a promoted detector.",
        "",
        f"- Source GitHub Actions run: `{report['source_run_id']}`",
        f"- Retained artifact: `{report['source_artifact_name']}` (ID `{report['source_artifact_id']}`)",
        f"- Artifact digest: `{report['source_artifact_digest']}`",
        f"- Real-wire behavioral sessions: **{report['sessions']}** (1000/1000 successful)",
        "- Pipeline: **VALIDATED_END_TO_END** — Bronze PCAP, Suricata/Zeek Silver, production-compatible Gold, grouped splits, leakage checks, M0/M1/M2 and evaluation all completed.",
        f"- Research quality decision: **REJECTED_MODEL_QUALITY** (`{report['automatic_failures']}`)",
        "- Scale decision: **STOP_AT_1K** — 4k/10k/20k/40k are intentionally blocked.",
        "- Model promotion: **NONE**.",
        "",
        "## M1 LightGBM",
        "",
        f"- Validation PR-AUC: **{float(val['pr_auc']):.6f}**, ROC-AUC: **{float(val['roc_auc']):.6f}**",
        f"- Test PR-AUC: **{float(test['pr_auc']):.6f}**, ROC-AUC: **{float(test['roc_auc']):.6f}**",
        f"- Challenge PR-AUC: **{float(challenge['pr_auc']):.6f}**, ROC-AUC: **{float(challenge['roc_auc']):.6f}**",
        f"- Validation primary FPR: **{float(val['fpr']):.6f}**",
        f"- Recall @ FPR <=1%: **{float(strict['fpr_1pct']['recall']):.6f}**",
        f"- Recall @ FPR <=0.1%: **{float(strict['fpr_0_1pct']['recall']):.6f}**",
        f"- Challenge campaign recall: **{campaign.get('campaign_recall')}**",
        "",
        "## Why the model is rejected",
        "",
        f"The strongest nuisance-only validation baseline is `{best['name']}` with PR-AUC **{float(best['pr_auc']):.6f}**, versus full M1 **{float(shortcut['full_model_pr_auc']):.6f}**. The full model therefore does not demonstrate a robust multivariate anomaly signal and the shortcut gate correctly remains red.",
        "",
        f"Grouped learning curve ends at delta PR-AUC **{float(curve['last_delta_pr_auc']):.6f}** with recommendation `{curve['scale_recommendation']}`. More rows from the same generator distribution are not supported by evidence.",
        "",
        f"Hard-benign FPR is **{float(hard['fpr']):.6f}** ({hard['false_positives']}/{hard['n']}), so false positives alone are not the blocker; the blocker is extremely poor recall/generalization.",
        "",
        "## Storage",
        "",
        "- GitHub Actions artifact retained for 90 days; full Bronze PCAP and raw Silver remain recoverable.",
        f"- Private Hugging Face quarantine: `{hf['repo_id']}/{hf['path']}` — status **{hf['status']}**.",
        "- This quarantine path is **not** a promoted/validated production dataset path.",
        "",
        "## Deployment posture",
        "",
        "- Suricata deterministic remote-admin rules: visibility/audit telemetry only.",
        "- M1 LightGBM: shadow/research only; **must not enforce/block**.",
        "- M2 Isolation Forest: shadow/research only; **must not enforce/block**.",
        "- No model promotion occurs from this V1 research result.",
        "",
    ]
    (out_dir / "RESULTS_NEGATIVE_AUTOGENERATED.md").write_text("\n".join(lines), encoding="utf-8")

    scale_lines = [
        "# Remote Admin Anomaly V1 — Scale Decision",
        "",
        "- Decision: **STOP_AT_1K**",
        "- Allow scale: **false**",
        "- Next sessions: **0**",
        f"- Reason: `{scale['reason']}`",
        f"- Validation PR-AUC: `{scale['validation_pr_auc']}`",
        f"- Test PR-AUC: `{scale['test_pr_auc']}`",
        f"- Challenge PR-AUC: `{scale['challenge_pr_auc']}`",
        f"- Last grouped learning-curve delta PR-AUC: `{scale['last_delta_pr_auc']}`",
        f"- Recommendation: `{scale['scale_recommendation']}`",
        "",
        "The next experiment must change the **feature/data hypothesis**, not merely multiply rows from the same generator distribution.",
        "",
    ]
    (out_dir / "SCALE_DECISION_NEGATIVE.md").write_text("\n".join(scale_lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--repo-output", type=Path, required=True)
    parser.add_argument("--source-run-id", type=int, required=True)
    parser.add_argument("--source-artifact-id", type=int, required=True)
    parser.add_argument("--source-artifact-name", required=True)
    parser.add_argument("--source-artifact-digest", required=True)
    parser.add_argument("--hf-repo", required=True)
    parser.add_argument("--hf-path", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.artifact_root.resolve()
    report = verify_negative_research(
        root,
        source_run_id=args.source_run_id,
        source_artifact_id=args.source_artifact_id,
        source_artifact_name=args.source_artifact_name,
        source_artifact_digest=args.source_artifact_digest,
    )
    hf = persist_to_hf(
        root,
        token=os.environ.get("HF_TOKEN", ""),
        repo_id=args.hf_repo,
        remote_root=args.hf_path,
        source_run_id=args.source_run_id,
        source_artifact_id=args.source_artifact_id,
    )
    generate_repo_evidence(report, hf, args.repo_output.resolve())
    print(
        json.dumps(
            {
                "research_status": report["research_status"],
                "pipeline_status": report["pipeline_status"],
                "scale_decision": report["scale_decision"],
                "hf_status": hf["status"],
                "source_run_id": report["source_run_id"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
