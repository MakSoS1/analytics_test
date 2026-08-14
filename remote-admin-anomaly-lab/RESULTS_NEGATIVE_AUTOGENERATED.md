# Remote Admin Anomaly V1 — Evidence-verified negative research result

This is a **validated negative result**, not a failed pipeline and not a promoted detector.

- Source GitHub Actions run: `31818445960`
- Retained artifact: `remote-admin-research-gate-v2-31818445960` (ID `9226887886`)
- Artifact digest: `sha256:40a463b9f16d4251d3b40b8915ef7a7425a883edd2916484acab660328fbbf72`
- Real-wire behavioral sessions: **1000** (1000/1000 successful)
- Pipeline: **VALIDATED_END_TO_END** — Bronze PCAP, Suricata/Zeek Silver, production-compatible Gold, grouped splits, leakage checks, M0/M1/M2 and evaluation all completed.
- Research quality decision: **REJECTED_MODEL_QUALITY** (`['shortcut_risk']`)
- Scale decision: **STOP_AT_1K** — 4k/10k/20k/40k are intentionally blocked.
- Model promotion: **NONE**.

## M1 LightGBM

- Validation PR-AUC: **0.507471**, ROC-AUC: **0.448047**
- Test PR-AUC: **0.513759**, ROC-AUC: **0.460563**
- Challenge PR-AUC: **0.422284**, ROC-AUC: **0.498992**
- Validation primary FPR: **0.009615**
- Recall @ FPR <=1%: **0.015504**
- Recall @ FPR <=0.1%: **0.000000**
- Challenge campaign recall: **0.0**

## Why the model is rejected

The strongest nuisance-only validation baseline is `rate_only` with PR-AUC **0.673315**, versus full M1 **0.507471**. The full model therefore does not demonstrate a robust multivariate anomaly signal and the shortcut gate correctly remains red.

Grouped learning curve ends at delta PR-AUC **-0.013808** with recommendation `prefer_diversity_or_holdout_analysis`. More rows from the same generator distribution are not supported by evidence.

Hard-benign FPR is **0.003361** (2/595), so false positives alone are not the blocker; the blocker is extremely poor recall/generalization.

## Storage

- GitHub Actions artifact retained for 90 days; full Bronze PCAP and raw Silver remain recoverable.
- Private Hugging Face quarantine: `Maksim123321/remote-admin-anomaly-v1/quarantine/rejected/gh-31818445960` — status **UPLOADED_AND_VERIFIED_QUARANTINE**.
- This quarantine path is **not** a promoted/validated production dataset path.

## Deployment posture

- Suricata deterministic remote-admin rules: visibility/audit telemetry only.
- M1 LightGBM: shadow/research only; **must not enforce/block**.
- M2 Isolation Forest: shadow/research only; **must not enforce/block**.
- No model promotion occurs from this V1 research result.
