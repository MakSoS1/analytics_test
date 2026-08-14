# Remote Admin Anomaly Lab V1 — Living Plan and Results

**Branch:** `remote-admin-anomaly-lab-v1`  
**Started:** 2026-08-14  
**V1 research closed:** 2026-08-14  
**Final V1 decision:** `STOP_AT_1K` / `REJECTED_MODEL_QUALITY` / no model promotion  
**Design spec:** `docs/superpowers/specs/2026-08-14-remote-admin-anomaly-lab-v1-design.md`  
**Implementation plan:** `docs/superpowers/plans/2026-08-14-remote-admin-anomaly-lab-v1.md`

## Rules for this tracker

- A checkbox is marked complete only after test/workflow evidence exists.
- A completed research milestone does **not** imply that its model hypothesis passed.
- Record run IDs, counts, parser coverage, sizes and storage locations as evidence becomes available.
- Never publish PCAP as GitHub Release assets.
- Bronze full PCAP is the rollback source of truth.
- Suricata alerts are detector output/telemetry, never ground-truth labels.
- A red scientific quality gate is preserved when the evidence rejects promotion; it is not weakened to obtain a green workflow.

## Final V1 status

The lab/data pipeline is validated end to end, but the V1 flow-model hypothesis is rejected.

- Final research source: run `31818445960`.
- Retained Actions artifact: `remote-admin-research-gate-v2-31818445960`, Artifact ID `9226887886`.
- Artifact size: `718,832,312` B.
- Artifact digest: `sha256:40a463b9f16d4251d3b40b8915ef7a7425a883edd2916484acab660328fbbf72`.
- Finalizer: run `31821404669` — GREEN.
- Finalizer contract evidence: run `31821362433` — GREEN.
- Private HF quarantine: `Maksim123321/remote-admin-anomaly-v1/quarantine/rejected/gh-31818445960`.
- HF status: `UPLOADED_AND_VERIFIED_QUARANTINE`; the path is deliberately **not promoted**.
- Scale: `STOP_AT_1K`, `allow_scale=false`, `next_sessions=0`.
- Model promotion: `NONE`.

## Milestones

- [x] **M0 — design and safety boundary fixed.**
  - Isolated namespace lab; no endpoint default route/NAT.
  - No malware/C2 framework payload execution in V1.
  - Sliver/Mythic/Havoc/Cobalt Strike/Metasploit-style traffic deliberately excluded from V1.

- [x] **M1 — configuration/schema contracts pass.**
  - Initial evidence run `31787756618`.
  - Final contract after all corrections: run `31817735933` — GREEN.
  - `SessionRecord` includes `server_stack` and `implementation_id`; serialization is covered by tests.

- [x] **M2 — digital-twin planner and ground truth pass.**
  - Initial planner evidence run `31787949680`.
  - Final planner audit run `31817778803` — GREEN.
  - Exact 1k plan: 500 benign / 500 suspicious; SSH/SMB/RDP/VNC = 250 each; every protocol spans all 45 simulated days.
  - Challenge share reduced from the earlier distorted 53.8% to 34.0% by enforcing strict holdout impact budgets.

- [x] **M3 — namespace topology isolation passes.**
  - Evidence run `31788233293`.
  - 15 namespaces; internal connectivity PASS; external/default-route isolation PASS.

- [x] **M4 — core real SSH/SMB wire smoke passes.**
  - Evidence run `31788947200`: 40/40 real sessions; SSH 25 / SMB 15.

- [x] **M5 — recoverable Bronze PCAP/manifests/checksums pass.**
  - Initial accepted Bronze run `31789649604`.
  - Final research run `31818445960`: 1000/1000 successful behavioral sessions and full compressed Bronze PCAP retained.
  - Final research `pcap.zst`: `227,883,905` B.
  - Capture is never deleted merely because features/models were built.

- [x] **M6 — Suricata + Zeek Silver passes.**
  - Initial Silver evidence run `31790538926`.
  - Final research: 14,925 Suricata EVE lines, 2,705 Zeek conn records.
  - Raw/background traffic remains in Silver even when it is ineligible for direct flow-to-session mapping.

- [x] **M7 — V1 fidelity matrix finalized.**
  - SSH: real OpenSSH wire.
  - SMB: real smbclient/Samba plus real alternate smbprotocol client.
  - RDP: real FreeRDP -> xrdp wire, validated in current V4/implementation gates.
  - VNC: real RFB client -> TigerVNC wire, validated in current V4/implementation gates.
  - Updated V4 evidence: run `31817920754` — GREEN.
  - Updated alternative-client evidence: run `31817953836` — GREEN; Paramiko and smbprotocol observed on wire.
  - Native Windows DCOM/DCE-RPC and native Windows WinRM are **not claimed as solved**. Linux/Samba or bounded WS-Man fixtures are partial semantics only and stay outside promoted V1 training claims.

- [x] **M8 — production-compatible Gold, grouped splits and leakage audit pass.**
  - Suricata normalization uses `flow.start` for offline flow timing where available.
  - Nullable EVE handling is aligned offline/online.
  - Production feature implementation: `adminlab.online_features.EveFeatureState`.
  - Held-out evaluation uses causal prior-train reference context rather than an artificial empty state.
  - Final Gold rows: 2,263 parser-observed flows.
  - Suricata raw flows: 2,705; eligible: 2,271; mapped: 2,263; background: 434.
  - Flow mapping coverage: `0.9964773`.
  - Session mapping coverage: `0.993`.
  - Per-protocol session mapping: RDP `1.0`, SMB `1.0`, SSH `0.972`, VNC `1.0`.
  - UID alignment: `1.0`.
  - Leakage audit: PASS.

- [x] **M9 — persistence/recovery path verified.**
  - GitHub Actions artifact is retained first for 90 days.
  - Negative research release uploaded to private HF quarantine by finalizer `31821404669`.
  - Verified HF files include Bronze `pcap.zst`, Suricata EVE, Zeek conn, Gold model matrix, M1 metrics and challenge evaluation.
  - GitHub Release PCAP assets are never used.

- [x] **M10 — staged fan-out gate executed and terminated by evidence.**
  - Research scale gate completed at 1,000 sessions.
  - 4k/10k/20k/40k fan-out was intentionally **not** launched because grouped learning-curve evidence rejects scaling the same generator/model hypothesis.
  - Final decision file: `SCALE_DECISION_NEGATIVE.json`.

- [x] **M11 — M0/M1/M2 trained and evaluated; model hypothesis rejected.**
  - M1 validation PR-AUC `0.5074707204`, ROC-AUC `0.4480471079`.
  - M1 test PR-AUC `0.5137590769`, ROC-AUC `0.4605629446`.
  - M1 challenge PR-AUC `0.4222839299`, ROC-AUC `0.4989922318`.
  - Challenge campaign recall at the primary operating point: `0.0`.
  - Hard-benign FPR: `0.0033613445` (2 FP / 595 hard-benign flows).
  - Nuisance-only baselines outperform full M1; `shortcut_risk` correctly remains the automatic rejection reason.
  - Learning curve: last delta PR-AUC `-0.0138075260`; recommendation `prefer_diversity_or_holdout_analysis`.
  - Scientific conclusion: more rows from the same distribution are not justified.

- [x] **M12 — NGFW/storage/rebuild posture documented.**
  - No V1 ML model is promoted to enforcement.
  - Suricata deterministic T1021-family rules remain visibility/audit telemetry, not labels and not proof of maliciousness.
  - M1 LightGBM and M2 Isolation Forest remain shadow/research-only.
  - `docs/NGFW_INTEGRATION.md`, `docs/FIDELITY_MATRIX.md`, this PLAN and the autogenerated negative-result files are the final V1 deployment/research contract.

## Final storage contract

Primary recoverable private path:

```text
Maksim123321/remote-admin-anomaly-v1/
└── quarantine/rejected/gh-31818445960/
    ├── NEGATIVE_RESEARCH_VERIFIED.json
    ├── RESEARCH_GATE.json
    ├── release/
    │   ├── bronze/H-research-1k/
    │   │   ├── captures/H-research-1k.pcap.zst
    │   │   ├── manifests/
    │   │   ├── reproducibility.json
    │   │   └── checksums.sha256
    │   ├── silver/H-research-1k/
    │   │   ├── suricata/eve.json.zst
    │   │   ├── suricata-rules/eve.json.zst
    │   │   ├── zeek/*.log.zst
    │   │   └── parser_versions.json
    │   ├── gold/H-research-1k/
    │   │   ├── production_flow_features.parquet
    │   │   ├── production_flow_labels.parquet
    │   │   ├── production_model_matrix.parquet
    │   │   └── production_splits.parquet
    │   └── quality/H-research-1k/
    ├── models/
    └── evaluation/
```

Fallback/reproducibility copy:

- GitHub Actions run `31818445960`.
- Artifact `remote-admin-research-gate-v2-31818445960`, ID `9226887886`.
- Retention: 90 days from the research run.
- Digest: `sha256:40a463b9f16d4251d3b40b8915ef7a7425a883edd2916484acab660328fbbf72`.

The HF location is a **quarantine/rejected** research path. It is a durable rollback/source corpus, not an assertion that the detector is production-ready.

## Accepted challenge/evaluation design

Final 1k challenge reasons at session level:

- `temporal_future`: 101 sessions.
- `unseen_client_implementation`: 187 sessions.
- `unseen_host_pair`: 46 sessions.
- `unseen_persona`: 38 sessions.
- `unseen_src_host`: skipped because every whole-host candidate exceeded the declared 8% group-impact budget; the splitter now fails closed instead of distorting the benchmark.

Generic session splits after explicit challenge holdouts:

- train: 463 sessions;
- validation: 97 sessions;
- test: 100 sessions;
- challenge: 340 sessions.

Counterfactual pairs/campaign groups remain indivisible across splits. Evaluation metadata and implementation/persona/host identifiers remain forbidden from production model features.

## Final research decision

`REJECTED_MODEL_QUALITY` does **not** mean the data pipeline failed. The full pipeline reached real wire, Bronze, Silver, Gold, model training and challenge evaluation successfully. The rejection is the scientific result:

1. M1 generalization is approximately chance-level under proper grouped/held-out evaluation.
2. Simple nuisance families (`rate`, `time`, `duration`, `bytes`, `port/protocol`) are at least as predictive as, and often more predictive than, full M1 on validation.
3. Primary-threshold recall on the challenge cohort is effectively zero.
4. Grouped learning curve does not improve at 100% of the 1k corpus.
5. Therefore multiplying the same synthetic-real lab distribution to 4k/10k would spend compute/storage without evidence of expected model improvement.

A V2 may reopen research only with a materially different hypothesis, for example richer longitudinal/user-policy context, endpoint/identity context available to the intended product, additional truly independent network environments, native Windows fidelity cohorts, or external real/reference data. A V2 must pass a new 1k gate before any larger fan-out.

## Known external limitations retained honestly

- Native Windows DCOM/DCE-RPC and native Windows WinRM fidelity are not provided by the Linux namespace lab.
- No independent external/reference corpus was available in the final V1 run; reference validation remains unavailable rather than fabricated.
- GitHub-hosted runners are not a substitute for independent organizations/ASNs/OS estates; environment shift remains an external validation requirement.
- V1 intentionally excludes advanced C2 frameworks to avoid learning framework fingerprints instead of remote-admin behavior.
