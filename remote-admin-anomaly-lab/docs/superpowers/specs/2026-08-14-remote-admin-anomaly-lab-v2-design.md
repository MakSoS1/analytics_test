# Remote Admin Anomaly Lab V2 — Mixed-Environment Dataset Design

**Date:** 2026-08-14  
**Branch:** `remote-admin-anomaly-lab-v2`  
**Baseline:** V1 final head `07262068b9ad26bda4a147d043a5d444befb7591`  
**V1 result:** validated data/pipeline, model hypothesis rejected (`STOP_AT_1K`).

## 1. Purpose

V2 is not a larger copy of V1. Its purpose is to test a materially different data and representation hypothesis:

> Remote-administration intent is weakly identifiable at isolated-flow level, but becomes learnable when the corpus contains harder counterfactual behavior, independent implementation/environment holdouts, and causal session/campaign history.

V1 remains immutable baseline evidence. V2 must preserve V1 rollback/reproducibility standards while adding:

1. a native-Windows cohort where GitHub-hosted Windows can produce genuine Windows network-stack traffic;
2. an independent operational reference slice from a public enterprise dataset;
3. much richer benign/suspicious counterfactual scenario semantics;
4. session-level and campaign/window-level Gold in addition to flow Gold;
5. environment and implementation holdouts that are never used for feature selection or threshold tuning;
6. a fail-closed V2 1k research gate that alone may authorize 4k scaling.

## 2. Non-goals

V2 does **not**:

- manufacture 4k/10k/201k rows before the 1k research gate passes;
- promote C2-framework fingerprints into training labels;
- claim native Windows RDP/DCOM/WinRM fidelity when the runner did not actually produce corresponding wire evidence;
- treat Suricata alerts, service names, scenario IDs, implementation IDs, runner OS, generator settings or campaign labels as model inputs;
- use future events to compute historical features;
- silently mix LANL/reference telemetry into the synthetic training distribution;
- require EDR-only process telemetry for the primary NGFW-compatible model.

## 3. Chosen architecture

Three data environments are kept distinct until evaluation:

```text
Environment A — Linux behavioral lab (train/validation/test)
  OpenSSH + Paramiko
  Samba smbclient + smbprotocol
  FreeRDP -> xrdp
  RFB client -> TigerVNC
  richer counterfactual session/campaign sequences
             |
             v
       Bronze / Silver
             |
             v
flow_gold -> session_gold -> campaign_gold
             |
             +--------------------------+
                                        |
Environment B — GitHub Windows native-stack holdout
  Windows OpenSSH client/server
  Windows SMB server/client (explicit temporary share + IPC where observable)
  WinRM / PowerShell Remoting
  DCOM/WMI probe over the Windows RPC stack
  mstsc/RDP attempted as a real fidelity probe; no synthetic fallback
             |
             v
   windows Bronze + metadata
             |
             v
   Linux parser merge/evaluation only
                                        |
Environment C — independent public reference
  LANL Unified Host and Network Dataset (2017)
  bounded network-flow + Windows-logon slice
  never used to train or tune thresholds
             |
             v
  external benign/reference evaluation
```

Environment B and C are external holdouts by policy. Environment A is the only source allowed to fit the primary V2 model during the 1k gate.

## 4. Why this architecture

### Rejected approach A: scale the V1 generator

Cheap and easy, but V1 already showed a saturated/negative learning curve and nuisance-only baselines competitive with the full model. More rows from the same distribution would not test a new hypothesis.

### Rejected approach B: Windows-only V2

Improves fidelity but does not solve the isolated-flow representation problem and is constrained by hosted-runner topology. It is useful as a holdout, not as the sole corpus.

### Chosen approach C: mixed environment + hierarchical representation

It attacks both demonstrated V1 failure modes: generator/environment dependence and insufficient temporal/relational representation. It also keeps an explicit external holdout so improvement cannot be claimed solely from in-lab validation.

## 5. V2 release layout

```text
remote-admin-anomaly-v2/<run-id>/
├── baseline/
│   └── v1_reference.json
├── release/
│   ├── bronze/
│   │   ├── linux-v2-1k/
│   │   └── windows-native/
│   ├── silver/
│   │   ├── linux-v2-1k/
│   │   └── windows-native/
│   ├── gold/
│   │   ├── linux-v2-1k/
│   │   │   ├── flow_features.parquet
│   │   │   ├── flow_labels.parquet
│   │   │   ├── session_features.parquet
│   │   │   ├── session_labels.parquet
│   │   │   ├── campaign_features.parquet
│   │   │   └── campaign_labels.parquet
│   │   └── windows-native/
│   └── quality/
│       ├── capture_health.json
│       ├── parser_health.json
│       ├── mapping_health.json
│       ├── leakage_checks.json
│       ├── causal_history_checks.json
│       └── windows_fidelity.json
├── external/
│   └── lanl-2017/
│       ├── source_manifest.json
│       ├── remote_admin_flows.parquet
│       ├── network_logons.parquet
│       └── reference_quality.json
├── models/
│   ├── flow-baseline/
│   ├── session-primary/
│   └── campaign-primary/
├── evaluation/
│   ├── internal_grouped.json
│   ├── windows_holdout.json
│   ├── lanl_reference.json
│   ├── hard_benign.json
│   ├── shortcut_audit.json
│   └── learning_curve.json
└── V2_RESEARCH_GATE.json
```

A failed research gate is persisted under a private Hugging Face quarantine path; a passing gate may be copied to a candidate path but is still not an enforcement model release.

## 6. Environment A — richer behavioral corpus

The Linux lab keeps the V1 wire implementations because they are already reproducible, but the scenario distribution changes materially.

### Benign families

At minimum:

- routine interactive administration;
- scheduled deployment/patching fan-out;
- backup and bulk-copy bursts;
- helpdesk troubleshooting;
- incident-response surge;
- new-server provisioning;
- first-day/new-admin behavior;
- service-account automation;
- jump-host style multi-target work;
- off-hours emergency administration;
- approved mass diagnostics;
- first-seen target/protocol events that are nevertheless benign.

### Suspicious families

At minimum:

- low-and-slow lateral movement;
- sudden fan-out from a normally narrow source;
- rare/new source→destination pair;
- new protocol for a source;
- protocol switching across SSH/SMB/RDP/VNC;
- failed-attempt → successful-session sequence;
- target chaining across multiple hosts;
- credential-like hopping sequence represented only through network-visible session outcomes;
- staged small-copy then remote-admin sequence;
- off-hours behavior matched to benign bytes/duration/rates.

### Counterfactual rule

For important suspicious scenarios, generate a benign counterpart with deliberately overlapping packet-level nuisance variables (duration, bytes, packet count, rate, hour, protocol). The class difference must come from historical/relational sequence semantics rather than an easy single-flow control.

## 7. Environment B — native Windows cohort

The Windows workflow runs on an explicit GitHub Windows image and records runner image metadata.

### Required behavior

The workflow must attempt genuine Windows-stack traffic for:

- OpenSSH;
- SMB using a temporary explicitly-created share and standard Windows client commands;
- WinRM/PowerShell Remoting;
- DCOM/WMI over RPC where the runner permits remote-style loopback communication;
- RDP using `mstsc`/TermService only if a real session/handshake can be proven.

Traffic capture uses Windows-native packet capture (`pktmon`) and converts retained capture to PCAPNG/PCAP for offline parsing on Linux. Every protocol result records:

```text
service_present
tool_present
wire_observed
session_completed
source_stack
target_stack
runner_image
fidelity_status
failure_reason
```

A protocol is `native_windows_validated` only if wire evidence and a completed bounded operation are both present. Tool presence alone never upgrades fidelity. If RDP self-connection cannot be completed on a hosted runner, the result is `unavailable_hosted_runner` and V2 retains the existing FreeRDP→xrdp RDP train path rather than inventing a native sample.

### Holdout policy

All Windows-native rows are `external_environment` challenge rows. They are never used for training, feature-family selection or threshold tuning in the 1k gate.

## 8. Environment C — independent reference corpus

V2 uses a bounded slice of the **Los Alamos National Laboratory Unified Host and Network Data Set (2017)** as independent operational reference data. The source contains de-identified enterprise network flows and Windows host logon events with identities aligned across telemetry. Well-known network ports are preserved. The LANL source is public-release research data and is kept as a separate external subtree.

The V2 fetcher must:

1. record the exact source URL, date, checksum/size and citation metadata;
2. use a bounded day/slice so CI remains practical;
3. filter network candidates to remote-administration-relevant well-known ports where available (SSH 22, SMB 445, RDP 3389, WinRM 5985/5986, RPC endpoint mapper 135);
4. separately retain Windows network-logon events (for example logon type `Network` / relevant authentication events) as reference context;
5. never assign synthetic suspicious labels to unlabeled operational events;
6. report reference FPR/score distribution separately from supervised internal metrics.

If the public source is temporarily inaccessible, the V2 research gate fails external-reference completeness rather than silently substituting synthetic data.

## 9. Hierarchical Gold

### 9.1 Flow Gold

Flow Gold remains a parser-observed, NGFW-compatible baseline using only features derivable from Suricata/Zeek-visible traffic and prior state. It exists to compare directly against V1.

### 9.2 Session Gold — primary V2 unit

Flows mapped to one behavioral session are aggregated after parsing. Example model-visible features:

- flow count and session duration;
- total/median/max bytes and packets by direction;
- connection attempt count;
- protocol/port composition and transition indicators;
- failed-like attempt count when inferable from network/session result metadata available at inference integration;
- unique targets within source history windows;
- pair frequency before session start;
- source protocol diversity before session start;
- new-destination/new-protocol indicators;
- prior 1m/5m/15m/1h session counts;
- prior 1h/24h fan-out;
- prior source→target recency;
- hour/day cyclic encodings;
- causal graph degree/novel-edge features.

Forbidden inputs remain: label, scenario/campaign IDs, implementation ID, environment ID, generator controls, semantic family names and future observations.

### 9.3 Campaign/window Gold

Campaign/window rows represent a bounded source-centric window or orchestrated sequence, but features are computed from observed sessions, not campaign labels. Example features:

- number of sessions/targets/protocols;
- fan-out slope;
- new-target ratio;
- protocol-transition count/entropy;
- failed→success-like transition count where observable;
- target-chain length;
- inter-session timing statistics;
- low-and-slow periodicity/burstiness;
- fraction of pairs unseen before the window;
- source baseline deviation using only prior windows.

Campaign labels are used only as ground truth/evaluation grouping.

## 10. Causality and state

All history features are computed in event-time order. Validation, test and challenge rows may receive reference history only from events that occurred strictly earlier in simulated/observed time. The feature builder must support explicit warm-state replay from allowed prior rows.

Tests must prove that adding future rows cannot change an earlier row's features.

## 11. Split policy

Environment A uses grouped, campaign-safe splits with explicit challenge reasons including:

- temporal future;
- unseen persona;
- unseen host pair;
- unseen client implementation;
- unseen campaign family when feasible.

Windows-native and LANL are not randomly split: they are external holdouts.

The V2 split planner must keep train/validation/test sufficiently populated while challenge impact budgets remain bounded. It must not force a whole-host holdout that consumes an excessive fraction of the corpus merely to satisfy a checkbox.

## 12. Models and evaluation

V2 trains/evaluates three supervised views using the same grouped policy:

1. `flow-baseline` — direct V1-comparable LightGBM;
2. `session-primary` — primary LightGBM candidate;
3. `campaign-primary` — campaign/window LightGBM candidate.

M2 benign-only anomaly scoring may remain a shadow expert.

Required reports:

- PR-AUC / ROC-AUC / precision / recall / F1;
- Recall at <=1% and <=0.1% FPR where statistically supportable;
- hard-benign FPR;
- per-protocol and per-scenario-family slices;
- unseen implementation/persona/pair/temporal slices;
- campaign detection rate and time-to-detection;
- Windows-native holdout metrics where labels exist;
- LANL reference score/FPR distribution;
- nuisance-only shortcut baselines;
- grouped learning curve.

## 13. V2 1k acceptance gate

The gate is intentionally stricter than “model trained successfully”. A candidate 1k passes only if all engineering gates and the following research conditions hold:

### Engineering

- 1000/1000 Environment-A behavioral sessions successful;
- balanced labels within a narrow tolerance;
- all four core protocols represented across the simulated timeline;
- Bronze PCAP complete and checksum-valid;
- Suricata and Zeek non-empty;
- session mapping >= 0.98 overall and >= 0.95 per core protocol;
- train/serve and leakage checks PASS;
- session/campaign Gold non-empty with stable schema;
- at least four native-Windows protocol probes attempted and fidelity results retained;
- independent LANL reference slice present and verified.

### Research

Primary decision uses `session-primary`:

- grouped validation PR-AUC >= 0.65;
- grouped test PR-AUC >= 0.60;
- challenge campaign recall at the <=1% FPR operating point > 0;
- hard-benign FPR <= 0.05 at the selected research threshold;
- full session model validation PR-AUC exceeds the best nuisance-only baseline by >= 0.05;
- no automatic shortcut-risk flag;
- Windows-native holdout must produce a finite, non-degenerate score distribution and at least one successfully mapped native protocol family;
- LANL reference evaluation must complete without using LANL to tune the threshold.

These thresholds are research gates, not production deployment claims.

### Scale authorization

`allow_scale=true` only when the research gate passes **and** the grouped learning curve shows useful improvement at the full 1k point (`last_delta_pr_auc > 0.005`) or a documented diversity expansion is explicitly justified.

Otherwise V2 stops at 1k and records the failed hypothesis. A failure never triggers 4k/10k automatically.

## 14. CI/workflow design

V2 workflows are separate from V1. The obsolete V1 `remote-admin-research-gate.yml` is archived outside `.github/workflows/` on the V2 branch so it cannot create ambiguous red runs.

Planned V2 gates:

1. `remote-admin-v2-contract.yml` — fast TDD/static contracts;
2. `remote-admin-v2-planner-audit.yml` — no-wire scenario/split audit;
3. `remote-admin-v2-windows-native.yml` — Windows native-stack capture/fidelity probe;
4. `remote-admin-v2-reference.yml` — bounded LANL external-reference acquisition;
5. `remote-admin-v2-wire-smoke.yml` — small Environment-A end-to-end barrier;
6. `remote-admin-v2-research-1k.yml` — final 1k Environment-A capture + Gold + models, consuming verified Windows/reference artifacts;
7. `remote-admin-v2-finalizer.yml` — private HF persistence, candidate/quarantine decision and living-plan update.

## 15. Persistence

Preferred private Hugging Face repository remains `Maksim123321/remote-admin-anomaly-v1` for continuity, but V2 paths are isolated:

```text
v2/quarantine/<run-id>/...
v2/candidates/<run-id>/...
```

GitHub Actions artifact retention remains the first recovery copy. Complete Bronze captures are never stored as public GitHub Release assets.

## 16. Security and containment

All generated behavior remains bounded to ephemeral CI lab hosts/runners. No malware or C2 payload execution is required. Windows shares/remoting configuration is temporary and restored/removed in cleanup. No workflow opens an unauthenticated public listener to the Internet.

## 17. Definition of done

V2 dataset work is complete when:

- the V2 1k corpus and external holdouts are reproducibly persisted;
- flow/session/campaign Gold are all built from retained Bronze/Silver evidence;
- the Windows fidelity matrix states exactly what was and was not native/validated;
- LANL/reference source metadata and sample are preserved separately;
- the V2 research gate has a reproducible PASS or FAIL decision;
- a PASS is required before any 4k scale workflow can run;
- docs/NGFW integration describes session/campaign scoring as research/shadow until production false-positive evidence exists.

A scientifically valid FAIL at 1k is an acceptable final result; silently scaling a failed distribution is not.