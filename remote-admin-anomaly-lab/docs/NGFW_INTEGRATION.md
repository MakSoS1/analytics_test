# Remote Admin Anomaly V1 — NGFW / Suricata Integration

## Final V1 decision

The V1 research pipeline is validated, but **no ML detector is promoted to enforcement or production alerting**.

Final evidence from research run `31818445960`:

- M1 validation PR-AUC `0.5074707204`, ROC-AUC `0.4480471079`;
- M1 test PR-AUC `0.5137590769`, ROC-AUC `0.4605629446`;
- M1 challenge PR-AUC `0.4222839299`, ROC-AUC `0.4989922318`;
- challenge campaign recall at the primary operating point: `0.0`;
- nuisance-only baselines outperform full M1;
- grouped learning-curve final delta PR-AUC `-0.0138075260`;
- research quality failure: `shortcut_risk`;
- scale decision: `STOP_AT_1K`.

Therefore V1 deployment posture is:

```text
wire traffic
    |
    v
Suricata on NGFW
    |-- deterministic remote-admin rules -> visibility / audit telemetry only
    |
    `-- EVE flow JSON -> optional research sidecar
                           |
                           |-- EveFeatureState
                           |-- M1 LightGBM shadow score
                           `-- M2 Isolation Forest shadow score
                                      |
                                      v
                           experiment/SIEM telemetry only
```

No V1 M1/M2 score should block, drop, quarantine or independently create a production-severity incident.

Suricata alerts are never used as training labels. The scenario manifest is ground truth in the lab. Production has no scenario/campaign/persona/implementation metadata and must not depend on it.

## M0 — deterministic Suricata visibility layer

`rules/remote-admin.rules` remains useful as a transparent comparison/audit layer for observable SSH, SMB, RDP and VNC activity and bounded rate conditions. It is **not** evidence that the connection is malicious and its alerts are not ground truth.

In final 1k parsing the deterministic rule pass produced observable rule events, but the separate deterministic-behavior model still had extremely poor suspicious recall at its chosen operating point. Consequently V1 does not claim a high-quality behavioral detector merely because a Suricata signature fired.

Rules are compiled with `suricata -T`. Rule output is stored separately from raw parser EVE under `silver/<shard>/suricata-rules/` so detector output cannot contaminate Gold labels.

Recommended V1 operational use:

- protocol visibility;
- policy/audit signal;
- low-severity SOC enrichment;
- troubleshooting and research cohort selection;
- **not automatic malicious/benign classification**.

## M1 — LightGBM research sidecar, not promoted

M1 was trained on `production_model_matrix.parquet`, whose unit is a parser-observed Suricata flow. The train/serve feature implementation is `adminlab.online_features.EveFeatureState` and the final Gold construction uses causal prior-train reference context for held-out evaluation.

The same sidecar code can be run in a **shadow experiment**:

```bash
python scripts/score_eve_sidecar.py \
  --model models/M1-lightgbm.joblib \
  --metrics models/M1-lightgbm.metrics.json \
  --eve /var/log/suricata/eve.json
```

For streaming research, feed newline-delimited EVE records through a local stream/socket consumer or existing event bus and retain the `EveFeatureState` object for the life of the worker.

This command demonstrates train/serve integration only. The V1 metrics do **not** justify treating its output as a production detector.

### Model-visible inputs

Only `production_allowlist` columns from `configs/feature_contract.yaml` are model inputs. The following categories remain forbidden:

- raw source/destination IPs as model values;
- host/persona/task/scenario/campaign IDs;
- client/server implementation IDs;
- generator/wire-control parameters;
- netem profiles;
- fidelity tags;
- MITRE labels;
- split/challenge metadata.

The sidecar may use source/destination IPs internally as ephemeral state keys to derive network-visible history such as connection counts, unique destinations, first-seen pair flags, pair frequency and graph counters. Raw keys are not passed into the model.

## M2 — benign-only Isolation Forest shadow expert

M2 is trained only on benign training rows and numeric network-visible features. Final V1 results do not justify promotion. Keep it as shadow telemetry for later feature/data research only.

A future fusion policy must not combine weak M0/M1/M2 outputs into a stronger-looking severity without independent calibration. Fusion is a new hypothesis and requires a new research gate.

## EVE configuration

At minimum Suricata must export `flow` records plus normal protocol metadata. File output is adequate for offline validation; production-like research should prefer a bounded local transport such as a Unix socket/stream or an existing event pipeline.

Example EVE section:

```yaml
outputs:
  - eve-log:
      enabled: yes
      type: file
      filename: eve.json
      types:
        - alert
        - flow
        - anomaly
        - ssh
        - smb
        - rdp
        - rfb
        - dcerpc
```

Protocol-specific EVE availability is Suricata-version/parser dependent. The production-flow feature code does not require payload visibility to compute its current flow/history features.

## State and restart behavior

`EveFeatureState` is prior-only: the current flow is scored from state that existed before the current flow is inserted. Final offline Gold projects parser-observed flow timing onto the simulated organization clock and uses causal reference context for held-out evaluation.

For HA/restarts, recent source history and one-hour graph counters may be checkpointed. A cold restart is operationally safe but novelty/history features reset. Any research deployment should surface `state_warm=false` during warm-up instead of interpreting every first-seen destination as meaningful anomaly evidence.

## Final V1 response policy

```text
Suricata deterministic match -> audit / visibility event
M1 score                      -> shadow research telemetry only
M2 score                      -> shadow research telemetry only
M0 + M1 + M2 agreement        -> still not an enforcement decision in V1
```

Automatic packet drop, IP blocking, account action, host quarantine or runtime relabelling is prohibited for this V1 result.

## Why no promotion occurs

The blocker is not merely an arbitrary threshold. Under corrected full-timeline sampling, strict challenge budgets and causal state replay:

1. M1 validation/test discrimination is around chance level;
2. simple rate/time/duration/bytes/port-protocol families are as strong as or stronger than full M1;
3. challenge campaign recall at the chosen low-FPR operating point is zero;
4. the grouped learning curve does not improve with all 1k sessions;
5. therefore scaling the same generator distribution is not supported by evidence.

The correct research conclusion is `REJECTED_MODEL_QUALITY`, not threshold relaxation.

## What would justify a V2 promotion attempt

A new promotion attempt should change the hypothesis, for example by adding one or more of:

- richer longitudinal policy/user/host context available to the intended product;
- independently collected network environments instead of more rows from one GitHub namespace lab;
- native Windows RDP/WinRM/DCOM cohorts;
- real/reference benign administration data;
- explicit organizational authorization context if such context is available at inference time;
- new temporal/session/campaign representations that are evaluated without split leakage.

Any V2 must first pass a fresh 1k gate with low-FPR recall, hard-benign, unseen implementation/persona/pair/temporal slices and shortcut audit before larger fan-out.

## Rollback, storage and reproducibility

Final rejected V1 evidence is intentionally retained so the research can be reproduced or re-featured without regenerating traffic.

Private HF quarantine:

```text
Maksim123321/remote-admin-anomaly-v1/
└── quarantine/rejected/gh-31818445960/
    ├── release/
    │   ├── bronze/H-research-1k/   # full PCAP + manifests + checksums
    │   ├── silver/H-research-1k/   # raw Suricata/Zeek
    │   ├── gold/H-research-1k/     # production-flow matrices/labels/splits
    │   └── quality/H-research-1k/  # mapping/parser/leakage evidence
    ├── models/
    ├── evaluation/
    ├── RESEARCH_GATE.json
    └── NEGATIVE_RESEARCH_VERIFIED.json
```

GitHub fallback:

- research run `31818445960`;
- artifact `remote-admin-research-gate-v2-31818445960`;
- Artifact ID `9226887886`;
- digest `sha256:40a463b9f16d4251d3b40b8915ef7a7425a883edd2916484acab660328fbbf72`;
- 90-day retention.

If parser or feature logic changes, rebuild Silver/Gold from Bronze `H-research-1k.pcap.zst`; do not regenerate traffic merely to recompute features.

The quarantine path is a research rollback source, **not** a production-promoted model/data release.
