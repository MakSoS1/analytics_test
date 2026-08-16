# Remote Admin Anomaly Lab V3 — Corrected Causal / NGFW Status

**Branch:** `remote-admin-anomaly-lab-v3`  
**Dataset generation:** V3 in-place; no V4 fork  
**Primary production unit:** Suricata EVE `flow`  
**Production feature implementation:** `adminlab.online_features.EveFeatureState`  
**Deployment model alias:** `gold/V3-1k/models/M1-lightgbm.joblib`

## Authoritative evidence

Do not infer scientific readiness from this Markdown file. For every corrected V3 release, the authoritative machine-readable files are:

```text
quality/V3-1k/V3_RESEARCH_DECISION.json
quality/V3-1k/V3_RELEASE_MANIFEST.json
quality/V3-1k/V3_HF_REMOTE_VERIFY.json
quality/V3-1k/V3_CAUSAL_FINAL_STATUS.json
quality/V3-1k/production_flow_gold.json
gold/V3-1k/models/flow-primary.metrics.json
gold/V3-1k/models/shortcut-audit.json
quality/V3-1k/hard_benign_flow.json
quality/V3-1k/flow_learning_curve.json
```

`dataset_release_status=READY` and `research_status=PASS` are deliberately separate. A technically complete dataset is retained even if its detector hypothesis fails the promotion gates.

## What was corrected in V3

The original V3 generated a balanced binary label largely independently of the network process and added much of the benign/malicious distinction later as forbidden semantic metadata. That made the production feature matrix close to non-identifiable.

Corrected V3 changes the causal direction:

```text
source baseline / prior relations
          ↓
benign activity or suspicious mutation
          ↓
real application session on isolated wire
          ↓
Suricata EVE flow
          ↓
prior-only production state
          ↓
label used only for training/evaluation
```

The incoming legacy labels from the candidate pool are not used to choose the corrected target class. The candidate pool supplies realistic protocol/timestamp/current-session nuisance variation; `v3_causal_ngfw` constructs the observable relation before the final label is materialized.

## Network identities and endpoints

The corrected topology has at least 32 independent source identities for the 1k gate and explicitly includes compromised-workstation sources. It no longer collapses the organizational baseline to the old handful of source IPs.

SSH and SMB use several independent target namespaces/service instances. RDP and VNC use several explicitly marked L3 endpoint aliases on the same validated xrdp/TigerVNC service stack. Alias endpoints exist to provide pair/graph diversity without falsely claiming several independent Windows desktops on a GitHub-hosted Linux runner.

All endpoints stay inside `10.77.0.0/24`. External routing and payload execution remain disabled.

## Counterfactual pairs

At least 40% of the corrected 1k corpus must belong to matched benign/suspicious current-session pairs.

A pair is accepted only when:

1. current-session nuisance controls match;
2. labels are opposite;
3. the strictly-prior production-observable history differs;
4. the difference still exists after the final current-session timestamp copy and a complete chronological replay of all already accepted pairs.

A semantic-only pair is a hard planner failure.

## Production model boundary

The production candidate is **flow-primary**. Session and campaign views remain research/SOC views and are not required at inference time.

The NGFW scorer consumes Suricata EVE `flow` records for remote-administration candidate traffic only. Unrelated DNS/HTTP/TLS flows do not mutate this model's rolling baseline.

Production state includes prior-only quantities such as:

- connection counts over 1m/5m/15m/1h/24h/7d/30d;
- unique destination counts;
- source/destination pair frequency and recency;
- new-destination/new-pair state;
- source-protocol and source-pair-protocol familiarity;
- destination prevalence;
- short-window graph degree/new-edge rate;
- protocol switches and entropy.

Raw IPs are state keys only and never model features.

## Train / serve parity

Offline production Gold and the online sidecar use the same `EveFeatureState` implementation. The current flow is scored before it is inserted into history.

The online state can be atomically checkpointed and restored, so a sensor restart does not erase its 7d/30d baseline.

The production sidecar does not require:

- orchestrator `session_id`;
- campaign IDs;
- personas or labels;
- Zeek;
- PCAP;
- EDR telemetry.

Deployment files are in:

```text
deploy/ngfw/install_v3.sh
deploy/ngfw/remote-admin-v3.service
deploy/ngfw/README.md
scripts/score_eve_sidecar.py
```

## Split and leakage policy

Campaign/counterfactual connected groups never cross split boundaries. The session/campaign research view uses independent state replay per split.

For the production flow benchmark, held-out streams may receive only causally prior reference context permitted by the production replay policy; validation/test/challenge do not mutate one another's state. Ground-truth, generator, netem, identity and fidelity metadata remain forbidden model columns.

## Shortcut audit

The old V3 compared different estimator families for full vs nuisance-only models. Corrected V3 trains the full model and every ablation with the same LightGBM pipeline/hyperparameters.

The promotion decision separately measures:

- time-only;
- protocol-only;
- bytes/packets-only;
- duration/current-session-only;
- history-only;
- full production feature set.

A high PR-AUC is not sufficient if the full model does not materially beat nuisance views or the intended history view does not beat prevalence.

## Corrected 1k promotion gates

The corrected release is fail-closed. The committed gate currently requires, among other checks:

- exactly 1000 successful labeled sessions for the 1k gate;
- 500 benign / 500 suspicious;
- 250 SSH / 250 SMB / 250 RDP / 250 VNC;
- 125/125 class balance inside each protocol;
- at least 32 source identities;
- at least 40% causal counterfactual rows;
- overall session mapping >= 99.5%;
- each protocol session mapping >= 99%;
- flow mapping >= 98%;
- validation flow PR-AUC >= 0.70;
- test and challenge flow PR-AUC >= 0.65;
- full model margin over best nuisance >= 0.05;
- history-only margin over prevalence >= 0.05;
- hard-benign FPR <= 1%;
- non-zero challenge recall at the strict low-FPR operating point;
- no external data in fit or threshold tuning;
- exact Suricata/EveFeatureState train-serve candidate-stream parity.

Failure of a scientific gate means `STOP_AT_1K`, not silent threshold relaxation and not automatic generation of 4k rows.

## Bronze / rollback

Final Bronze remains recoverable and manually inspectable:

```text
bronze/V3-1k/
├── sessions/
├── campaigns/
├── raw_chunks/
└── manifests/
```

The giant merged capture is a temporary parsing object and is not retained in the final HF payload. Session PCAPs, campaign PCAPs and complete raw packet chunks preserve the ability to rebuild Silver/Gold with later Suricata/Zeek/feature code.

## External evidence

LANL-derived reference traffic and native-Windows evidence remain external holdouts. They are forbidden from training and threshold selection.

The LANL flow evaluation is transformed into an EVE-like stream and replayed through the same `EveFeatureState` instead of being pushed through the old session adapter with missing columns filled by zeros.

Native Windows protocols are reported fail-closed: a protocol is never called validated without corresponding wire evidence. In particular, native RDP/DCOM limitations of hosted runners are not converted into synthetic success claims.

## Release and storage policy

A corrected release is uploaded only under a new immutable V3 prefix:

```text
Maksim123321/remote-admin-anomaly-v1
└── v3/final/run-<github-run-id>/
```

The prior verified V3 payload is not deleted before the corrected payload has passed its own manifest, HF upload and full remote-download/hash verification.

The final Actions workflow is:

```text
.github/workflows/remote-admin-v3-causal-final.yml
```

Its dependency order is fail-closed:

```text
full regression suite
        ↓
80-session real-wire causal smoke
        ↓
Windows + LANL external evidence
        ↓
1k real-wire corrected corpus
        ↓
Silver / production Gold
        ↓
flow-primary model + ablations
        ↓
low-FPR / hard-benign / learning-curve gates
        ↓
immutable manifest
        ↓
HF upload
        ↓
full remote download + hash verification
```

Do not replace the JSON evidence with remembered metric values in this file. The release JSON is the source of truth.
