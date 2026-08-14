# Remote Admin Anomaly V1 — NGFW / Suricata Integration

## Decision

V1 is a hybrid detector, not a choice between rules and ML:

```text
wire traffic
    |
    v
Suricata on NGFW
    |-- M0 deterministic rules -> immediate IDS alert
    |
    `-- EVE flow JSON -> admin-anomaly sidecar
                           |
                           |-- prior-only window / novelty / graph state
                           |-- M1 LightGBM primary score
                           `-- M2 benign-only anomaly shadow score
                                      |
                                      v
                           remote_admin_ml event / SIEM
```

Suricata alerts are never used as training labels. The scenario manifest is ground truth in the lab. In production no scenario metadata is available or required.

## M0 — deterministic Suricata layer

`rules/remote-admin.rules` provides a deliberately conservative comparison baseline for observable connection bursts on SSH, SMB, RDP, VNC and the challenge-only WS-Man fixture. It is suitable for known policy/rate conditions and immediate alerting. It is not expected to distinguish a valid administrator from a compromised internal host when both use the same protocol normally.

The rules are compiled with `suricata -T` before an offline evaluation run. Rule output is stored separately from raw parser EVE under `silver/<shard>/suricata-rules/` so the detection result cannot contaminate Gold labels.

## M1 — production behavioral model

The promoted M1 model is trained on `production_model_matrix.parquet`, whose unit is a parser-observed network flow. Ground truth is used only to attach a class and grouped split during training.

The online scorer is:

```bash
python scripts/score_eve_sidecar.py \
  --model models/M1-lightgbm.joblib \
  --metrics models/M1-lightgbm.metrics.json \
  --eve /var/log/suricata/eve.json
```

For a streaming deployment, feed the same newline-delimited EVE records over a Unix stream/socket consumer or message bus and retain the `EveFeatureState` object for the life of the worker.

### Model-visible inputs

Only `production_allowlist` columns from `configs/feature_contract.yaml` are model inputs. Raw `src_ip`, `dest_ip`, host IDs, scenario/campaign IDs, generator parameters, netem profile, fidelity tags and MITRE labels are forbidden.

The sidecar is allowed to use source/destination IPs internally as ephemeral state keys to derive:

- connection counts over 1m/5m/15m/1h;
- unique destinations and protocol diversity;
- first-seen destination/pair indicators;
- pair frequency;
- one-hour source out-degree and destination in-degree;
- new-edge count and protocol entropy.

These raw keys are not passed to the model.

## M2 — benign-only anomaly expert

M2 is an Isolation Forest trained only on benign training rows and numeric network-visible features. In V1 it is a **shadow expert**. Its score is logged for evaluation and SOC enrichment but does not independently trigger a block.

A future fusion policy may combine M0/M1/M2 only after calibration on production-like holdouts. No V1 corpus should be relabelled from M2 output.

## EVE configuration

At minimum Suricata must export flow records plus protocol metadata needed operationally. File output is adequate for offline validation; production should prefer a bounded local transport such as Unix socket/stream or an existing event pipeline.

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

Availability of protocol-specific EVE types is version/parser dependent; the production-flow model does not require payload visibility to operate.

## State and restart behavior

`EveFeatureState` is prior-only: the current flow is scored using history that existed before the flow is inserted into rolling state. This prevents future leakage and matches the production-flow Gold semantics.

For HA/restarts the minimal state that may be checkpointed is recent source history and one-hour graph counters. A cold restart is safe but novelty features temporarily reset; deployments must surface a `state_warm=false` operational field during the warm-up period rather than treating all first-seen destinations as equally trustworthy.

## V1 response policy

V1 promotion target is alert/enrichment only:

```text
risk < promoted threshold     -> no ML alert
risk >= promoted threshold    -> remote_admin_ml alert
M0 deterministic alert        -> Suricata alert independently
M0 + high M1                  -> increase SOC priority
M2 anomaly only               -> shadow telemetry
```

Automatic packet drop, IP blocking or runtime dataset insertion is intentionally deferred. It requires a separate production false-positive study, rollback procedure and approval threshold because legitimate helpdesk/deployment/admin bursts are hard negatives by design.

## Rollback and reproducibility

A model release is not accepted unless its exact feature-contract hash, metrics, split policy and source Gold release are retained. If a parser or feature implementation changes, rebuild Silver/Gold from Bronze `*.pcap.zst`; do not regenerate traffic merely to recompute features.

The intended storage hierarchy is:

```text
releases/<release-id>/
  bronze/<shard>/      # full PCAP + manifests + checksums
  silver/<shard>/      # Suricata/Zeek raw parser logs
  gold/<shard>/        # research/session and production-flow features
  quality/<shard>/     # mapping/parser/leakage gates
  merged/              # global split/model analysis
  production-promoted/ # parser-flow final models/reports
```
