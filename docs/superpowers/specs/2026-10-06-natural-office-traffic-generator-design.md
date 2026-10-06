# Natural Office Traffic Generator v2 — Design

**Date:** 2026-10-06  
**Repository:** `MakSoS1/analytics_test`  
**Base branch:** `research-transfer-2026-10-06`  
**Implementation branch:** `natural-traffic-generator-v2-2026-10-06`

## 1. Goal

Build a universal research generator that produces **labelled scenario/control network sessions using real client protocol stacks**, then composes those sessions with retained office background so the resulting positive population is suitable for training and evaluating NDR/NGFW models without relying on laboratory-source shortcuts.

The generator must support the existing Cover Channel corpus and a generic external-activity import path for future network-visible techniques.

The result is considered a **training-ready naturalness candidate** only when a frozen benign-control population passes explicit office-domain similarity gates and the corresponding scenario population preserves measurable technique signal. The implementation must never claim that a synthetic generator is indistinguishable from every future production office network.

## 2. Problem Statement

The current research-transfer pipeline can preserve and replay packet captures, align them to office windows, model selected path properties, and calculate the same pipeline/Arkime features as the office corpus. It does not recreate the transport and application session through the target client stack.

The retained audits show that source origin remains highly separable even for benign laboratory clients. Therefore the dominant defect is not one feature family; it is the joint fingerprint of the capture/runtime domain.

The replacement architecture must move the adaptation point **before packet capture**:

```text
activity specification
      |
      +--> matched benign control
      |
      +--> scenario
              |
              v
      frozen runtime profile
      (real client stack)
              |
              v
      real protocol exchange
              |
              v
      packet capture + evidence
              |
              v
      pipeline + Arkime extraction
              |
              v
      office-domain validation
              |
              v
      office-background composition
```

## 3. Available Reference Data

The implementation uses the pseudonymized dataset already committed under:

`cover-channel-lab/research-transfer/datasets/office-cover-20261006/`

Required reference tables:

- `pipeline_office_full.parquet`: 5,726 rows × 180 columns.
- `pipeline_added_full.parquet`: 2,784 rows × 180 columns.
- `pipeline_original_155.parquet`: 8,510 rows × 155 columns, containing the original 127 feature columns plus identifiers/labels/service fields.
- `arkime_office_all_fields.parquet`: 6,053 rows × 833 columns.
- `arkime_added_all_fields.parquet`: 2,790 rows × 833 columns.
- `matched_office_pipeline_arkime.parquet`: 5,723 rows × 990 columns.
- `matched_added_pipeline_arkime.parquet`: 2,784 rows × 990 columns.
- `matched_mixed_pipeline_arkime.parquet`: 8,507 rows × 990 columns.
- `session_comparison.parquet`: 8,843 rows × 50 columns.

The encrypted dictionary is **not required** for numeric naturalness evaluation. Sensitive textual semantics must remain pseudonymized in CI.

## 4. Design Principles

### 4.1 Real stack, not packet morphing

The primary generated artifact must come from a live protocol exchange performed by the selected client stack.

The generator may configure environment properties such as MTU, latency, jitter, packet loss, client/browser implementation, and protocol settings **before capture**. It must not rewrite payload bytes, TCP option bytes, TLS handshake bytes, packet sizes, or packet ordering after capture in order to improve naturalness metrics.

Timestamp-only composition is allowed only when placing an already validated capture into a retained office timeline. It must not be counted as evidence that the capture itself became office-native.

### 4.2 Benign-only domain calibration

Runtime/profile selection is calibrated using:

`office reference ↔ generated matched benign controls`

Scenario/positive sessions are never used to choose runtime profiles, feature masks, path parameters, stack weights, or naturalness thresholds.

After calibration, the profile manifest is frozen by SHA256. Scenario generation consumes that immutable manifest.

This prevents optimization of suspicious traffic against the diagnostic origin classifier.

### 4.3 Paired scenario/control generation

Each activity profile has a scenario arm and a matched-control arm.

A pair must share:

- client stack and version;
- server stack and version;
- path profile;
- client identity class;
- protocol version;
- connection lifecycle policy;
- capture point;
- time-of-day/load stratum;
- randomization seed family.

Only the technique-relevant application behavior may differ.

### 4.4 Grouped evaluation

No derivative of the same source execution may cross train/validation/test.

Grouping precedence:

1. source capture/execution ancestor;
2. runtime profile;
3. activity pair;
4. office capture day/block.

Repeated placement of one PCAP is never an independent observation.

### 4.5 Preserve full features

The analysis layer retains the full pipeline feature schema and all emitted Arkime fields. Feature masks are model configurations, not destructive dataset transformations.

Identifiers, labels, provenance, split assignment, and pseudonymization tokens are never model inputs.

## 5. Runtime Profile System

A new profile registry defines how a benign control or scenario is executed.

Each profile records:

- `profile_id`;
- operating-system runner family;
- client implementation;
- protocol implementation;
- browser/runtime version information;
- capture implementation;
- MTU/path settings;
- timing environment;
- TLS implementation class;
- server fixture type;
- deterministic seed;
- capability evidence;
- image/tool hashes where available.

### 5.1 Initial profiles

The first implementation ships with these families:

1. **Linux Python stdlib / ssl**
2. **Linux curl**
3. **Linux Chromium**
4. **Linux protocol-native clients** for HTTP/2, HTTP/3/QUIC, gRPC, WebSocket/WSS and MQTT-over-WSS where the existing Coverlab implementation already has a wire-real client.
5. **Windows native client profile** running on a GitHub-hosted `windows-latest` runner and using a native Windows HTTP/TLS client path when capture capability passes its probe.

Windows is a capability-gated profile. The workflow must run a capture probe first and publish `supported=false` rather than silently substituting Linux if packet capture is unavailable.

### 5.2 Profile calibration

Calibration generates only benign controls.

For every profile, the pipeline extracts the same comparable numeric feature space used by the reference office tables. A calibration optimizer chooses a **mixture of profiles**, not per-session packet edits.

The objective is lexicographic:

1. satisfy minimum support and integrity;
2. minimize classifier two-sample separability;
3. minimize normalized distribution distance by feature family;
4. prefer simpler mixtures when statistically equivalent.

The optimizer must use only training/reference partitions. Thresholds and profile candidates are frozen before the confirmation split is read.

## 6. Universal Activity Interface

Two supported integration modes are required.

### 6.1 Managed adapter mode

A `TechniqueAdapter` exposes a bounded interface:

```python
class TechniqueAdapter(Protocol):
    def describe(self) -> ActivityDescriptor: ...
    def generate(self, context: GenerationContext) -> CaptureBundle: ...
```

`ActivityDescriptor` declares:

- technique ID;
- transport/protocol family;
- scenario/control roles;
- required capabilities;
- timing ownership;
- expected evidence types.

`GenerationContext` supplies the frozen runtime profile, output directory, seed, role, and resource budget.

`CaptureBundle` returns immutable paths/hashes for PCAP, evidence, manifest and runtime metadata.

The adapter registry is explicit. Repository workflows never execute arbitrary commands supplied through dataset metadata.

### 6.2 External import mode

The existing `activity.json` path remains supported for third-party generators.

It accepts scenario/control PCAP plus evidence and hashes, validates integrity and membership, extracts features, and evaluates the same naturalness/technique contracts.

External import does not claim the capture was generated by the repository runtime.

## 7. Cover Channel Integration

Existing Cover Channel scenario definitions remain the first managed activity family.

The implementation must preserve current scenario identifiers and source pins where possible, but generation must be routed through the new frozen runtime profile layer.

Mechanics that cannot be represented by a selected real stack are not converted into approximate sessions and labelled as wire-real. They remain explicitly marked with their fidelity class.

The generator must distinguish:

- wire-real mechanism;
- semantic fixture;
- visibility-only fixture;
- unsupported on the selected profile.

Only wire-real or explicitly accepted research-fixture rows can be marked training-eligible.

## 8. Office Composition

Validated generated captures can be placed into retained office background windows.

Composition requirements:

- original office rows remain immutable;
- generated packet bytes remain immutable after capture;
- endpoint collisions are rejected;
- packet ordering is preserved;
- time placement cannot compress the source session;
- positive/control membership is exact and separately persisted;
- office labels remain unknown;
- generated labels never propagate to neighboring office sessions.

The output contains clean, control and scenario alternatives for the same pinned office source windows where practical.

## 9. Naturalness Evaluation

Naturalness is evaluated on benign controls only.

### 9.1 Classifier two-sample test (C2ST)

At minimum run three predeclared classifiers:

- balanced histogram gradient boosting;
- balanced ExtraTrees;
- balanced logistic regression.

Evaluation is grouped and held out by runtime/source groups and office blocks.

A confirmation population passes the primary C2ST gate when:

- each class has at least 30 independent groups;
- no classifier has point ROC AUC > 0.70;
- the maximum point ROC AUC across the three classifiers is <= 0.65 **or** its 95% cluster-bootstrap interval overlaps 0.50 and its upper bound is <= 0.70.

A result is `insufficient_data`, never `passed`, when support is below the declared minimum.

### 9.2 Distribution-distance gate

For each feature family, compare office-vs-control distance to the reference **office-vs-office-block** distance.

Families include at least:

- volume/direction;
- size;
- timing/burst;
- TCP flags/handshake;
- retransmission;
- TLS;
- payload statistics;
- QUIC;
- DNS;
- parser/presence metadata;
- Arkime common numeric session fields.

A profile mixture passes this gate when:

- at least 90% of measurable families are at or below the 95th percentile of the intra-office reference distance;
- no measurable family exceeds 1.5× that reference threshold;
- missingness gaps are reported and included as signal, not imputed away before the diagnostic.

### 9.3 Negative control

A same-office random cohort split must remain close to chance. If the naturalness test cannot recognize an intentionally injected synthetic origin artifact in a unit test, the diagnostic is invalid.

### 9.4 Naturalness statuses

Allowed status values:

- `passed_candidate`
- `not_passed`
- `insufficient_data`
- `integrity_failed`

The repository must not emit `production_ready=true` based only on synthetic-vs-retained-office evaluation.

## 10. Technique Signal Evaluation

Scenario-vs-matched-control evaluation is performed **after** the frozen profile passes benign naturalness calibration.

For each technique:

- evaluate only paired scenario/control executions;
- keep source/runtime ancestors grouped;
- use the same production-available feature contract;
- report classifier AUC, paired effect tests and confidence intervals.

A technique becomes `training_eligible=true` when:

- integrity and fidelity gates pass;
- at least 30 independent paired groups exist, unless an exact paired test provides stronger evidence with fewer groups;
- either the frozen classifier lower 95% CI exceeds 0.60 or a predeclared paired-feature family test survives family-wise correction and has consistent direction in at least 70% of non-zero independent pairs;
- the benign naturalness profile used by that technique remains `passed_candidate`.

A failed technique-signal gate does not invalidate the generator; it marks that technique/profile combination as not training-eligible.

## 11. Calibration Leakage Prevention

The workflow is divided into three phases:

1. **calibrate** — office-train + benign-control-train only;
2. **freeze** — write `frozen_profile_manifest.json` and SHA256;
3. **confirm** — office-confirmation + benign-control-confirmation + scenario/control confirmation.

The confirmation phase must verify the frozen manifest hash and refuse to run optimization.

Generated scenarios are unavailable to calibration code by construction.

## 12. GitHub Actions Architecture

Add a dedicated workflow for the new generator.

### 12.1 Jobs

1. **validate-reference-data**
   - verify dataset manifest/hashes;
   - verify Parquet schemas and expected row/column counts;
   - ensure sensitive dictionary decryption is not required.

2. **unit-tests**
   - Python tests for adapters, profile manifests, grouping, gates and leakage prevention.

3. **capture-probe-linux**
   - verify namespace/capture privileges and required tools.

4. **capture-probe-windows**
   - verify native packet-capture capability on `windows-latest`;
   - publish a capability artifact.

5. **generate-benign-matrix**
   - generate benign control captures across supported profiles;
   - enforce disk/resource budgets;
   - upload capture/evidence artifacts.

6. **calibrate-profile-mixture**
   - extract comparable features;
   - calculate train-only profile mixture;
   - freeze manifest.

7. **confirm-naturalness**
   - evaluate held-out benign controls against held-out office reference;
   - produce machine-readable and Markdown reports.

8. **generate-cover-scenarios**
   - run only profiles that passed benign calibration;
   - use frozen profile manifest;
   - generate scenario/control pairs.

9. **evaluate-technique-signal**
   - extract full features;
   - evaluate scenario-vs-control by technique;
   - produce training-eligibility manifest.

10. **package-release**
    - package code, manifests, reports and Parquet outputs;
    - never package private decryption material.

### 12.2 Workflow triggers

Support:

- `workflow_dispatch` for full runs;
- pull-request CI for unit tests/reference validation only;
- optional manual profile/technique filters.

A pull request must not automatically launch the expensive full capture corpus.

## 13. Resource Controls

Every capture/generation job must:

- measure free disk before work;
- reserve at least 15 GiB free on hosted runners;
- cap temporary capture storage per matrix shard;
- delete only its own scratch directory after successful artifact upload;
- retain failed manifests/logs;
- never delete source/reference dataset files.

Large corpora are sharded. No single job should need the complete generated corpus in local scratch simultaneously.

## 14. Evidence and Reproducibility

Every generated capture stores:

- activity ID and role;
- runtime profile ID;
- Git commit SHA;
- workflow/run/job identifiers;
- dependency/runtime versions;
- seed;
- PCAP SHA256;
- evidence SHA256;
- frozen profile manifest SHA256;
- capture capability result;
- feature-extractor version;
- split/group ancestor IDs;
- integrity result;
- naturalness status;
- technique-signal status.

Reports must distinguish measured fact, inferred classification and unsupported capability.

## 15. Testing Strategy

### 15.1 Unit tests

Tests must cover:

- scenario/control profile equality except technique-owned fields;
- calibration code cannot access scenario rows;
- confirmation code cannot modify frozen profile manifest;
- grouped split prevents source-ancestor leakage;
- insufficient support cannot pass;
- label/provenance columns cannot enter X;
- missingness remains visible to diagnostics;
- endpoint/timestamp/order integrity;
- adapter registry rejects undeclared arbitrary execution;
- packet bytes are not rewritten after capture;
- unsupported Windows capture is explicit;
- deterministic profile-mixture freezing;
- same-office negative-control sanity;
- injected source artifact is detected by C2ST;
- training eligibility requires both naturalness and technique signal.

### 15.2 Integration tests

Linux CI must produce at least one real paired HTTPS capture and prove:

- both arms traverse the same selected runtime profile;
- PCAP is non-empty and parseable;
- full extraction succeeds;
- pairing/grouping metadata is complete;
- bytes used for extraction match the captured artifact hash.

Windows integration runs only after the capture probe reports supported.

### 15.3 Reference-data regression

The committed office-cover dataset is immutable input for this branch.

CI verifies the expected hashes from `DATA_MANIFEST.json` before using it.

## 16. Deliverables

The branch is complete when it contains:

1. universal adapter/profile framework;
2. Cover Channel managed adapter;
3. external `activity.json` compatibility;
4. Linux real-stack generation profiles;
5. Windows capability-gated native profile;
6. office calibration and frozen-mixture logic;
7. naturalness evaluation suite;
8. technique-signal evaluation suite;
9. office composition path;
10. GitHub Actions workflow;
11. full tests;
12. generated machine-readable example reports;
13. documentation for adding another technique;
14. release/package manifest.

## 17. Non-Goals

This project does not:

- modify production NDR detection logic;
- tune a C2 implementation against a deployed detector;
- rewrite captured TCP/TLS bytes to imitate a particular user/device;
- infer original sensitive strings from pseudonymized tables;
- label all retained office traffic benign;
- claim proof of production transfer without future positive sessions observed by a real office sensor.

## 18. Acceptance Criteria

The implementation itself is accepted when:

- all repository tests pass on the implementation branch;
- reference-data verification passes;
- Linux real-stack integration capture passes;
- calibration/freeze/confirmation lifecycle is enforced by tests;
- at least one Cover Channel technique completes end-to-end through frozen profile → capture → extraction → composition → evaluation;
- full GitHub Actions CI for the new workflow reaches a terminal result with artifacts/reports;
- no private key, HMAC key or decrypted dictionary is committed.

The **generated corpus** is labelled `naturalness=passed_candidate` only if the Section 9 gates pass on the committed reference dataset and newly generated benign controls. Otherwise the generator remains functional but the corpus status is `not_passed` or `insufficient_data`, and the report must identify the dominant separating feature families/profile combinations.

## 19. Migration

The existing `research-transfer` code and datasets remain immutable reference material.

New code lives under a new focused package within `cover-channel-lab/research-transfer/code/` and reuses existing extractors/importers only through explicit interfaces. Historical one-off diagnostics are not silently deleted during the first implementation; canonical replacements are documented, and cleanup happens only after equivalence tests exist.
