# V3 Causal NGFW Signal Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair `remote-admin-anomaly-lab-v3` in place so labels arise from production-observable causal network history/sequence differences and the primary model can be trained and served from Suricata EVE plus prior rolling state.

**Architecture:** Keep the current Bronze/Silver/Gold and real-wire execution stack, but replace the Stage-H V3 planner with a causal baseline-and-mutation planner. Expand lightweight source endpoint identities, build split-isolated prior-state features with the same state semantics used online, and make all shortcut ablations use the same estimator as the full model. Regenerate the 1k gate only after contracts prove causal observability and train/serve parity.

**Tech Stack:** Python 3.12, pandas, LightGBM, Suricata EVE JSON, GitHub Actions Ubuntu 24.04 network namespaces, pytest, Zeek as research-only parser.

## Global Constraints

- Work only on branch `remote-admin-anomaly-lab-v3`; do not create V4.
- Primary production inputs are Suricata EVE plus strictly prior rolling state.
- No username/EDR/AD/persona dependency in the primary production model.
- Raw IP/host IDs may be state keys but never model features.
- Preserve real-wire SSH/SMB/RDP/VNC execution and 250 sessions per protocol at the 1k gate.
- Preserve 500 benign / 500 suspicious and at least 40% valid counterfactual rows.
- Counterfactual twins must match current-session nuisance controls but differ in at least one production-observable intended-history feature.
- 4k remains fail-closed until corrected 1k research gates pass.

---

### Task 1: Add causal planner contracts

**Files:**
- Create: `remote-admin-anomaly-lab/tests/test_v3_causal_signal.py`
- Modify: `remote-admin-anomaly-lab/src/adminlab/v3_signal.py`
- Modify: `remote-admin-anomaly-lab/scripts/v3_planner_audit.py`

**Interfaces:**
- Produces: `history_signature(record, history_state)`, causal family audit fields, and fail-closed matched-pair history-difference checks.

- [ ] Write tests that prove opposite-label counterfactual pairs cannot pass if their intended production-history signatures are identical.
- [ ] Write tests that require causal suspicious families to materialize explicit observable invariants (`rare_pair`, `sudden_fanout`, `new_protocol`, `protocol_switch`, `target_chain`, `source_drift`, `low_slow_lateral`).
- [ ] Run the new tests and confirm the current planner fails them.
- [ ] Implement the minimal causal audit/signature helpers and planner report fields.
- [ ] Re-run tests until they pass.

### Task 2: Expand lightweight source endpoint population

**Files:**
- Modify: `remote-admin-anomaly-lab/configs/topology.yaml`
- Modify: `remote-admin-anomaly-lab/configs/personas.yaml`
- Modify: `remote-admin-anomaly-lab/scripts/setup_topology.sh`
- Test: `remote-admin-anomaly-lab/tests/test_v3_causal_signal.py`

**Interfaces:**
- Produces: at least 32 distinct source endpoint IDs/IPs available to the Stage-H planner without adding external routing.

- [ ] Add a test asserting at least 32 source endpoint identities and explicit compromised-workstation source availability.
- [ ] Expand topology with lightweight source-only namespaces/addresses across admin, jump, developer, helpdesk, service, remote/user and compromised cohorts.
- [ ] Update persona endpoint-role mapping so malicious source-drift scenarios can use compromised/workstation-like sources without making source choice label-shortcut deterministic.
- [ ] Verify topology validation and namespace setup remain isolated and service destinations unchanged.

### Task 3: Replace shuffled labels with baseline-then-mutation generation

**Files:**
- Modify: `remote-admin-anomaly-lab/src/adminlab/digital_twin.py`
- Modify: `remote-admin-anomaly-lab/src/adminlab/v3_signal.py`
- Modify: `remote-admin-anomaly-lab/src/adminlab/v3_campaigns.py`
- Modify: `remote-admin-anomaly-lab/scripts/run_scenarios_extended_v2.py`
- Test: `remote-admin-anomaly-lab/tests/test_v3_causal_signal.py`

**Interfaces:**
- Produces: `plan_v3_causal_sessions(...)->list[SessionRecord]` where scenario family creates observable history first and label is assigned after invariants are satisfied.

- [ ] Add failing tests proving Stage-H V3 labels are not produced by a shuffled label vector independent of source/destination/history.
- [ ] Implement benign warm-up histories per source.
- [ ] Implement causal suspicious mutations for the seven required families.
- [ ] Implement hard-benign analogs with the same coarse rate/volume shapes but established prior familiarity.
- [ ] Preserve balanced protocol/label quotas and timeline coverage.
- [ ] Ensure campaign construction groups actual causal sequences rather than arbitrary same-label chunks.
- [ ] Run planner tests and existing contract tests.

### Task 4: Make counterfactual pairs current-session matched but history-separated

**Files:**
- Modify: `remote-admin-anomaly-lab/src/adminlab/v3_signal.py`
- Modify: `remote-admin-anomaly-lab/src/adminlab/wire_controls.py`
- Test: `remote-admin-anomaly-lab/tests/test_v3_causal_signal.py`

**Interfaces:**
- Produces: matched pairs with equal current-session signatures and unequal intended-history signatures.

- [ ] Add pair-level tests for exact current-session signature equality.
- [ ] Add pair-level tests requiring at least one directional difference in pair familiarity/new-edge/protocol novelty/fanout history.
- [ ] Preserve shared RNG keys for nuisance wire controls.
- [ ] Fail planning if 40% pair coverage cannot be achieved without violating the history-separation invariant.

### Task 5: Fix split-isolated causal state replay

**Files:**
- Modify: `remote-admin-anomaly-lab/src/adminlab/session_gold.py`
- Modify: `remote-admin-anomaly-lab/scripts/build_hierarchical_gold_v3.py`
- Create: `remote-admin-anomaly-lab/tests/test_v3_split_state.py`

**Interfaces:**
- Produces: `build_session_gold(..., state_partition_column="split")` or equivalent split-isolated replay used for primary benchmark Gold.

- [ ] Add a failing test where an earlier train event would change a validation feature under the old global replay.
- [ ] Implement independent rolling state per split for the primary benchmark.
- [ ] Keep within-split chronological ordering and strictly-prior semantics.
- [ ] Add a quality field that explicitly reports `cross_split_state_dependency=false`.
- [ ] Run state tests and hierarchical Gold tests.

### Task 6: Add NGFW-realistic state features and protocol context

**Files:**
- Modify: `remote-admin-anomaly-lab/src/adminlab/session_gold.py`
- Modify: `remote-admin-anomaly-lab/src/adminlab/online_features.py`
- Modify: `remote-admin-anomaly-lab/configs/v3_feature_contract.yaml`
- Create: `remote-admin-anomaly-lab/tests/test_v3_train_serve_parity.py`

**Interfaces:**
- Produces: identical offline/online values for pair recency, source/destination prevalence, protocol familiarity, new-edge counts/ratios and protocol-switch features.

- [ ] Add parity tests that replay the same ordered EVE-like sequence through offline and online state paths.
- [ ] Implement missing rolling features using only prior events.
- [ ] Permit `protocol`/`app_proto` as categorical context while adding a protocol-only shortcut audit.
- [ ] Keep raw IPs/host IDs forbidden from model matrices.
- [ ] Run parity and leakage tests.

### Task 7: Make shortcut audit estimator-identical

**Files:**
- Modify: `remote-admin-anomaly-lab/src/adminlab/v3_modeling.py`
- Modify: `remote-admin-anomaly-lab/scripts/train_v3_models.py`
- Test: `remote-admin-anomaly-lab/tests/test_v3_causal_signal.py`

**Interfaces:**
- Produces: full and ablation PR-AUC values trained with the same LightGBM pipeline/hyperparameters/seed.

- [ ] Add a test asserting all shortcut baselines use the same estimator factory as the full model.
- [ ] Add `protocol_only` and prevalence/random references.
- [ ] Reuse the production LightGBM pipeline for every ablation.
- [ ] Report full-over-best-nuisance and history-over-prevalence margins.

### Task 8: Update gates, docs and status

**Files:**
- Modify: `remote-admin-anomaly-lab/src/adminlab/v3_gate.py`
- Modify: `remote-admin-anomaly-lab/configs/v3_research.yaml`
- Modify: `remote-admin-anomaly-lab/FINAL_STATUS.md`
- Modify: `remote-admin-anomaly-lab/PLAN.md`
- Modify: `.github/workflows/remote-admin-v3-contract.yml`
- Modify: `.github/workflows/remote-admin-v3-research-release.yml`

**Interfaces:**
- Produces: fail-closed 1k promotion thresholds and accurate V3 documentation.

- [ ] Add causal-observability, source-diversity, pair-history-separation, split-state and parity gates.
- [ ] Set 1k research promotion thresholds from the design spec.
- [ ] Fix stale V1 text in `FINAL_STATUS.md`.
- [ ] Document the old V3 release as a retained negative/control snapshot until corrected V3 verifies.

### Task 9: Verify contracts and regenerate corrected V3-1k

**Files:**
- No new source files unless verification exposes a defect.

**Interfaces:**
- Consumes all prior tasks; produces a new immutable corrected V3 release only if all gates pass.

- [ ] Run full pytest suite in GitHub Actions.
- [ ] Run topology/planner smoke gate.
- [ ] Run a small 40-session end-to-end real-wire gate and inspect mapping/parity/causal audits.
- [ ] Run corrected V3 1k research release only after the small gate is green.
- [ ] Verify Bronze/Silver/Gold/checksums/HF persistence and exact source-diversity/pair-history contracts.
- [ ] Accept the corrected V3 only if the scientific gates pass; otherwise retain the artifact as another explicit negative result and do not scale to 4k.
