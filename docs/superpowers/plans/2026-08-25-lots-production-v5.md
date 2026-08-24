# LOTS Production v5 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify a catalog-complete, production-oriented LOTS detector release with safe traffic generation, locked holdout metrics, hardened streaming runtime, and deterministic SOC bundle.

**Architecture:** Normalize the 175-entry LOTS Project catalog into safe scenario families; generate real read-only traffic plus controlled write/exfil/C2 emulation; reject data before training unless packet/EVE/mechanism QC passes; retrain a service-agnostic fast+window cascade with minimum evidence; validate on campaign/service/provider/evasion/background splits; harden budget and ingestion; package only if measured release gates are satisfied.

**Tech Stack:** Python 3.12, pandas/numpy/scikit-learn, LightGBM, Suricata 7/8 EVE JSON, tcpdump/Wireshark CLI, GitHub Actions ubuntu-24.04, pytest/unittest-compatible regression tests.

**Spec:** `docs/superpowers/specs/2026-08-25-lots-production-v5-design.md`

## Global Constraints

- No malware, phishing, credential theft, or real third-party exfiltration.
- Public services are read-only unless a documented harmless endpoint is explicitly created for the experiment; write-side attack mechanics default to controlled TLS emulation.
- Phishing-only LOTS entries are hard negatives/context, never LOTS-positive by domain membership.
- Gold accepts only exact/high-confidence action↔flow matches; ambiguous/unmatched never train.
- Service identity, scenario_role, JA3/JA4, and generator/client identity may not act as direct maliciousness features.
- Locked test is fixed before model selection; 0.95 targets are evaluated only on locked data.
- Safety-floor alerts are never suppressed by ordinary alert budget.
- Native Suricata EVE JSON Lines remains the runtime input contract.

---

### Task 1: Catalog snapshot and safe scenario compiler

**Files:**
- Create: `lots-v5/catalog/lots_project_2026-08-25.csv`
- Create: `lots-v5/catalog/scenario_policy.yaml`
- Create: `lots-v5/src/catalog.py`
- Create: `lots-v5/tests/test_catalog.py`

**Interfaces:**
- Produces `load_catalog(path) -> list[CatalogEntry]`.
- Produces `compile_scenarios(entries, policy) -> list[ScenarioSpec]` with fields `scenario_id, domain_pattern, provider, mechanism, label, generation_mode, timing_profile, payload_profile, pair_id`.

- [ ] Write tests requiring exactly 175 unique catalog entries, normalized tag sets, no LOTS-positive scenario for phishing-only entries, and paired benign twins for every positive mechanism.
- [ ] Run tests and confirm failure before implementation.
- [ ] Implement typed catalog parsing and scenario compilation.
- [ ] Run tests and require all catalog/pair invariants to pass.
- [ ] Emit `coverage.json` with counts by provider/tag/mechanism/generation_mode.

### Task 2: Safe traffic generator and three-stage QC

**Files:**
- Create: `lots-v5/src/generate.py`
- Create: `lots-v5/src/local_tls_harness.py`
- Create: `lots-v5/src/qc.py`
- Create: `lots-v5/tests/test_qc.py`
- Create: `.github/workflows/lots-v5-corpus.yml`

**Interfaces:**
- `run_scenario(spec, out_dir) -> ActionManifest`.
- `validate_contract(manifest) -> QCResult`.
- `validate_eve(manifest, eve_path) -> QCResult`.
- `validate_mechanism(manifest, canonical_flows) -> QCResult`.

- [ ] Write failing QC tests for mixed-label windows, missing TLS/flow pairs, wrong SNI, checksum-offload replay, timing mismatch, upload/download direction mismatch, and stale retry contamination.
- [ ] Implement a deterministic local TLS harness for C2/write/exfil mechanics and a read-only public probe runner for safe domains.
- [ ] Implement GitHub Actions sharding and artifact retention (PCAP, raw EVE, filtered EVE, action manifests, QC report).
- [ ] Require three QC gates before a shard is accepted.
- [ ] Run at least three independent pilot iterations (GitHub, Rentry/paste family, cloud/object-storage family) and compare measured flow shape to declared mechanism before scaling.

### Task 3: Gold builder and locked split protocol

**Files:**
- Create: `lots-v5/src/build_gold.py`
- Create: `lots-v5/src/splits.py`
- Create: `lots-v5/tests/test_splits.py`
- Create: `lots-v5/data/SPLIT_MANIFEST.json`

**Interfaces:**
- `build_gold(accepted_manifests, eve_files) -> DataFrame`.
- `make_locked_splits(df, seed) -> SplitManifest`.

- [ ] Test that campaign IDs never cross train/validation/test.
- [ ] Test service-disjoint and provider-disjoint folds truly exclude held-out identities.
- [ ] Test no scenario-role/client-stack/service string leaks into model features.
- [ ] Freeze split manifest before training/model selection.

### Task 4: Feature and cascade redesign

**Files:**
- Modify/copy from current source: `lots-v5/runtime/features.py`, `lots-v5/runtime/multiscale.py`
- Create: `lots-v5/src/train_fast.py`
- Create: `lots-v5/src/train_window.py`
- Create: `lots-v5/tests/test_fast_evidence_gate.py`
- Create: `lots-v5/tests/test_feature_contract.py`

**Interfaces:**
- Fast inference returns `eligible_for_alert: bool` and cannot be alert-eligible with fewer than 3 correlated connections unless deterministic repeated coupling evidence is present.
- Window inference consumes completed 1200-second windows and returns calibrated logit/probabilities plus local contributions.

- [ ] Reproduce the previous GitHub/Rentry one-GET pathology as a failing regression test.
- [ ] Add minimum-evidence features/gate and verify one harmless GET remains watch-only without extreme alert-grade treatment.
- [ ] Keep all shape features defined for one connection but separate score eligibility from feature computability.
- [ ] Train candidate generalist LightGBM models; compare optional coarse provider-family expert routing only on provider-disjoint validation.
- [ ] Select by locked-validation policy, never by locked test.

### Task 5: Evaluation and threshold/safety-floor selection

**Files:**
- Create: `lots-v5/src/evaluate.py`
- Create: `lots-v5/src/calibrate_release.py`
- Create: `lots-v5/reports/MODEL_CARD.md`
- Create: `lots-v5/reports/metrics.json`

**Interfaces:**
- `evaluate_all(...)` reports incident precision/recall/F1, service LOSO, provider holdout, evasion slices, background alerts/1k-host-day with denominator confidence, latency, and calibration sufficiency.

- [ ] Evaluate locked campaign-disjoint test once per finalized candidate.
- [ ] Evaluate LOSO and provider-disjoint folds.
- [ ] Evaluate evasion families separately (jitter, low volume, distributed services, session reuse).
- [ ] Compute safety floor from held-out known attacks, not training attacks.
- [ ] Refuse to claim 5 alerts/1k-host-day when background host-hours are insufficient for stable quantile estimation.
- [ ] Mark release PROD_READY only if all mandatory measured gates pass; otherwise SHADOW_READY with exact blockers.

### Task 6: Runtime hardening

**Files:**
- Modify/copy: `lots-v5/runtime/eve_stream.py`
- Modify/copy: `lots-v5/runtime/infer.py`
- Modify/copy: `lots-v5/runtime/runtime_state.py`
- Modify/copy: `lots-v5/runtime/soc_runner.py`
- Create: `lots-v5/tests/test_budget.py`
- Create: `lots-v5/tests/test_rotation.py`
- Create: `lots-v5/tests/test_incident_lifecycle.py`

**Interfaces:**
- Ordinary alert budget is a persisted token bucket/sliding allowance and may yield zero ordinary alerts per tick.
- Safety-floor alerts bypass ordinary budget.
- EVE rotation tracks inode/path and drains the readable old tail when available; offline completed-file replay is deterministic.

- [ ] Write failing test proving old min-one-per-tick implementation violates 5/day budget.
- [ ] Implement persisted token-bucket budget using actual elapsed wall time/host denominator.
- [ ] Add rotation/truncation regression tests and safe behavior.
- [ ] Verify incident dedup, watch→confirmed→resolved transitions, and state persistence on long replay.

### Task 7: End-to-end real Suricata validation

**Files:**
- Create: `.github/workflows/lots-v5-e2e.yml`
- Create: `lots-v5/tests/e2e_assert.py`
- Create: `lots-v5/examples/`

**Interfaces:**
- Workflow performs capture/emulation → PCAP → Suricata → native EVE → streaming runtime → assertions.

- [ ] Validate shipped Suricata config with `suricata -T`.
- [ ] Run representative C2, dead-drop, download, exfil, hard-negative, unseen-service, no-SNI, and evasion samples.
- [ ] Compare offline and streaming feature parity.
- [ ] Run multiple iterations with different seeds/client profiles; reject non-reproducible detections.

### Task 8: SOC bundle and release audit

**Files:**
- Create/modify: `lots-v5/build_soc_bundle.py`
- Create: `lots-v5/SOC_RUNBOOK_RU.md`
- Create: `lots-v5/CALIBRATION.md`
- Create: `lots-v5/release_audit.py`
- Produce: `lots_ngfw_soc_2026-08-25_v5.tar.gz`

**Interfaces:**
- Bundle contains runtime, model artifacts, configs, examples, docs, VERSION.json and MANIFEST.sha256; excludes training data, secrets, developer paths, PCAP and research-only code.

- [ ] Run full unit/regression/e2e test suite.
- [ ] Run manifest/secret/path/training-data audit.
- [ ] Build bundle twice and compare SHA-256 for determinism.
- [ ] Smoke-run bundled `soc_runner.py` on included native EVE example.
- [ ] Verify MODEL_CARD status exactly matches measured gates.
- [ ] Publish workflow/source changes to `lots-prod-v5-20260825` and provide the generated SOC archive to the user.
