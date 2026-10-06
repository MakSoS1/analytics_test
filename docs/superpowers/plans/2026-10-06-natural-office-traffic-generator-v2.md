# Natural Office Traffic Generator v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a universal research generator that creates labelled scenario/control network sessions through real client protocol stacks, calibrates benign runtime mixtures against committed office reference data, freezes that calibration before scenario generation, composes validated captures into retained office background, and emits reproducible naturalness/technique-signal reports and GitHub Actions artifacts.

**Architecture:** Add a focused `natural_traffic` package beside the existing `office_injection` and `cover_runtime` code. The package owns runtime-profile contracts, benign-only calibration, frozen profile manifests, managed/external adapters, evaluation gates, and workflow orchestration; existing feature extractors and office composition code are reused through narrow interfaces. GitHub Actions runs cheap validation on PRs and a manual full pipeline for real-stack capture, calibration, scenario generation, evaluation, and release packaging.

**Tech Stack:** Python 3.12, pandas, PyArrow, NumPy, scikit-learn, existing office/Arkime extractors, Linux network namespaces/tcpdump/curl/Chromium/protocol-native clients where available, GitHub Actions Ubuntu and Windows runners.

**Spec:** `docs/superpowers/specs/2026-10-06-natural-office-traffic-generator-design.md`

## Global Constraints

- Scenario rows must never influence naturalness calibration, runtime-profile selection, feature masking, path parameters, or naturalness thresholds.
- Generated packet bytes, TCP/TLS bytes, packet sizes, and packet ordering must not be rewritten after capture to improve naturalness metrics.
- The committed pseudonymized office dataset under `cover-channel-lab/research-transfer/datasets/office-cover-20261006/` is immutable input.
- Identifiers, labels, provenance, split assignment, and pseudonymization tokens must never enter model X.
- Repeated placement of one source capture is never an independent evaluation group.
- Unsupported runtime capabilities must be explicit; Windows failure must not silently fall back to Linux.
- Office rows remain unlabeled; the pipeline never assumes all office traffic is benign.
- A naturalness result below support thresholds is `insufficient_data`, never `passed_candidate`.
- Full GitHub Actions corpus jobs are manual; pull requests run validation/unit tests only.
- No private key, HMAC key, decrypted dictionary, raw private office PCAP, or site-specific deployment secret may be committed.
- Hosted-runner capture jobs must reserve at least 15 GiB free disk and bound scratch usage.
- The implementation must not modify production NDR detector behavior.

## Review Focus

1. **Calibration leakage:** any scenario row becoming visible to profile selection must fail closed. Covered in Task 2.
2. **Group leakage:** repeated/source-related executions crossing train/confirmation must be detected and rejected. Covered in Task 2.
3. **Capture post-processing:** any managed adapter attempting to rewrite captured packet bytes must fail integrity verification. Covered in Task 3.
4. **Capability substitution:** an unsupported Windows capture path must report unsupported rather than execute a Linux substitute. Covered in Task 3.
5. **Naturalness false-pass:** tiny classes, missing classes, or uninformative diagnostics must return `insufficient_data`/error rather than chance AUC success. Covered in Task 2.

---

## File Structure

New package:

- `cover-channel-lab/research-transfer/code/natural_traffic/__init__.py` — public package exports.
- `cover-channel-lab/research-transfer/code/natural_traffic/contracts.py` — dataclasses/protocols for profiles, activities, capture bundles and frozen manifests.
- `cover-channel-lab/research-transfer/code/natural_traffic/profiles.py` — runtime profile registry and deterministic profile manifests.
- `cover-channel-lab/research-transfer/code/natural_traffic/reference.py` — immutable committed dataset loading/verification and feature-column policy.
- `cover-channel-lab/research-transfer/code/natural_traffic/calibration.py` — benign-only train calibration, mixture selection and freeze.
- `cover-channel-lab/research-transfer/code/natural_traffic/evaluation.py` — grouped C2ST, distribution-family gates, negative controls and technique-signal evaluation.
- `cover-channel-lab/research-transfer/code/natural_traffic/capture.py` — managed capture execution interface, disk/resource guards and artifact hashing.
- `cover-channel-lab/research-transfer/code/natural_traffic/adapters.py` — adapter registry, generic external import adapter and Cover Channel managed adapter.
- `cover-channel-lab/research-transfer/code/natural_traffic/composition.py` — narrow wrapper over existing office composition/extraction.
- `cover-channel-lab/research-transfer/code/natural_traffic/cli.py` — validate/calibrate/confirm/generate/evaluate/package commands.
- `cover-channel-lab/research-transfer/code/natural_traffic/reporting.py` — stable JSON/Markdown reports and release manifest.
- `cover-channel-lab/research-transfer/code/natural_traffic/windows_probe.ps1` — Windows capture capability probe.
- `.github/workflows/natural-office-traffic-v2.yml` — PR validation and manual full workflow.

Tests live in `cover-channel-lab/research-transfer/code/tests/`.

### Task 1: Contracts, profile registry, and immutable reference dataset

**Files:**
- Create: `cover-channel-lab/research-transfer/code/natural_traffic/__init__.py`
- Create: `cover-channel-lab/research-transfer/code/natural_traffic/contracts.py`
- Create: `cover-channel-lab/research-transfer/code/natural_traffic/profiles.py`
- Create: `cover-channel-lab/research-transfer/code/natural_traffic/reference.py`
- Create: `cover-channel-lab/research-transfer/code/tests/test_natural_contracts.py`
- Create: `cover-channel-lab/research-transfer/code/tests/test_natural_reference.py`

**Interfaces:**
- Produces `RuntimeProfile`, `ActivityDescriptor`, `GenerationContext`, `CaptureBundle`, `FrozenProfileManifest`.
- Produces `ProfileRegistry` with deterministic `resolve(profile_id)` and `manifest(profile_ids, seed)`.
- Produces `load_reference(root: Path) -> ReferenceDataset`.
- Produces `model_feature_columns(df, dictionary) -> list[str]` and rejects metadata/labels/tokens.

- [ ] **Step 1: Write failing contract tests**
  - Assert deterministic manifest SHA for identical profile list/seed.
  - Assert scenario/control contexts expose identical environment fields for one pair.
  - Assert undeclared runtime/profile IDs are rejected.
  - Assert arbitrary shell command fields are not part of the managed adapter contract.

- [ ] **Step 2: Run contract tests and verify RED**
  - Run: `cd cover-channel-lab/research-transfer && PYTHONPATH=code python -m unittest code.tests.test_natural_contracts -v`
  - Expected: import/module failures because `natural_traffic` does not yet exist.

- [ ] **Step 3: Implement contracts and profile registry**
  - Add frozen dataclasses/protocols.
  - Register initial profile IDs: `linux-python-ssl`, `linux-curl`, `linux-chromium`, `linux-protocol-native`, `windows-native-http`.
  - Profile manifests include OS family, implementation, protocol capabilities, capture type, resource budget and capability requirement.

- [ ] **Step 4: Run contract tests and verify GREEN**

- [ ] **Step 5: Write failing reference-data tests**
  - Verify all required Parquet names exist.
  - Verify expected row/column counts from the committed dataset README.
  - Verify hashes against `DATA_MANIFEST.json` where entries are available.
  - Verify model feature selection excludes labels, provenance, IDs and pseudonymized string tokens.
  - Verify dictionary decryption is not required for numeric evaluation.

- [ ] **Step 6: Run reference tests and verify RED**

- [ ] **Step 7: Implement reference loader and feature policy**

- [ ] **Step 8: Run both Task 1 test modules and verify GREEN**

- [ ] **Step 9: Commit**
  - Commit message: `feat: add natural traffic contracts and reference loader`

### Task 2: Benign-only calibration, grouped evaluation, and freeze lifecycle

**Files:**
- Create: `cover-channel-lab/research-transfer/code/natural_traffic/calibration.py`
- Create: `cover-channel-lab/research-transfer/code/natural_traffic/evaluation.py`
- Create: `cover-channel-lab/research-transfer/code/tests/test_natural_calibration.py`
- Create: `cover-channel-lab/research-transfer/code/tests/test_natural_evaluation.py`

**Interfaces:**
- Consumes Task 1 `ReferenceDataset`, `RuntimeProfile`, `FrozenProfileManifest`.
- Produces `calibrate_profiles(office_train, benign_controls_train, groups, registry, seed) -> FrozenProfileManifest`.
- Produces `confirm_naturalness(manifest, office_confirm, benign_confirm, groups) -> NaturalnessReport`.
- Produces `evaluate_technique_signal(manifest, scenario, control, pair_groups) -> TechniqueSignalReport`.

- [ ] **Step 1: Write failing leakage and support tests**
  - Scenario rows passed to calibration raise `CalibrationLeakageError`.
  - One ancestor appearing on both train and confirmation raises `GroupLeakageError`.
  - Missing class, fewer than 30 independent groups, or only duplicated placements yields `insufficient_data`.
  - Frozen manifest mutation or hash mismatch makes confirmation fail closed.

- [ ] **Step 2: Run tests and verify RED**

- [ ] **Step 3: Implement grouped split validation and freeze lifecycle**

- [ ] **Step 4: Write failing C2ST tests**
  - Synthetic identical distributions produce near-chance point estimates but cannot pass with insufficient group support.
  - Injected origin artifact is detected by all/most diagnostics.
  - Same-office random cohorts remain near chance.
  - Missingness-only source artifact remains visible to diagnostics.

- [ ] **Step 5: Run tests and verify RED**

- [ ] **Step 6: Implement C2ST and cluster bootstrap**
  - Predeclared models: balanced HGB, ExtraTrees, logistic regression.
  - Use group-disjoint confirmation only.
  - Emit point AUC, cluster-bootstrap CI, group counts and support status.

- [ ] **Step 7: Write failing distribution-family tests**
  - Compare generated-control family distances to office-vs-office reference distances.
  - Require >=90% measurable families under reference p95 and no family >1.5x threshold.
  - Preserve missingness as a reported signal.

- [ ] **Step 8: Implement distribution-family gate**

- [ ] **Step 9: Write failing mixture-selection tests**
  - Selection reads only benign train controls and office train.
  - Simpler profile mixture wins ties.
  - Same input/seed produces byte-identical frozen manifest.
  - Confirmation cannot re-optimize profile weights.

- [ ] **Step 10: Implement deterministic benign profile-mixture calibration**

- [ ] **Step 11: Write and implement technique-signal tests**
  - Naturalness must already be `passed_candidate`.
  - Scenario/control pairs remain grouped.
  - Training eligibility requires integrity/fidelity plus signal.
  - A failed signal gate marks the technique ineligible without invalidating the generator.

- [ ] **Step 12: Run full Task 2 tests and verify GREEN**

- [ ] **Step 13: Commit**
  - Commit message: `feat: add benign calibration and naturalness gates`

### Task 3: Real-stack capture engine and capability probes

**Files:**
- Create: `cover-channel-lab/research-transfer/code/natural_traffic/capture.py`
- Create: `cover-channel-lab/research-transfer/code/natural_traffic/windows_probe.ps1`
- Create: `cover-channel-lab/research-transfer/code/tests/test_natural_capture.py`
- Modify only through wrappers as needed: existing `cover_runtime` launch helpers; do not rewrite pinned upstream source.

**Interfaces:**
- Consumes Task 1 runtime profiles and generation contexts.
- Produces `probe_capability(profile) -> CapabilityReport`.
- Produces `run_capture(profile, adapter, context) -> CaptureBundle`.
- CaptureBundle hashes immutable PCAP/evidence/runtime metadata.

- [ ] **Step 1: Write failing resource/capability tests**
  - Refuse work below 15 GiB free.
  - Scratch cap is enforced per shard.
  - Unsupported Windows capture returns `supported=false` with reason.
  - Windows unsupported path never resolves to Linux profile.
  - Failed runs retain manifest/log metadata.

- [ ] **Step 2: Run tests and verify RED**

- [ ] **Step 3: Implement capability/resource guards**

- [ ] **Step 4: Write failing capture-integrity tests**
  - PCAP SHA is pinned immediately after capture.
  - Extraction input must match pinned PCAP SHA.
  - Any modified packet bytes after capture are rejected.
  - Scenario/control pair manifests show equal environment/profile identity.
  - Managed capture output is non-empty and parseable.

- [ ] **Step 5: Run tests and verify RED**

- [ ] **Step 6: Implement Linux managed capture execution**
  - Provide bounded execution for Python SSL, curl, Chromium and protocol-native profiles.
  - Use isolated namespaces/fixtures where the existing runtime already supports them.
  - Do not add packet-morphing stages.

- [ ] **Step 7: Implement Windows capability probe**
  - Probe runner/native capture availability and emit machine-readable report.
  - Only enable Windows generation when probe explicitly passes.

- [ ] **Step 8: Run Task 3 unit tests and Linux integration smoke**
  - Integration expected to produce one paired HTTPS capture with verified SHA/evidence.

- [ ] **Step 9: Commit**
  - Commit message: `feat: add real stack capture engine and probes`

### Task 4: Universal adapters and Cover Channel integration

**Files:**
- Create: `cover-channel-lab/research-transfer/code/natural_traffic/adapters.py`
- Create: `cover-channel-lab/research-transfer/code/tests/test_natural_adapters.py`
- Modify: `cover-channel-lab/research-transfer/code/office_injection/activity.py` only if required for a narrow compatibility hook.
- Read/reuse: `cover-channel-lab/research-transfer/code/cover_runtime/registry.json`, `native_registry.json`, existing source pins.

**Interfaces:**
- Produces explicit adapter registry.
- Produces `ExternalActivityAdapter` for `activity.json`.
- Produces `CoverChannelAdapter` that maps supported Coverlab entries to managed capture profiles without changing scenario IDs/source pins.
- Adapter APIs return Task 1 `CaptureBundle`.

- [ ] **Step 1: Write failing registry/safety tests**
  - Unknown adapter name rejected.
  - Dataset metadata cannot inject executable shell commands.
  - External adapter validates PCAP/evidence hashes and preserves external origin label.
  - Cover Channel adapter distinguishes wire-real, semantic fixture, visibility-only and unsupported fidelity.

- [ ] **Step 2: Run tests and verify RED**

- [ ] **Step 3: Implement adapter registry and external import compatibility**

- [ ] **Step 4: Write failing Cover Channel mapping tests**
  - Preserve current scenario IDs.
  - Supported H1/H2/H3/WSS/gRPC/MQTT entries resolve only to profiles declaring those capabilities.
  - Unsupported profile/mechanism combination yields explicit unsupported, never an approximation labelled wire-real.
  - Scenario/control runtime profile identity is equal.

- [ ] **Step 5: Implement Cover Channel managed adapter**

- [ ] **Step 6: Run Task 4 tests and verify GREEN**

- [ ] **Step 7: Commit**
  - Commit message: `feat: integrate universal and cover channel adapters`

### Task 5: Office composition, full feature extraction, and end-to-end pipeline

**Files:**
- Create: `cover-channel-lab/research-transfer/code/natural_traffic/composition.py`
- Create: `cover-channel-lab/research-transfer/code/tests/test_natural_composition.py`
- Reuse: existing `office_injection`, `prepare_arkime_inputs.py`, Arkime wrappers and lab pipeline.
- Do not modify committed reference Parquet.

**Interfaces:**
- Consumes validated CaptureBundles and frozen profile manifest.
- Produces clean/control/scenario alternative compositions.
- Produces pipeline feature Parquet, Arkime feature Parquet where available, strict-match table, memberships and evaluation-ready metadata.

- [ ] **Step 1: Write failing composition integrity tests**
  - Office packet rows remain byte-identical.
  - Generated capture bytes remain unchanged.
  - Endpoint collisions are rejected.
  - Source duration is not compressed.
  - Neighboring office sessions remain unlabeled.
  - Positive/control membership joins only exact generated sessions.

- [ ] **Step 2: Run tests and verify RED**

- [ ] **Step 3: Implement composition wrapper over existing validated paths**

- [ ] **Step 4: Write failing extraction tests**
  - Pipeline extraction exposes the full feature schema rather than the old 89-X research subset.
  - Arkime comparison preserves emitted fields and presence mask.
  - Labels/provenance remain separate from X.
  - Strict pipeline↔Arkime matching preserves direction caveats.

- [ ] **Step 5: Implement extraction orchestration**

- [ ] **Step 6: Add end-to-end fixture test**
  - One managed HTTPS pair: frozen profile → capture → composition → pipeline extraction → naturalness/technique evaluation report.
  - Verify all artifact hashes and ancestor/group metadata.

- [ ] **Step 7: Run Task 5 tests and verify GREEN**

- [ ] **Step 8: Commit**
  - Commit message: `feat: compose generated captures with office background`

### Task 6: CLI, reports, and GitHub Actions workflow

**Files:**
- Create: `cover-channel-lab/research-transfer/code/natural_traffic/cli.py`
- Create: `cover-channel-lab/research-transfer/code/natural_traffic/reporting.py`
- Create: `cover-channel-lab/research-transfer/code/tests/test_natural_cli.py`
- Create: `.github/workflows/natural-office-traffic-v2.yml`

**Interfaces:**
- CLI subcommands: `validate-reference`, `probe`, `generate-benign`, `calibrate`, `confirm`, `generate-scenarios`, `evaluate-techniques`, `compose`, `package`.
- Stable report schemas for capability, frozen manifest, naturalness, technique eligibility and release.

- [ ] **Step 1: Write failing CLI/report tests**
  - Every command has `--help`.
  - Reports are deterministic JSON with explicit version/status/support counts.
  - Packaging excludes private/decrypted/sensitive paths.
  - Confirmation rejects missing or mismatched frozen manifest SHA.

- [ ] **Step 2: Run tests and verify RED**

- [ ] **Step 3: Implement CLI and reports**

- [ ] **Step 4: Write workflow structure test**
  - PR jobs include reference validation and unit tests only.
  - Full generation jobs require `workflow_dispatch`.
  - Linux and Windows capability probes are distinct.
  - Scenario generation depends on successful freeze/confirmation.
  - Artifact upload precedes scratch cleanup.
  - Resource guard invoked before capture.

- [ ] **Step 5: Implement GitHub Actions workflow**
  - Jobs: `validate-reference-data`, `unit-tests`, `capture-probe-linux`, `capture-probe-windows`, `generate-benign-matrix`, `calibrate-profile-mixture`, `confirm-naturalness`, `generate-cover-scenarios`, `evaluate-technique-signal`, `package-release`.
  - Full jobs are conditional on manual dispatch.
  - Support profile/technique filters.

- [ ] **Step 6: Run Task 6 tests and YAML validation**

- [ ] **Step 7: Commit**
  - Commit message: `ci: add natural traffic generator workflow`

### Task 7: Documentation, example reports, full verification, and cleanup

**Files:**
- Create: `cover-channel-lab/research-transfer/docs/NATURAL_TRAFFIC_GENERATOR_V2.md`
- Modify: `cover-channel-lab/research-transfer/README.md`
- Modify: `cover-channel-lab/research-transfer/docs/UNIVERSAL_IMPORT.md`
- Modify: `cover-channel-lab/research-transfer/docs/RUNNING.md`
- Create only if generated by verified commands: `cover-channel-lab/research-transfer/examples/natural-traffic-v2/` machine-readable example manifests/reports.

**Interfaces:**
- Documentation shows how to add another technique adapter and how to import an external scenario/control pair.
- Documentation distinguishes generator correctness, `passed_candidate` naturalness and production transfer.

- [ ] **Step 1: Write documentation regression checks**
  - Every documented CLI command resolves to an implemented subcommand.
  - No docs claim `production_ready=true`.
  - No docs claim all office traffic is benign.
  - No private/decryption paths are included in examples.

- [ ] **Step 2: Update documentation and examples from actual verified outputs**

- [ ] **Step 3: Run complete standalone test suite**
  - Run: `cd cover-channel-lab/research-transfer && PYTHONPATH=code python -m unittest discover -s code/tests -v`
  - Expected: 0 failures/errors.

- [ ] **Step 4: Run syntax/import verification**
  - Run compileall on new package and existing research-transfer code.
  - Run every new CLI `--help`.

- [ ] **Step 5: Run reference-data verification**
  - Expected committed shapes/hashes and no dictionary decryption requirement.

- [ ] **Step 6: Run local Linux end-to-end smoke**
  - At least one real paired HTTPS capture must complete through evaluation.

- [ ] **Step 7: Push branch and run GitHub Actions PR-validation jobs**

- [ ] **Step 8: Run manual full GitHub Actions workflow**
  - Collect terminal statuses and artifacts.
  - If a capability is unsupported, verify explicit unsupported status rather than fallback.

- [ ] **Step 9: Inspect naturalness result**
  - If `passed_candidate`: verify support and confidence gates independently from raw report.
  - If `not_passed`: identify dominant separating families/profiles from the report; return to the earliest responsible task under systematic debugging rather than lowering thresholds.
  - If `insufficient_data`: generate additional benign controls with the already frozen rules until minimum independent support is met, within runner/disk budgets.

- [ ] **Step 10: Run final whole-branch verification and review**
  - Confirm all spec acceptance criteria.
  - Confirm no secrets/private material in diff.
  - Confirm reference dataset unchanged.

- [ ] **Step 11: Commit documentation/final verified artifacts**
  - Commit message: `docs: finalize natural traffic generator v2`

## Completion Contract

The plan is complete only when:

- Tasks 1–7 are complete with fresh test evidence.
- A real Linux managed capture has passed end-to-end.
- The new GitHub Actions workflow reaches terminal status for PR validation and one manual full run.
- The generated corpus receives one of the explicit statuses from the spec; no threshold is weakened after seeing confirmation results.
- At least one Cover Channel technique is evaluated end-to-end through a frozen benign-calibrated profile.
- No private material is present in git.
- The final branch review has no unaddressed Critical/Important findings.
