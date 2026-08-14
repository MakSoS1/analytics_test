# Remote Admin Anomaly Lab V2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and validate a mixed-environment V2 remote-administration anomaly dataset with richer counterfactual behavior, causal session/campaign Gold, a native-Windows external holdout, an independent LANL reference slice, and a fail-closed 1k research gate.

**Architecture:** V1 remains immutable baseline evidence. Environment A (Linux lab) supplies the only training rows; Environment B (GitHub Windows native stack) and Environment C (LANL public enterprise reference) are evaluation-only. The primary V2 model consumes causal session-level features, with flow and campaign models retained for comparison.

**Tech Stack:** Python 3.12, pandas, pyarrow, scikit-learn, LightGBM, Suricata, Zeek, Bash, PowerShell, Windows `pktmon`, GitHub Actions, Hugging Face Hub.

## Global Constraints

- No 4k/10k/201k scaling before the V2 1k gate passes.
- Windows rows and LANL rows are external holdouts and must never train/tune the primary model.
- No synthetic fallback may be labelled `native_windows_validated`.
- Flow/session/campaign features must be causal and network/NGFW-compatible; scenario IDs, campaign IDs, implementation IDs, environment IDs and generator controls are forbidden model inputs.
- V2 1k primary acceptance: validation PR-AUC >= 0.65, test PR-AUC >= 0.60, challenge campaign recall at <=1% FPR > 0, hard-benign FPR <= 0.05, full model beats best nuisance-only baseline by >= 0.05.
- LANL is reference-only and may not be used for threshold tuning.
- Complete Bronze is retained before optional Hugging Face upload.

---

### Task 1: V2 CI hygiene and contracts

**Files:**
- Create: `.github/legacy/remote-admin-research-gate-v1.yml.disabled`
- Delete: `.github/workflows/remote-admin-research-gate.yml`
- Create: `.github/workflows/remote-admin-v2-contract.yml`
- Create: `remote-admin-anomaly-lab/tests/test_v2_contract.py`
- Create: `remote-admin-anomaly-lab/configs/v2_research.yaml`

**Interfaces:**
- Consumes: existing V1 branch contents.
- Produces: V2-only workflow paths and `configs/v2_research.yaml` with thresholds/source metadata.

- [ ] **Step 1: Write the failing V2 contract test**

```python
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_v2_research_config_is_fail_closed():
    cfg = yaml.safe_load((ROOT / "configs/v2_research.yaml").read_text())
    assert cfg["sessions"] == 1000
    assert cfg["validation_pr_auc_min"] == 0.65
    assert cfg["test_pr_auc_min"] == 0.60
    assert cfg["shortcut_margin_min"] == 0.05
    assert cfg["windows_external_only"] is True
    assert cfg["lanl_external_only"] is True


def test_legacy_v1_research_workflow_is_not_active():
    repo = ROOT.parent
    assert not (repo / ".github/workflows/remote-admin-research-gate.yml").exists()
    assert (repo / ".github/legacy/remote-admin-research-gate-v1.yml.disabled").exists()
```

- [ ] **Step 2: Run the test and verify RED**

Run: `PYTHONPATH=src pytest -q tests/test_v2_contract.py`
Expected: FAIL because V2 config/archive do not exist and legacy workflow is active.

- [ ] **Step 3: Add the config and V2 workflow**

`configs/v2_research.yaml` must contain:

```yaml
schema_version: 2
sessions: 1000
validation_pr_auc_min: 0.65
test_pr_auc_min: 0.60
shortcut_margin_min: 0.05
hard_benign_fpr_max: 0.05
challenge_recall_at_fpr_1pct_min_exclusive: 0.0
learning_curve_delta_for_scale: 0.005
windows_external_only: true
lanl_external_only: true
hf_repo: Maksim123321/remote-admin-anomaly-v1
hf_candidate_prefix: v2/candidates
hf_quarantine_prefix: v2/quarantine
lanl:
  dataset: Unified Host and Network Data Set
  year: 2017
  netflow_day: 2
  netflow_url: https://csr.lanl.gov/data-fence//unified-host-network-dataset-2017/netflow/netflow_day-02.bz2
  host_url: https://csr.lanl.gov/data-fence//unified-host-network-dataset-2017/wls/wls_day-02.bz2
  remote_admin_ports: [22, 135, 445, 3389, 5985, 5986]
```

V2 contract workflow runs `pytest -q tests` only on branch `remote-admin-anomaly-lab-v2` and V2 paths.

- [ ] **Step 4: Re-run contract test**

Run: `PYTHONPATH=src pytest -q tests/test_v2_contract.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add .github remote-admin-anomaly-lab/configs/v2_research.yaml remote-admin-anomaly-lab/tests/test_v2_contract.py
git commit -m "ci(remote-admin): isolate V2 workflows and archive V1 gate"
```

---

### Task 2: Counterfactual V2 scenario semantics

**Files:**
- Create: `remote-admin-anomaly-lab/configs/v2_campaigns.yaml`
- Create: `remote-admin-anomaly-lab/src/adminlab/v2_scenarios.py`
- Create: `remote-admin-anomaly-lab/tests/test_v2_scenarios.py`
- Modify: `remote-admin-anomaly-lab/scripts/check_scenario_quality.py`

**Interfaces:**
- Produces: `build_v2_semantic_plan(records: list[SessionRecord], seed: int) -> list[SessionRecord]`.
- Required fields are stored in existing `SessionRecord` fields (`behavior_profile`, `campaign_type`, `intent_profile`, `historical_relation`, `sequence_profile`) without changing the wire schema.

- [ ] **Step 1: Write RED tests for semantic families and nuisance overlap**

```python
from adminlab.v2_scenarios import V2_BENIGN_FAMILIES, V2_SUSPICIOUS_FAMILIES, counterfactual_key


def test_v2_has_required_semantic_families():
    assert {"scheduled_patch_fanout", "backup_burst", "incident_response", "new_admin", "service_automation"} <= V2_BENIGN_FAMILIES
    assert {"low_slow_lateral", "sudden_fanout", "new_protocol", "failed_then_success", "target_chain"} <= V2_SUSPICIOUS_FAMILIES


def test_counterfactual_key_excludes_label_semantics(sample_session_pair):
    benign, suspicious = sample_session_pair
    assert counterfactual_key(benign) == counterfactual_key(suspicious)
    assert benign.label_binary != suspicious.label_binary
```

- [ ] **Step 2: Verify RED**

Run: `PYTHONPATH=src pytest -q tests/test_v2_scenarios.py`
Expected: import failure.

- [ ] **Step 3: Implement deterministic family assignment**

```python
V2_BENIGN_FAMILIES = {
    "routine_admin", "scheduled_patch_fanout", "backup_burst", "helpdesk",
    "incident_response", "new_server", "new_admin", "service_automation",
    "jump_host", "offhours_emergency", "mass_diagnostics", "benign_first_seen",
}
V2_SUSPICIOUS_FAMILIES = {
    "low_slow_lateral", "sudden_fanout", "rare_pair", "new_protocol",
    "protocol_switch", "failed_then_success", "target_chain",
    "credential_hop_like", "small_copy_then_admin", "offhours_lateral",
}


def counterfactual_key(row):
    return (row.protocol, row.simulated_day, row.netem_profile, row.task_id)
```

`build_v2_semantic_plan` must assign families deterministically from seed and ensure at least 30% of rows belong to explicit benign/suspicious counterfactual pairs with overlapping protocol/day/netem/task controls.

- [ ] **Step 4: Extend scenario quality report**

Add `v2_family_counts`, `counterfactual_pair_fraction`, `per_protocol_label_balance`, `timeline_days_by_protocol`, and fail if pair fraction <0.30 or any core protocol lacks both labels.

- [ ] **Step 5: Run tests**

Run: `PYTHONPATH=src pytest -q tests/test_v2_scenarios.py tests/test_extended_selection_timeline.py tests/test_campaign_sequences.py`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add remote-admin-anomaly-lab/configs/v2_campaigns.yaml remote-admin-anomaly-lab/src/adminlab/v2_scenarios.py remote-admin-anomaly-lab/scripts/check_scenario_quality.py remote-admin-anomaly-lab/tests/test_v2_scenarios.py
git commit -m "feat(remote-admin): add V2 counterfactual campaign semantics"
```

---

### Task 3: Causal session and campaign Gold

**Files:**
- Create: `remote-admin-anomaly-lab/src/adminlab/session_gold.py`
- Create: `remote-admin-anomaly-lab/src/adminlab/campaign_gold.py`
- Create: `remote-admin-anomaly-lab/scripts/build_hierarchical_gold.py`
- Create: `remote-admin-anomaly-lab/tests/test_session_gold.py`
- Create: `remote-admin-anomaly-lab/tests/test_campaign_gold.py`
- Create: `remote-admin-anomaly-lab/configs/v2_feature_contract.yaml`

**Interfaces:**
- `build_session_gold(flows: DataFrame, labels: DataFrame, sessions: DataFrame) -> tuple[DataFrame, DataFrame]`
- `build_campaign_gold(session_features: DataFrame, session_labels: DataFrame) -> tuple[DataFrame, DataFrame]`
- Both return feature frames with stable `row_id` plus separate label frames.

- [ ] **Step 1: RED causality test**

```python
import pandas as pd
from adminlab.session_gold import build_session_gold


def test_future_flow_cannot_change_earlier_session_features(base_flows, base_labels, sessions):
    before, _ = build_session_gold(base_flows, base_labels, sessions)
    future = pd.concat([base_flows, make_future_flow(hours=24)], ignore_index=True)
    after, _ = build_session_gold(future, base_labels, sessions)
    cols = [c for c in before.columns if c != "row_id"]
    pd.testing.assert_series_equal(before.iloc[0][cols], after.iloc[0][cols], check_names=False)
```

- [ ] **Step 2: RED aggregation test**

```python
def test_session_aggregates_multiple_parser_flows(session_fixture):
    features, labels = build_session_gold(*session_fixture)
    assert features.loc[0, "flow_count"] == 3
    assert features.loc[0, "session_total_bytes"] == 600
    assert labels.loc[0, "label_binary"] in (0, 1)
```

- [ ] **Step 3: Implement session builder**

Process sessions strictly sorted by session start. Compute current-session aggregate values from mapped parser flows, then compute history fields from state containing only earlier sessions, then insert current session into state. Required columns include:

```text
flow_count
session_duration_s
session_total_bytes
session_total_packets
unique_dst_count_current
prior_sessions_1m
prior_sessions_5m
prior_sessions_15m
prior_sessions_1h
prior_unique_dst_1h
prior_unique_dst_24h
pair_seen_count_prior
pair_recency_s
protocol_seen_prior
source_protocol_diversity_prior
new_dst_prior
new_protocol_prior
prior_out_degree_1h
prior_new_edge_count_1h
hour_sin
hour_cos
```

- [ ] **Step 4: Implement campaign builder**

Source-centric windows/campaign groups must expose:

```text
session_count
target_count
protocol_count
new_target_ratio
protocol_transition_count
protocol_entropy
fanout_slope
inter_session_mean_s
inter_session_cv
unseen_pair_fraction
prior_source_sessions_24h
```

No campaign name/family is a model input.

- [ ] **Step 5: Add feature-contract forbidden columns**

`v2_feature_contract.yaml` must explicitly forbid:

```yaml
forbidden:
  - label_binary
  - scenario_id
  - campaign_id
  - campaign_type
  - behavior_profile
  - implementation_id
  - environment_id
  - generator_seed
  - netem_profile
```

- [ ] **Step 6: Run hierarchical tests**

Run: `PYTHONPATH=src pytest -q tests/test_session_gold.py tests/test_campaign_gold.py tests/test_leakage_audit.py`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add remote-admin-anomaly-lab/src/adminlab/session_gold.py remote-admin-anomaly-lab/src/adminlab/campaign_gold.py remote-admin-anomaly-lab/scripts/build_hierarchical_gold.py remote-admin-anomaly-lab/configs/v2_feature_contract.yaml remote-admin-anomaly-lab/tests/test_session_gold.py remote-admin-anomaly-lab/tests/test_campaign_gold.py
git commit -m "feat(remote-admin): add causal session and campaign Gold"
```

---

### Task 4: Windows-native external holdout

**Files:**
- Create: `remote-admin-anomaly-lab/windows/capture_native.ps1`
- Create: `remote-admin-anomaly-lab/windows/validate_native.py`
- Create: `.github/workflows/remote-admin-v2-windows-native.yml`
- Create: `remote-admin-anomaly-lab/tests/test_windows_native_contract.py`

**Interfaces:**
- Produces artifact `remote-admin-v2-windows-native-<run-id>` containing `capture.etl`, converted `capture.pcapng`, `sessions.jsonl`, `windows_fidelity.json`, `runner.json`.
- `windows_fidelity.json` has one entry per `openssh`, `smb`, `winrm`, `dcom`, `rdp`.

- [ ] **Step 1: RED static fidelity tests**

```python
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]


def test_windows_script_is_fail_closed():
    text = (ROOT / "windows/capture_native.ps1").read_text().lower()
    assert "pktmon" in text
    assert "native_windows_validated" in text
    assert "wire_observed" in text
    assert "session_completed" in text
    assert "unavailable_hosted_runner" in text
    assert "synthetic" not in text
```

- [ ] **Step 2: Implement PowerShell capture**

The script must:

```powershell
pktmon start --capture --pkt-size 0 --file-name $etl
# configure/start OpenSSH if available
# create a temporary SMB share and perform bounded read/write
# Enable-PSRemoting -SkipNetworkProfileCheck -Force and invoke localhost WSMan
# invoke a bounded WMI/DCOM remote-style call to a loopback alias when permitted
# attempt TermService/mstsc probe without claiming success unless wire + session evidence exist
pktmon stop
pktmon pcapng $etl -o $pcapng
```

All temporary shares/services/firewall changes are cleaned up in `finally`.

- [ ] **Step 3: Implement validator**

`validate_native.py` rejects any `native_windows_validated` entry unless `tool_present`, `wire_observed`, and `session_completed` are all true. At least one Windows-native protocol must validate for the V2 research gate; all five probes must be reported.

- [ ] **Step 4: Create workflow**

Use `runs-on: windows-2025`, install Python, execute capture, run validator, upload artifact even on failure with `if: always()`.

- [ ] **Step 5: Run contracts**

Run: `PYTHONPATH=src pytest -q tests/test_windows_native_contract.py`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add remote-admin-anomaly-lab/windows .github/workflows/remote-admin-v2-windows-native.yml remote-admin-anomaly-lab/tests/test_windows_native_contract.py
git commit -m "feat(remote-admin): add native Windows external holdout capture"
```

---

### Task 5: LANL independent reference slice

**Files:**
- Create: `remote-admin-anomaly-lab/src/adminlab/lanl_reference.py`
- Create: `remote-admin-anomaly-lab/scripts/build_lanl_reference.py`
- Create: `.github/workflows/remote-admin-v2-reference.yml`
- Create: `remote-admin-anomaly-lab/tests/test_lanl_reference.py`

**Interfaces:**
- `parse_netflow(lines, ports: set[int], max_rows: int) -> DataFrame`
- `parse_windows_logons(lines, max_rows: int) -> DataFrame`
- Produces `external/lanl-2017/remote_admin_flows.parquet`, `network_logons.parquet`, `source_manifest.json`, `reference_quality.json`.

- [ ] **Step 1: RED parser tests**

```python
from adminlab.lanl_reference import parse_netflow


def test_lanl_filter_keeps_remote_admin_well_known_port():
    rows = ["761,4434,Comp1,Comp2,6,Port12597,22,10,8,1000,900"]
    df = parse_netflow(rows, {22, 135, 445, 3389, 5985, 5986}, 100)
    assert len(df) == 1
    assert int(df.iloc[0].dst_port) == 22
```

- [ ] **Step 2: Implement bounded streaming parser**

The fetch script streams the public BZ2 source, stops after configurable maximum decompressed lines/remote-admin rows, records HTTP/source metadata, SHA256 of downloaded bytes actually retained, parser version and filter ports. No LANL row gets a synthetic class label.

- [ ] **Step 3: Implement reference quality**

Require non-empty remote-admin flows, monotonic timestamps after sort, finite bytes/packet/duration fields, at least two observed destination ports when source data permits, and no synthetic label column.

- [ ] **Step 4: Create workflow**

`remote-admin-v2-reference.yml` runs on Ubuntu, attempts both LANL netflow and WLS day-02 URLs from `v2_research.yaml`, builds the bounded external artifact, and fails if either source is inaccessible or the resulting reference is empty.

- [ ] **Step 5: Run parser tests**

Run: `PYTHONPATH=src pytest -q tests/test_lanl_reference.py`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add remote-admin-anomaly-lab/src/adminlab/lanl_reference.py remote-admin-anomaly-lab/scripts/build_lanl_reference.py .github/workflows/remote-admin-v2-reference.yml remote-admin-anomaly-lab/tests/test_lanl_reference.py
git commit -m "feat(remote-admin): add independent LANL reference slice"
```

---

### Task 6: Hierarchical model training and shortcut audit

**Files:**
- Create: `remote-admin-anomaly-lab/scripts/train_v2_models.py`
- Create: `remote-admin-anomaly-lab/src/adminlab/v2_modeling.py`
- Create: `remote-admin-anomaly-lab/tests/test_v2_modeling.py`

**Interfaces:**
- `fit_view(name: str, features: DataFrame, labels: DataFrame, seed: int) -> tuple[object, dict]`
- Outputs model/metrics for `flow-baseline`, `session-primary`, `campaign-primary` plus `shortcut-audit.json`.

- [ ] **Step 1: RED test that external rows cannot train**

```python
from adminlab.v2_modeling import training_mask


def test_training_mask_excludes_external_environments(labels):
    mask = training_mask(labels)
    assert not mask[labels.environment_id.isin(["windows_native", "lanl_reference"])].any()
```

- [ ] **Step 2: Implement training mask and feature allowlist**

Only `environment_id == "linux_v2"` and split `train` may fit the model. Any forbidden column in feature matrices raises `ValueError`.

- [ ] **Step 3: Implement view training**

Use LightGBM with deterministic seed and existing evaluation helpers. Save grouped validation/test/challenge metrics and low-FPR operating points for each view.

- [ ] **Step 4: Implement shortcut baselines**

Train/evaluate nuisance families independently: bytes/packets, duration/rate, time-only, current-session-only. `shortcut_risk=true` when best nuisance PR-AUC exceeds `session-primary PR-AUC - 0.05`.

- [ ] **Step 5: Run tests and commit**

Run: `PYTHONPATH=src pytest -q tests/test_v2_modeling.py tests/test_evaluation.py`
Expected: PASS.

```bash
git add remote-admin-anomaly-lab/src/adminlab/v2_modeling.py remote-admin-anomaly-lab/scripts/train_v2_models.py remote-admin-anomaly-lab/tests/test_v2_modeling.py
git commit -m "feat(remote-admin): train hierarchical V2 models with shortcut guard"
```

---

### Task 7: V2 planner audit and wire smoke

**Files:**
- Create: `.github/workflows/remote-admin-v2-planner-audit.yml`
- Create: `.github/workflows/remote-admin-v2-wire-smoke.yml`
- Create: `remote-admin-anomaly-lab/scripts/v2_planner_audit.py`
- Create: `remote-admin-anomaly-lab/tests/test_v2_planner_audit.py`

**Interfaces:**
- Planner output `V2_PLANNER_AUDIT.json` must prove 45-day coverage, class/protocol balance, >=30% counterfactual pair fraction and bounded challenge size.

- [ ] **Step 1: RED planner acceptance test**

```python
from adminlab.v2_scenarios import summarize_v2_plan


def test_v2_plan_has_counterfactual_and_timeline_coverage(v2_records):
    report = summarize_v2_plan(v2_records)
    assert report["counterfactual_pair_fraction"] >= 0.30
    assert min(report["timeline_days_by_protocol"].values()) >= 30
    assert report["challenge_fraction"] <= 0.45
```

- [ ] **Step 2: Implement planner audit**

Generate a large deterministic no-wire plan and select 1000 using full-timeline balanced sampling. Fail before capture if constraints are not met.

- [ ] **Step 3: Implement 80-session smoke**

Use existing `capture_shard_extended_v4.sh` with V2-selected records, then build Silver, V1 flow Gold, V2 hierarchical Gold, and verify no schema/leakage regressions.

- [ ] **Step 4: Run tests and commit**

Run: `PYTHONPATH=src pytest -q tests/test_v2_planner_audit.py tests/test_extended_selection_timeline.py tests/test_gold_pipeline.py`
Expected: PASS.

```bash
git add .github/workflows/remote-admin-v2-planner-audit.yml .github/workflows/remote-admin-v2-wire-smoke.yml remote-admin-anomaly-lab/scripts/v2_planner_audit.py remote-admin-anomaly-lab/tests/test_v2_planner_audit.py
git commit -m "ci(remote-admin): add V2 planner and hierarchical wire smoke gates"
```

---

### Task 8: V2 1k research gate, external evaluation and persistence

**Files:**
- Create: `.github/workflows/remote-admin-v2-research-1k.yml`
- Create: `remote-admin-anomaly-lab/scripts/evaluate_v2_external.py`
- Create: `remote-admin-anomaly-lab/scripts/v2_research_decision.py`
- Create: `remote-admin-anomaly-lab/tests/test_v2_research_decision.py`
- Create: `.github/workflows/remote-admin-v2-finalizer.yml`

**Interfaces:**
- Consumes verified Windows-native and LANL artifacts from their latest explicit run IDs supplied to `workflow_dispatch`/repository variables.
- Produces `V2_RESEARCH_GATE.json`, complete V2 artifact, and private HF candidate/quarantine tree.

- [ ] **Step 1: RED decision test**

```python
from adminlab.v2_gate import decide_v2


def test_v2_gate_blocks_good_internal_model_when_shortcut_margin_fails():
    result = decide_v2({
        "validation_pr_auc": 0.72,
        "test_pr_auc": 0.68,
        "challenge_recall_at_fpr_1pct": 0.20,
        "hard_benign_fpr": 0.01,
        "best_shortcut_pr_auc": 0.70,
        "windows_mapped_native_protocols": 2,
        "lanl_reference_complete": True,
        "last_delta_pr_auc": 0.02,
    })
    assert result["automatic_gate_pass"] is False
    assert "shortcut_margin" in result["automatic_failures"]
```

- [ ] **Step 2: Implement `adminlab.v2_gate.decide_v2`**

Decision uses exact thresholds from `v2_research.yaml`, separates `automatic_gate_pass` from `allow_scale`, and never allows scale when research fails.

- [ ] **Step 3: Implement external evaluators**

Windows evaluator reports per-native-protocol score distributions/metrics when labels exist. LANL evaluator reports score distribution and fixed-threshold FPR-like exceedance rate without tuning the threshold.

- [ ] **Step 4: Implement 1k workflow**

Order:

```text
contracts -> planner audit -> 1000 Linux real-wire sessions -> Bronze -> Silver
-> flow Gold -> session Gold -> campaign Gold -> leakage/causality
-> train flow/session/campaign -> shortcut audit -> internal evaluation
-> download/verify Windows holdout -> download/verify LANL reference
-> external evaluation -> learning curve -> V2 decision
-> upload complete artifact always
```

The workflow must not trigger 4k automatically.

- [ ] **Step 5: Implement finalizer**

On PASS upload to `v2/candidates/<run-id>`; on FAIL upload to `v2/quarantine/<run-id>`. Verify required Bronze/Silver/Gold/model/evaluation files via `HfApi.list_repo_files`, then commit `V2_RESULTS_AUTOGENERATED.json`, `V2_SCALE_DECISION.json`, and update living docs.

- [ ] **Step 6: Run gate tests and full contracts**

Run: `PYTHONPATH=src pytest -q tests`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add .github/workflows/remote-admin-v2-research-1k.yml .github/workflows/remote-admin-v2-finalizer.yml remote-admin-anomaly-lab/scripts/evaluate_v2_external.py remote-admin-anomaly-lab/scripts/v2_research_decision.py remote-admin-anomaly-lab/src/adminlab/v2_gate.py remote-admin-anomaly-lab/tests/test_v2_research_decision.py
git commit -m "feat(remote-admin): add fail-closed V2 1k research and persistence gates"
```

---

### Task 9: Documentation and final verification

**Files:**
- Create/Modify: `remote-admin-anomaly-lab/V2_STATUS.md`
- Modify: `remote-admin-anomaly-lab/README.md`
- Modify: `remote-admin-anomaly-lab/PLAN.md`
- Modify: `remote-admin-anomaly-lab/docs/FIDELITY_MATRIX.md`
- Modify: `remote-admin-anomaly-lab/docs/NGFW_INTEGRATION.md`

**Interfaces:**
- Documentation must read results from generated V2 JSON evidence and must not claim promotion before gate PASS.

- [ ] **Step 1: Update docs with V2 architecture and holdout semantics**

State explicitly that session-primary is the research primary view, Windows/LANL are external-only, and automatic enforcement remains prohibited until production false-positive evidence exists.

- [ ] **Step 2: Run final static and unit contracts**

Run: `PYTHONPATH=src pytest -q tests`
Expected: PASS.

- [ ] **Step 3: Run the V2 planner, Windows, reference and smoke workflows**

All prerequisite workflows must be GREEN before the V2 1k workflow is launched.

- [ ] **Step 4: Run V2 1k and finalizer**

Record exact run IDs, artifact IDs/digests, session/flow mapping, model metrics, Windows fidelity and LANL reference status.

- [ ] **Step 5: Commit final evidence docs**

```bash
git add remote-admin-anomaly-lab/V2_STATUS.md remote-admin-anomaly-lab/README.md remote-admin-anomaly-lab/PLAN.md remote-admin-anomaly-lab/docs/FIDELITY_MATRIX.md remote-admin-anomaly-lab/docs/NGFW_INTEGRATION.md
git commit -m "docs(remote-admin): finalize evidence-backed V2 dataset status"
```

## Plan self-review

- Spec coverage: all V2 design sections map to Tasks 1-9.
- No placeholder implementation steps are intentionally left; inaccessible Windows/LANL capabilities fail closed and are represented explicitly in evidence.
- Type/interface consistency: hierarchical builders return feature/label DataFrame pairs; external environments remain evaluation-only; V2 decision separates research PASS from scale authorization.
- Scale safety: no task creates an automatic 4k fan-out path.