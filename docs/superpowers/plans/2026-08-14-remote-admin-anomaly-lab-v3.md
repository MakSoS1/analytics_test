# Remote Admin Anomaly Lab V3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a 1,000-session real-wire V3 corpus whose current-session nuisance/time features are deliberately matched across labels, whose intended signal lives in causal history/graph/campaign context, whose Bronze layer is human-inspectable via per-session/per-campaign PCAPs, and whose final verified HF release safely replaces V1/V2 storage.

**Architecture:** V3 preserves the proven V2 isolated network lab, Suricata/Zeek parsing, hierarchical Gold and external references. A new label-neutral matching layer creates time-matched benign/suspicious current sessions while a history planner constructs contrasting prior graph/sequence context; a PCAP slicer turns one temporary capture into authoritative per-session and per-campaign PCAPs. The release pipeline is fail-closed: planner → smoke → Windows/reference → 1k → research gate → HF verification → destructive cleanup.

**Tech Stack:** Python 3.12, pytest, pandas/pyarrow, LightGBM/scikit-learn, tcpdump/tshark/editcap/mergecap, Suricata, Zeek, Linux network namespaces, GitHub Actions Ubuntu + `windows-2025`, PowerShell/pktmon, `huggingface_hub`.

## Global Constraints

- GitHub-hosted runners only.
- Lab traffic remains inside `10.77.0.0/24` with no default route.
- Windows fidelity uses `windows-2025` only.
- No malware, C2 framework, credential theft, external target, or payload execution.
- Current-session wire controls and time assignment must be label-neutral after pair construction.
- V1/V2 persistence is deleted only after V3 GitHub + HF verification is complete.
- No GitHub Releases for PCAP storage.
- Final HF Bronze contains per-session/per-campaign PCAPs; merged PCAP is ephemeral.

---

### Task 1: V3 matching and history planner

**Files:**
- Create: `remote-admin-anomaly-lab/src/adminlab/v3_signal.py`
- Create: `remote-admin-anomaly-lab/tests/test_v3_signal.py`
- Modify: `remote-admin-anomaly-lab/scripts/run_scenarios_extended_v2.py`
- Create: `remote-admin-anomaly-lab/configs/v3_research.yaml`

**Interfaces:**
- Consumes: `SessionRecord`, `build_v2_semantic_plan()`, `materialize_wire_controls()`.
- Produces: `build_v3_signal_plan(records: list[SessionRecord], seed: int, matched_fraction: float) -> list[SessionRecord]` and `audit_v3_signal_plan(records: list[SessionRecord]) -> dict`.

- [ ] **Step 1: Write failing tests for exact-hour matching and label-neutral current controls**

```python
from collections import defaultdict
from adminlab.v3_signal import build_v3_signal_plan, audit_v3_signal_plan


def test_v3_pairs_match_current_session_controls(sample_sessions):
    rows = build_v3_signal_plan(sample_sessions, seed=20260814, matched_fraction=0.40)
    by_pair = defaultdict(list)
    for row in rows:
        if row.pair_id:
            by_pair[row.pair_id].append(row)
    pairs = [rows for rows in by_pair.values() if len(rows) == 2]
    assert pairs
    for left, right in pairs:
        assert left.label_binary != right.label_binary
        assert left.protocol == right.protocol
        assert left.start_ts[:13] == right.start_ts[:13]
        assert left.behavior_profile == right.behavior_profile
        assert left.netem_profile == right.netem_profile


def test_v3_audit_rejects_time_shortcut(sample_sessions):
    rows = build_v3_signal_plan(sample_sessions, seed=20260814, matched_fraction=0.40)
    report = audit_v3_signal_plan(rows)
    assert report["matched_hour_pair_fraction"] >= 0.80
    assert report["max_hour_label_fraction_gap"] <= 0.10
```

- [ ] **Step 2: Run RED tests**

Run:

```bash
cd remote-admin-anomaly-lab
PYTHONPATH=src pytest -q tests/test_v3_signal.py
```

Expected: import failure because `adminlab.v3_signal` does not exist.

- [ ] **Step 3: Implement deterministic matching**

Implement `build_v3_signal_plan` so that it:

```python
# conceptual signature only; implementation must use dataclasses.replace
# and must never derive wire controls from label after pairing.
def build_v3_signal_plan(records, seed, matched_fraction=0.40):
    # group candidate rows by protocol + exact simulated hour + weekday/weekend
    # pair opposite-label rows from the same bucket
    # assign shared pair_id and shared current behavior/netem profile
    # preserve different src/dst/history identities
    # distribute remaining unpaired rows across time label-neutrally
    return output
```

Create `configs/v3_research.yaml` with:

```yaml
version: v3
sessions_1k: 1000
matched_counterfactual_fraction: 0.40
min_matched_hour_pair_fraction: 0.80
max_hour_label_fraction_gap: 0.10
min_campaign_groups: 180
max_campaign_fraction: 0.025
min_validation_sessions: 120
min_test_sessions: 120
challenge_fraction_min: 0.15
challenge_fraction_max: 0.25
shortcut:
  max_time_only_pr_auc: 0.55
  min_full_over_current_session_margin: 0.05
  min_full_over_best_nuisance_margin: 0.05
research:
  min_validation_pr_auc: 0.60
  min_test_pr_auc: 0.58
  min_session_mapping_coverage: 0.98
  max_hard_benign_fpr: 0.05
```

- [ ] **Step 4: Add `--v3-signal` to the runner**

Call order in `run_scenarios_extended_v2.py` must become:

```python
selected = balanced_select(planned, args.count, protocols)
selected = organize_campaign_sequences(selected, bundle["campaigns"], seed=args.seed)
if args.v3_signal:
    selected = build_v3_signal_plan(selected, seed=args.seed, matched_fraction=args.v3_matched_fraction)
elif args.v2_semantic:
    selected = build_v2_semantic_plan(...)
selected = materialize_implementation_variants(...)
selected = materialize_wire_controls(...)
```

- [ ] **Step 5: Run full tests and commit**

```bash
PYTHONPATH=src pytest -q
```

Expected: all existing V1/V2 tests plus new V3 tests PASS.

Commit message: `feat(remote-admin): add V3 matched signal planner`.

---

### Task 2: V3 campaign diversity and split budgets

**Files:**
- Create: `remote-admin-anomaly-lab/src/adminlab/v3_campaigns.py`
- Create: `remote-admin-anomaly-lab/tests/test_v3_campaigns.py`
- Modify: `remote-admin-anomaly-lab/src/adminlab/splits.py`
- Create: `remote-admin-anomaly-lab/tests/test_v3_split_budget.py`

**Interfaces:**
- Produces: `organize_v3_campaigns(records, seed) -> list[SessionRecord]`, `audit_v3_campaigns(records) -> dict`.

- [ ] **Step 1: Add RED tests for campaign count/size**

```python
def test_v3_campaigns_are_many_and_bounded(v3_1k_plan):
    report = audit_v3_campaigns(v3_1k_plan)
    assert report["campaign_count"] >= 180
    assert report["max_campaign_fraction"] <= 0.025
    assert report["benign_campaign_count"] >= 60
    assert report["suspicious_campaign_count"] >= 60
    assert report["multi_protocol_campaign_count"] >= 30
```

- [ ] **Step 2: Add RED split viability test**

```python
def test_v3_generic_splits_keep_enough_sessions(v3_1k_plan):
    split_rows, report = build_grouped_splits(v3_1k_plan, policy="v3")
    counts = report["split_counts"]
    assert counts["validation"] >= 120
    assert counts["test"] >= 120
    challenge_fraction = counts["challenge"] / sum(counts.values())
    assert 0.15 <= challenge_fraction <= 0.25
```

- [ ] **Step 3: Implement campaign construction**

Create many independent campaign IDs by persona/day/sequence family, while keeping counterfactual pair IDs in the same connected component. Do not group all rows from the same day+label into one large campaign.

- [ ] **Step 4: Implement `policy="v3"` split budgets**

Holdouts are selected by connected-component impact. A holdout that cannot fit its configured maximum is reported unavailable and skipped rather than exceeding budget.

- [ ] **Step 5: Run tests and commit**

```bash
PYTHONPATH=src pytest -q tests/test_v3_campaigns.py tests/test_v3_split_budget.py tests/test_splits.py
PYTHONPATH=src pytest -q
```

Commit: `feat(remote-admin): rebalance V3 campaigns and split budgets`.

---

### Task 3: Human-inspectable Bronze PCAP slicing

**Files:**
- Create: `remote-admin-anomaly-lab/src/adminlab/pcap_slicing.py`
- Create: `remote-admin-anomaly-lab/scripts/build_v3_pcap_index.py`
- Create: `remote-admin-anomaly-lab/tests/test_pcap_slicing.py`
- Modify: `remote-admin-anomaly-lab/scripts/package_bronze.py`

**Interfaces:**
- Produces: `slice_session_pcaps(merged_pcap, sessions, output_root) -> list[PcapEvidence]`, `build_campaign_pcaps(session_evidence, sessions, output_root) -> list[PcapEvidence]`.

- [ ] **Step 1: RED test path layout and no persisted merged PCAP**

```python
def test_v3_pcap_layout(tmp_path, tiny_pcap, sessions):
    evidence = slice_session_pcaps(tiny_pcap, sessions, tmp_path)
    assert evidence
    for item in evidence:
        assert item.relative_path.startswith("sessions/")
        assert item.packet_count > 0
        assert len(item.sha256) == 64
    assert not (tmp_path / "merged.pcap").exists()
```

- [ ] **Step 2: Implement packet slicing with `editcap -A/-B`**

For each successful session use `execution_start_ts` and `execution_end_ts`, padded by 250 ms on each side. Compress with zstd only after `capinfos`/tshark confirms packet count >0.

- [ ] **Step 3: Build per-campaign PCAPs with `mergecap`**

Campaign PCAPs are composed from the already sliced session PCAPs, preserving authoritative session boundaries.

- [ ] **Step 4: Write `pcap_index.csv` and `pcap_index.parquet`**

Columns:

```text
label_binary,label_name,protocol,semantic_family,session_id,campaign_id,
start_ts,src_host_id,dst_host_id,implementation_id,semantic_fidelity,
relative_pcap_path,packet_count,pcap_bytes,sha256
```

These are Bronze inspection metadata and must be listed in the feature-contract forbidden set.

- [ ] **Step 5: Add CI sample reparse**

Random deterministic sample of 20 session PCAPs:

```bash
tshark -r "$pcap" -T fields -e frame.number >/dev/null
```

- [ ] **Step 6: Full tests and commit**

Commit: `feat(remote-admin): persist per-session and per-campaign PCAPs`.

---

### Task 4: Stronger causal session-history features

**Files:**
- Modify: `remote-admin-anomaly-lab/src/adminlab/session_gold.py`
- Modify: `remote-admin-anomaly-lab/configs/v2_feature_contract.yaml`
- Create: `remote-admin-anomaly-lab/configs/v3_feature_contract.yaml`
- Create: `remote-admin-anomaly-lab/tests/test_v3_history_features.py`

**Interfaces:**
- Session matrix adds only numeric causal prior-history features; raw IDs remain state keys and labels only.

- [ ] **Step 1: RED future-invariance test**

```python
def test_v3_history_features_do_not_change_when_future_rows_are_appended(base_rows, future_rows):
    first = build_session_gold(base_rows)
    second = build_session_gold(base_rows + future_rows)
    cols = [c for c in first.columns if c.endswith("_prior") or c.startswith("new_")]
    assert first[cols].equals(second.loc[first.index, cols])
```

- [ ] **Step 2: Add features**

Add:

```text
src_distinct_dst_24h_prior
src_distinct_dst_7d_prior
src_distinct_dst_30d_prior
pair_seen_count_prior
time_since_pair_seen_seconds_prior
new_destination_for_source
new_protocol_for_source
src_protocol_diversity_7d_prior
src_new_target_count_1h_prior
src_new_target_count_24h_prior
src_graph_expansion_rate_24h_prior
recent_protocol_switch_count_prior
recent_remote_admin_attempt_count_prior
```

- [ ] **Step 3: Add V3 allowlist and forbid all identity/context metadata**

- [ ] **Step 4: Run parity/leakage tests and commit**

Commit: `feat(remote-admin): strengthen causal V3 history features`.

---

### Task 5: V3 shortcut diagnostics and planner gate

**Files:**
- Create: `remote-admin-anomaly-lab/scripts/v3_planner_audit.py`
- Modify: `remote-admin-anomaly-lab/src/adminlab/v2_modeling.py`
- Create: `remote-admin-anomaly-lab/src/adminlab/v3_gate.py`
- Create: `remote-admin-anomaly-lab/tests/test_v3_gate.py`

**Interfaces:**
- Produces planner JSON and `evaluate_v3_gate(metrics, shortcut, quality, external) -> dict`.

- [ ] **Step 1: Add RED gate tests**

```python
def test_v3_gate_rejects_time_shortcut():
    decision = evaluate_v3_gate(
        metrics={"validation_pr_auc": .70, "test_pr_auc": .68, "challenge_recall_fpr_1pct": .2},
        shortcut={"time_only_pr_auc": .60, "current_session_only_pr_auc": .50, "best_nuisance_pr_auc": .60},
        quality={"session_mapping_coverage": .99, "hard_benign_fpr": .01, "leakage_pass": True},
        external={"external_rows_in_train": 0},
    )
    assert decision["research_status"] == "FAIL"
    assert "time_only_shortcut" in decision["failed_gates"]
```

- [ ] **Step 2: Add planner-only 1k assertions**

Require 1000 rows, 500/500 classes, 250/protocol, >=30 simulated days/protocol, campaign targets from Task 2, exact-hour matching thresholds from Task 1, and viable split counts.

- [ ] **Step 3: Add nuisance baselines**

Compute at minimum:

```text
time_only
current_session_only
bytes_packets_only
duration_rate_only
protocol_only
history_only
full_session
```

- [ ] **Step 4: Commit**

Commit: `feat(remote-admin): add V3 shortcut and planner gates`.

---

### Task 6: Windows-2025 DCOM and RDP evidence hardening

**Files:**
- Modify: `remote-admin-anomaly-lab/scripts/windows_fidelity_capture.ps1`
- Create: `remote-admin-anomaly-lab/scripts/validate_windows_v3.py`
- Create: `remote-admin-anomaly-lab/tests/test_windows_v3_contract.py`
- Create: `.github/workflows/remote-admin-v3-windows.yml`

**Interfaces:**
- Produces `windows_v3_fidelity.json` with one status per protocol: `native_windows_validated`, `attempted_unverified`, or `unavailable_hosted_runner`.

- [ ] **Step 1: RED validator test**

A DCOM result with `session_completed=true` but no TCP/135 evidence must remain `attempted_unverified`.

- [ ] **Step 2: Strengthen DCOM capture**

During capture run a bounded local CIM/DCOM operation and record both endpoint mapper TCP/135 and any subsequent RPC dynamic port observed by pktmon/tshark.

- [ ] **Step 3: Attempt bounded native RDP**

Use only localhost/hosted-runner resources. If mstsc cannot create an observable RDP session in the non-interactive runner, emit `unavailable_hosted_runner` rather than failing the technical dataset release.

- [ ] **Step 4: Run Windows workflow and commit evidence validator**

Commit: `feat(remote-admin): harden V3 Windows DCOM and RDP evidence`.

---

### Task 7: 80-session V3 real-wire smoke

**Files:**
- Create: `.github/workflows/remote-admin-v3-smoke.yml`
- Create: `remote-admin-anomaly-lab/scripts/verify_v3_smoke.py`

**Interfaces:**
- Smoke exercises the exact V3 planner, PCAP slicer, Silver, flow Gold, session Gold and split code used by 1k.

- [ ] **Step 1: Configure 80-session capture**

Use 20 SSH, 20 SMB, 20 RDP, 20 VNC; 40 benign/40 suspicious; V3 signal mode; deterministic seed.

- [ ] **Step 2: Verify PCAP outputs**

Require >=79 non-empty session PCAPs, non-empty campaign PCAP set, pcap index checksums, and no persisted merged PCAP.

- [ ] **Step 3: Verify Gold/leakage**

Require mapping >=95% for smoke and pair/campaign split integrity.

- [ ] **Step 4: Retain smoke artifact only until full V3 succeeds**

Commit: `ci(remote-admin): add V3 real-wire smoke`.

---

### Task 8: Full V3 1k release workflow

**Files:**
- Create: `.github/workflows/remote-admin-v3-release.yml`
- Create: `remote-admin-anomaly-lab/scripts/finalize_v3_research.py`
- Create: `remote-admin-anomaly-lab/scripts/build_v3_release_manifest.py`
- Modify: `remote-admin-anomaly-lab/scripts/upload_hf.py`

**Interfaces:**
- Produces authoritative `V3_RELEASE_MANIFEST.json`, `V3_RESEARCH_DECISION.json`, `V3_HF_STATUS.json` and final Actions artifact.

- [ ] **Step 1: Same-run prerequisites**

Jobs:

```text
contracts
planner
windows-2025
lanl-reference
linux-v3-1k (needs contracts+planner)
finalize (needs windows+lanl+linux)
```

- [ ] **Step 2: Capture and Bronze**

Run V3 1k real wire, slice per-session/per-campaign PCAPs, remove ephemeral merged capture before packaging final HF tree.

- [ ] **Step 3: Silver and Gold**

Build Suricata/Zeek, flow/session/campaign Gold and split/leakage evidence.

- [ ] **Step 4: Train/evaluate**

Train flow baseline, session primary and campaign model; calculate shortcut, hard-benign, low-FPR and grouped learning-curve evidence.

- [ ] **Step 5: External evaluation**

Score fresh same-run Windows evidence and fresh LANL reference after model/threshold selection. Never fit/tune on external data.

- [ ] **Step 6: Research decision**

`ALLOW_4K` only if all mandatory gates pass; otherwise `STOP_AT_1K`.

- [ ] **Step 7: Manifest and HF upload**

Create immutable checksums before upload. Upload to private `Maksim123321/remote-admin-anomaly-v1` under `v3/candidate/<run-id>` initially.

- [ ] **Step 8: Verify HF**

Use a separate verification script/API call to confirm required paths and checksums exist before marking persistence PASS.

- [ ] **Step 9: Upload final GitHub artifact**

The artifact must include manifests/evidence and the same authoritative V3 tree; no GitHub Release.

Commit: `ci(remote-admin): add complete V3 1k research release`.

---

### Task 9: V3 final status and HF promotion

**Files:**
- Create: `remote-admin-anomaly-lab/V3_FINAL_STATUS.md`
- Create: `remote-admin-anomaly-lab/V3_FINAL_STATUS.json`
- Create: `remote-admin-anomaly-lab/scripts/promote_v3_hf.py`

**Interfaces:**
- Promotion is storage promotion, not model promotion. Dataset may be technically READY even if research status FAIL.

- [ ] **Step 1: Verify final artifact digest and HF candidate**

- [ ] **Step 2: Move/copy verified HF candidate to `v3/final/<release-id>`**

- [ ] **Step 3: Record exact metrics, research verdict, fidelity gaps and storage locations in status files**

- [ ] **Step 4: Run full contract suite on final code HEAD**

Commit: `docs(remote-admin): record verified V3 final release`.

---

### Task 10: Destructive V1/V2 cleanup after verified V3

**Files:**
- Create: `.github/workflows/remote-admin-v3-cleanup.yml`
- Create: `remote-admin-anomaly-lab/scripts/cleanup_old_remote_admin.py`
- Create: `remote-admin-anomaly-lab/tests/test_v3_cleanup_guard.py`
- Create: `remote-admin-anomaly-lab/V3_CLEANUP_EVIDENCE.json`

**Interfaces:**
- Cleanup requires `V3_FINAL_STATUS.json` with technical status READY, verified GitHub artifact, and verified HF final path.

- [ ] **Step 1: RED fail-closed tests**

```python
def test_cleanup_refuses_unverified_release():
    status = {"dataset_release_status": "READY", "hf_verified": False, "github_artifact_verified": True}
    with pytest.raises(RuntimeError):
        validate_cleanup_preconditions(status)
```

- [ ] **Step 2: Implement dry-run inventory**

Enumerate remote-admin V1/V2 Actions runs/artifacts and HF paths; emit exact deletion plan JSON before deleting anything.

- [ ] **Step 3: Delete old HF paths**

Using `huggingface_hub` with repository write token, delete V1/V2 `releases`, `quarantine`, old V2 candidate/final/intermediate trees while retaining `v3/final/<release-id>`.

- [ ] **Step 4: Delete old Actions artifacts/runs**

Use GitHub REST from Actions with `GITHUB_TOKEN` and `actions: write`. Keep the final V3 release run/artifact and current V3 verification/cleanup run. Delete V1/V2 smoke/planner/intermediate/final artifacts and obsolete remote-admin workflow runs.

- [ ] **Step 5: Post-delete verify**

Re-list HF paths and GitHub artifacts; fail if any targeted V1/V2 persistent object remains or if V3 final object is missing.

- [ ] **Step 6: Commit cleanup evidence**

`V3_CLEANUP_EVIDENCE.json` stores IDs/paths deleted, retained V3 IDs/path, timestamps and verification status.

Commit: `chore(remote-admin): remove superseded V1 and V2 storage`.

---

### Task 11: Conditional V3 4k scale gate

**Files:**
- Create: `.github/workflows/remote-admin-v3-scale4k.yml`
- Create: `remote-admin-anomaly-lab/scripts/check_v3_scale_decision.py`

**Interfaces:**
- Reads `V3_RESEARCH_DECISION.json`; no V3 4k capture if decision is not `ALLOW_4K`.

- [ ] **Step 1: Add fail-closed scale-decision test**

- [ ] **Step 2: If `ALLOW_4K`, run 4×1000 V3 shards with per-session/per-campaign Bronze and global split-before-state replay**

- [ ] **Step 3: If `STOP_AT_1K`, workflow exits successfully without fan-out and records why**

- [ ] **Step 4: Do not create a 10k workflow until 4k learning-curve evidence exists**

Commit: `ci(remote-admin): gate V3 4k scaling on signal quality`.

---

## Final verification checklist

- [ ] Full branch pytest/static contracts PASS.
- [ ] V3 planner-only 1k gate PASS.
- [ ] V3 80-session real-wire smoke PASS.
- [ ] Same-run Windows and LANL external prerequisites retained.
- [ ] V3 1k records 1000/1000 successful sessions or fails technical release.
- [ ] Per-session PCAP coverage >=99%.
- [ ] Campaign PCAPs and PCAP index are present.
- [ ] No persisted merged PCAP in final HF tree.
- [ ] Session mapping coverage >=98%.
- [ ] Leakage audit PASS.
- [ ] `time_only` PR-AUC <=0.55.
- [ ] Full session model beats current-session-only and best nuisance baseline by >=0.05 PR-AUC.
- [ ] Validation PR-AUC >=0.60 and test PR-AUC >=0.58 for `ALLOW_4K`.
- [ ] Challenge recall at FPR<=1% is non-zero.
- [ ] Hard-benign FPR <=5%.
- [ ] External data rows in training/threshold selection = 0.
- [ ] V3 HF final path verified.
- [ ] V3 final GitHub artifact verified.
- [ ] V1/V2 HF and Actions persistent objects deleted only after both V3 verifications pass.
- [ ] Cleanup post-verification confirms V3 remains intact.
