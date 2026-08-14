# Remote Admin Anomaly Lab V1 — Living Plan and Results

**Branch:** `remote-admin-anomaly-lab-v1`  
**Started:** 2026-08-14  
**Design spec:** `docs/superpowers/specs/2026-08-14-remote-admin-anomaly-lab-v1-design.md`  
**Implementation plan:** `docs/superpowers/plans/2026-08-14-remote-admin-anomaly-lab-v1.md`

## Rules for this tracker

- A checkbox is marked complete only after test/workflow evidence exists.
- Record run IDs, counts, parser coverage, sizes and storage locations as they become available.
- Do not publish PCAP as GitHub Release assets.
- Bronze full PCAP is the rollback source of truth.
- Suricata alerts are detector output, never ground truth labels.

## Milestones

- [x] M0 — approved design fixed in repository.
  - Evidence: branch created and design/implementation plan committed.
  - Result: V1 excludes Sliver/C2 frameworks and focuses on clean remote-admin behavioral baseline.
- [x] M1 — configuration/schema contract passes.
  - Evidence: `Remote Admin Anomaly V1 Smoke` run `31787756618`, `contract-tests` success.
  - Result: 5/5 configuration tests passed on Ubuntu 24.04 / Python 3.12.13.
  - Validated: unique host IDs/namespaces/IPs, lab-only routing policy, known roles/protocols, safety flags, production feature leakage denylist.
- [x] M2 — canonical scenario planner and ground-truth manifests pass.
  - RED evidence: run `31787871563` failed because `adminlab.manifest` and `adminlab.scenarios` did not exist.
  - GREEN evidence: run `31787949680`, 11/11 tests passed in 0.21s.
  - Validated: deterministic same-seed plans, 200 unique session IDs, lab-only src/dst addresses, nuisance-profile overlap between classes, counterfactual pair label inversion with the same protocol/destination/netem context, orchestrator-owned ground truth without `expected_sid`.
- [ ] M3 — namespace topology isolation passes on GitHub Actions.
  - RED evidence: run `31788020553`, 11 tests passed and 3 topology tests failed because `scripts/setup_topology.sh` did not yet exist.
- [ ] M4 — real SSH/SMB wire smoke passes.
- [ ] M5 — complete Bronze PCAP + manifests/checksums produced.
- [ ] M6 — Suricata + Zeek Silver output produced.
- [ ] M7 — RDP/VNC/DCE-RPC/partial WinRM fidelity matrix measured.
- [ ] M8 — Gold features + grouped splits + leakage audit pass.
- [ ] M9 — HF persistence tested; fallback Actions artifacts documented.
- [ ] M10 — staged dataset fan-out runs.
- [ ] M11 — M0/M1/M2 models trained/evaluated.
- [ ] M12 — NGFW integration and final storage/rebuild instructions documented.

## Storage contract

Expected Hugging Face dataset repository: `Maksim123321/remote-admin-anomaly-v1`.

Per release/shard:

```text
releases/<run-id>/<shard>/
├── bronze/<shard>/
│   ├── captures/<shard>.pcap.zst
│   ├── manifests/
│   ├── reproducibility.json
│   └── checksums.sha256
├── silver/<shard>/
│   ├── suricata/eve.json.zst
│   ├── zeek/*.zst
│   └── parser_versions.json
├── gold/<shard>/
│   ├── flow_features.parquet
│   ├── window_features.parquet
│   ├── graph_features.parquet
│   └── splits.parquet
└── quality/<shard>/
    ├── capture_health.json
    ├── parser_health.json
    └── leakage_checks.json
```

If `HF_TOKEN` is unavailable in `analytics_test`, the same release tree must remain in a 90-day GitHub Actions artifact and the missing-HF blocker is recorded below. GitHub secrets are not readable, so no attempt is made to extract the value from `Ansible_lab`.

## Run results

### Configuration / unit tests

- 2026-08-14 — M1 RED: run `31787693161` failed as expected because `adminlab` did not exist.
- 2026-08-14 — M1 GREEN: run `31787756618` passed 5/5 configuration tests.
- 2026-08-14 — M2 RED: run `31787871563` failed on missing manifest/planner modules.
- 2026-08-14 — M2 GREEN: run `31787949680` passed 11/11 tests.
- 2026-08-14 — M3 RED: run `31788020553` passed 11 existing tests and failed 3 new topology tests on the intentionally missing topology script.

### Wire smoke

- Status: pending.

### Parser smoke

- Status: pending.

### HF persistence

- Status: pending.

### Dataset shards

- Status: pending.

### Model evaluation

- Status: pending.

## Discovered limitations / design changes

- 2026-08-14: local assistant container cannot resolve `github.com`, so target-environment verification is performed by GitHub Actions rather than a local clone. Repository work remains isolated in `remote-admin-anomaly-lab-v1`.
- 2026-08-14: unrelated legacy `mbi-hourly-monitor.yml` also runs on branch pushes and may fail independently; remote-admin evidence is tracked only from the dedicated `remote-admin-smoke.yml` workflow.
