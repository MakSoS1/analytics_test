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
- [x] M1 — configuration/schema contract passes. Evidence: run `31787756618`, 5/5 tests PASS.
- [x] M2 — canonical scenario planner and ground-truth manifests pass. Evidence: run `31787949680`, 11/11 tests PASS.
- [x] M3 — namespace topology isolation passes. Evidence: run `31788233293`; 15 namespaces, internal connectivity PASS, external/default-route isolation PASS.
- [x] M4 — real SSH/SMB wire smoke passes.
  - Initial functional evidence: run `31788604772` executed 40/40 real sessions successfully but exposed a cleanup defect after artifact upload.
  - Cleanup RED: run `31788781815`, 18 PASS / 1 expected cleanup-contract FAIL.
  - Final GREEN: run `31788947200`; contract-tests, topology-smoke and wire-smoke all PASS, including safe service stop and topology teardown.
  - Wire result: 40 success / 0 failed; SSH 25, SMB 15; benign 32, suspicious 8; no external targets; no payload execution.
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

If `HF_TOKEN` is unavailable in `analytics_test`, the same release tree must remain in a 90-day GitHub Actions artifact. GitHub secrets are non-readable, so no attempt is made to extract the value from `Ansible_lab`.

## Run results

### Configuration / unit tests

- M1 RED `31787693161` -> GREEN `31787756618`.
- M2 RED `31787871563` -> GREEN `31787949680`.
- M3 RED `31788020553` -> GREEN `31788233293`.
- M4 RED `31788309962`; functional-but-cleanup-failed `31788604772`; cleanup RED `31788781815`; final GREEN `31788947200`.

### Wire smoke

- 40/40 successful real sessions.
- SSH: 25; SMB: 15.
- Benign: 32; suspicious: 8.
- Process-group cleanup uses dedicated `setsid` groups; teardown no longer terminates the Actions shell.

### Parser smoke

- Status: pending.

### HF persistence

- Status: pending.

### Dataset shards

- Status: pending.

### Model evaluation

- Status: pending.

## Discovered limitations / design changes

- 2026-08-14: local assistant container cannot resolve `github.com`; target-environment verification is performed by GitHub Actions.
- 2026-08-14: unrelated legacy `mbi-hourly-monitor.yml` may fail independently; only the dedicated remote-admin workflow is used as project evidence.
- 2026-08-14: endpoint daemons must run in dedicated process groups. Broad namespace PID cleanup was removed after it terminated the Actions job despite successful traffic generation.
