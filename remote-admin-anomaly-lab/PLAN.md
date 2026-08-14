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
- [ ] M1 — configuration/schema contract passes.
- [ ] M2 — canonical scenario planner and ground-truth manifests pass.
- [ ] M3 — namespace topology isolation passes on GitHub Actions.
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

- Status: pending.

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
