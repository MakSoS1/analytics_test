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
  - Final GREEN: run `31788947200`; 40/40 real sessions, SSH 25 / SMB 15, benign 32 / suspicious 8, safe service stop and topology teardown.
- [x] M5 — complete Bronze PCAP + manifests/checksums produced.
  - First packaging run `31789349007` captured traffic but failed because root Python could not import `pandas`; partial artifact retained but was not accepted as Bronze.
  - TDD interpreter-propagation RED: run `31789576028`.
  - Final GREEN: run `31789649604`; all jobs PASS.
  - `A-smoke-00`: 40 sessions; raw PCAP 2,710,821 B; retained `pcap.zst` 1,851,067 B.
  - Bronze checksum gate: 8 checksum entries verified, zero errors.
  - Manifest set: sessions JSONL + sessions/ground_truth/hosts/campaigns Parquet + reproducibility metadata.
  - Actions artifact: `remote-admin-bronze-smoke-31789649604`, Artifact ID `9214949423`, artifact size 1,954,386 B, 90-day retention, ZIP SHA256 `dce853d31a4856c8b7216353489b141d059a278e00f7a7fb23ed606162c60d98`.
- [x] M6 — Suricata + Zeek Silver output produced.
  - First Silver attempt `31790193120` proved Bronze valid but failed on root-owned release directory before parser output; partial artifact was retained but not accepted.
  - Ownership handoff fixed: privileged capture now returns the entire output tree to runner UID/GID before Silver/Gold/HF stages.
  - Final GREEN: run `31790538926`; contract, topology, Bronze and Silver gates all PASS.
  - Parser versions: Suricata `7.0.3 RELEASE`; Zeek `8.2.1` pinned as `zeek/zeek:8.2.1`.
  - Parser visibility on the 40-session smoke: 304 Suricata EVE lines, 102 Suricata flow events, 66 SSH-related events, 179 SMB-related events; 102 Zeek `conn.log` lines, 45 SSH log lines, 60 SMB log lines.
  - Important mapping result: 40 orchestrator sessions generated 102 actual TCP connections, therefore Gold must support session→many-flows aggregation and must not assume one manifest row equals one flow.
  - Silver sizes: `eve.json.zst` 11,280 B; `conn.log.zst` 4,870 B.
  - Combined Bronze+Silver Actions artifact: `remote-admin-dataset-smoke-31790538926`, Artifact ID `9215318136`, size 1,974,898 B, ZIP SHA256 `d2c5e4573ba9e3a83eedcbc816b7bfed5126472d4faa6195ea1b5ed7c7a980d8`, 90-day retention.
  - Note: stock Suricata emitted a warning that no external ruleset was loaded; this does not invalidate the parser layer, but M0 deterministic T1021 rules must be added before final model comparison.
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
- M4 final GREEN `31788947200`.
- M5 initial packaging failure `31789349007`; interpreter RED `31789576028`; final GREEN `31789649604`.
- M6 ownership/parser failure `31790193120`; final GREEN `31790538926`.

### Wire / Bronze smoke

- 40/40 successful real sessions.
- SSH: 25; SMB: 15.
- Benign: 32; suspicious: 8.
- Complete PCAP retained compressed, not discarded after feature preparation.
- `src_port` is not invented by the orchestrator: `0` means unknown until observed from PCAP/Suricata/Zeek.
- Latest Bronze in M6: raw 2,710,834 B -> retained zstd 1,848,045 B; 8 checksums validated; ownership safely handed to runner UID/GID 1001:1001.

### Parser smoke

- Suricata `7.0.3 RELEASE`, Zeek `8.2.1`.
- 102 flows/connections observed by both parsers from 40 orchestrator sessions.
- Suricata: 304 EVE / 102 flow / 66 SSH-related / 179 SMB-related.
- Zeek: 102 conn / 45 SSH / 60 SMB log lines.
- Result: Silver contract PASS and raw compressed parser logs retained.

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
- 2026-08-14: an orchestrator cannot truthfully predict the ephemeral source port selected by a real client stack. Planned/executed ground truth therefore keeps `src_port=0`; real source ports are parser-observed fields in Silver/Gold.
- 2026-08-14: root privileges end with capture/topology teardown. Dataset ownership is handed back to the runner before Silver/Gold/HF, preventing privileged parser/model stages.
- 2026-08-14: session manifests are behavioral units, not direct TCP-flow rows. One session may intentionally create multiple flows; feature extraction must aggregate a variable number of parser-observed connections back to one orchestrator session.
