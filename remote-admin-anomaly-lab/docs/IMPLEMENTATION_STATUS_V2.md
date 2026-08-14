# Remote Admin Anomaly V2 — Final Implementation Status

Date: 2026-08-14

V2 is technically complete as a reproducible dataset release. The scientific result is intentionally **negative**: the dataset/evaluation pipeline passes its technical gates, but the session-primary detector does not pass the V2 research-quality gate. Therefore the release is retained and persisted as a quarantine research artifact and **must not be scaled to 4k yet**.

## Final verdict

- Dataset release status: **READY**.
- Research status: **FAIL**.
- Scale decision: **STOP_AT_1K**.
- Technical failures: none.
- Automatic research failures:
  - validation PR-AUC below target;
  - test PR-AUC below target;
  - session-primary model does not beat the best shortcut baseline by the required margin.

The failed research gate is not treated as a failed dataset build. V2 remains a complete, recoverable negative research release.

## Authoritative runs and provenance

### Data generation

- GitHub Actions run: `31831956891`.
- Data-generation Git SHA: `ebe12195545f3612ef5204fe1cb505b1cb8b0e90`.
- The full 1k capture was generated once and was not regenerated during finalization.

### Finalization

- Final recovery/finalization run: `31835350024` — **PASS**.
- Finalization Git SHA: `0625582a8c6aeaafc1810a8fff1a5dbb80a07544`.
- Final Actions artifact: `remote-admin-v2-final-31835350024`.
- Artifact ID: `9232297940`.
- Artifact size: `299,111,227` bytes.
- Artifact digest: `sha256:e533705143a69975d5880bd7cb4423a2f9a8cb60d24b6fc19b32b76306599569`.
- Retained until: `2026-11-12T19:53:53Z`.

### Final regression gate

- `Remote Admin Anomaly V2 Contract Tests` run `31835350082` on SHA `0625582a8c6aeaafc1810a8fff1a5dbb80a07544` — **PASS**.

## Linux V2 1k corpus

The final Bronze corpus contains exactly:

- 1,000 / 1,000 successful behavioral sessions;
- 500 benign / 500 suspicious;
- SSH: 250;
- SMB: 250;
- RDP: 250;
- VNC: 250;
- 125 benign + 125 suspicious inside every protocol;
- 45 simulated days represented for each protocol;
- 150 matched benign/suspicious counterfactual pairs = 30% of all session rows;
- zero invalid counterfactual pairs.

The exact retained compressed PCAP is:

- `bronze/V2-1k/captures/V2-1k.pcap.zst`;
- 236,099,245 bytes;
- Bronze checksum contract: PASS, eight checksum entries verified.

The planner used a 16,000-row candidate pool and produced 18 distinct semantic families in the selected 1k corpus: 11 benign families and 7 suspicious families.

## Semantic families represented

Benign families include:

- `routine_admin`;
- `scheduled_patch_fanout`;
- `backup_burst`;
- `helpdesk`;
- `incident_response`;
- `new_server`;
- `new_admin`;
- `service_automation`;
- `jump_host`;
- `offhours_emergency`;
- `benign_first_seen`.

Suspicious families include:

- `credential_hop_like`;
- `failed_then_success`;
- `low_slow_lateral`;
- `new_protocol`;
- `offhours_lateral`;
- `protocol_switch`;
- `small_copy_then_admin`.

The current-session wire controls of counterfactual pairs are label-neutral. Labels/intent/semantic metadata are not used to choose nuisance controls or implementation variants.

## Parser-backed flow Gold

The production unit remains a parser-observed Suricata flow.

Final V2 flow evidence:

- raw Suricata flow rows: 2,625;
- background flow rows: 481;
- eligible behavioral flow rows: 2,144;
- mapped production flow rows: 2,122;
- flow mapping coverage: **98.9739%**;
- session mapping coverage: **98.9%**;
- UID alignment coverage: **100%**;
- leakage audit: **PASS**.

Session mapping by protocol:

- RDP: 100%;
- SMB: 100%;
- SSH: 95.6%;
- VNC: 100%.

The primary model contains no evaluation/orchestrator metadata. Zeek data is retained for research evidence but is not part of the primary production feature matrix.

Unseen implementation challenge holdouts are real and group-isolated:

- `ssh:paramiko->openssh-server`;
- `smb:smbprotocol->samba`.

Challenge reasons also include future temporal groups and an unseen host pair. Campaigns and counterfactual pairs are indivisible split groups.

## Hierarchical Gold

V2 now has three explicit modeling units:

1. flow Gold;
2. session Gold;
3. campaign Gold.

Final hierarchy:

- parser-backed flow rows: 2,122;
- session rows: 989;
- session features: 44;
- campaign rows: 191;
- campaign features: 18;
- external rows in training Gold: 0.

Session class counts:

- benign: 493;
- suspicious: 496.

Session splits:

- train: 83;
- validation: 22;
- test: 25;
- challenge: 859.

Campaign splits:

- train: 16;
- validation: 5;
- test: 5;
- challenge: 165.

History features use strictly prior session event time. Raw source/destination identity is used only as ephemeral causal state and does not enter the model matrix.

## Native Windows external holdout

The final same-run Windows cohort was captured on `windows-2025` using real `pktmon` evidence and a fail-closed fidelity validator.

Validated native Windows protocols:

- OpenSSH — `native_windows_validated`;
- SMB — `native_windows_validated`;
- WinRM — `native_windows_validated`.

Not promoted beyond the evidence:

- DCOM — session completed, but port 135 wire evidence was not observed in this final run; status `attempted_unverified`;
- RDP — hosted runner could not prove an interactive native RDP session; status `unavailable_hosted_runner`.

Final pktmon evidence counts:

- TCP/22: 17;
- TCP/445: 1;
- TCP/5985: 370;
- TCP/135: 0;
- TCP/3389: 0.

The retained Windows PCAPNG does not expose conventional Wireshark `tcp.stream` fields on the Linux recovery runner. External evaluation therefore uses the retained formatted pktmon packet evidence as the parser fallback. This does not weaken the native-fidelity gate: only protocols already marked `native_windows_validated` are scored.

The final external adapter mapped 11 Windows session-like references:

- OpenSSH: 1;
- SMB: 1;
- WinRM: 9.

Windows external scores are finite and non-degenerate. No Windows row is used for fitting or threshold tuning.

## Independent LANL reference

V2 contains an independent enterprise operational reference derived from the LANL Unified Host and Network Data Set lineage. The direct LANL data-fence requires authorization, so the automated transport uses the documented Rocketgraph/xGT mirror while retaining LANL provenance and documenting the mirror transformations.

Final bounded reference:

- remote-admin network flows: 5,000;
- Windows network-logon events: 5,000;
- synthetic labels: none;
- external-only: true;
- threshold tuning allowed: false.

Remote-admin port counts in the 5,000-flow slice:

- TCP/22: 224;
- TCP/135: 321;
- TCP/445: 4,439;
- TCP/5986: 16.

The external LANL score distribution is finite/non-degenerate and has 0 threshold exceedances at the Linux validation-selected session threshold. It is reference evidence, not supervised ground truth.

## Model results

### Flow baseline

The flow view remains a baseline and is not the V2 decision unit.

### Session primary

Final LightGBM session-primary metrics:

- validation PR-AUC: **0.5246163491**;
- test PR-AUC: **0.5447247842**;
- challenge PR-AUC: **0.5031918670**;
- selected threshold: `0.8986076382450815`.

At the selected threshold:

- validation recall: 0;
- test recall: 0;
- challenge recall: **0.00936768**;
- challenge FPR: **0.00694444**.

At the strict challenge `FPR <= 1%` operating point:

- threshold: `0.8788951050877135`;
- recall: **0.01639344**;
- precision: **0.63636**;
- FPR: **0.00925926**.

This is still far below a production-quality anomaly detector.

### Shortcut audit

Best nuisance-only baseline: `time_only`.

- `time_only` validation PR-AUC: **0.5883155788**;
- full session-primary validation PR-AUC: **0.5246163491**;
- shortcut margin: **-0.0636992297**;
- required margin: `+0.05`;
- shortcut risk: **true**.

This is one of the decisive reasons V2 is not allowed to scale.

### Hard-benign evaluation

The current threshold produced:

- hard benign rows: 185;
- false positives: 0;
- hard-benign FPR: **0.0**;
- FP / 10k hard benign: 0.

The hard-negative set includes approved forwarding, backup, emergency administration, incident response, off-hours response, new-pair and multi-target/multi-protocol legitimate administration cases.

### Learning curve

Grouped session learning curve final delta:

- last PR-AUC delta: **+0.0467336975**.

The isolated learning-curve rule would recommend expansion, but scaling is an AND-gated decision. The PR-AUC targets and shortcut margin fail, so the final scale decision remains **STOP_AT_1K**.

## Final research gate

Configured requirements include:

- validation PR-AUC >= 0.65;
- test PR-AUC >= 0.60;
- full session model must beat best shortcut baseline by >= 0.05;
- hard-benign FPR <= 0.05;
- challenge recall must be non-zero;
- at least one mapped native Windows protocol;
- independent LANL reference complete;
- positive final grouped learning-curve delta for scaling.

Final automatic failures:

1. `validation_pr_auc`;
2. `test_pr_auc`;
3. `shortcut_margin`.

Therefore:

```text
dataset_release_status = READY
research_status        = FAIL
scale_decision         = STOP_AT_1K
```

This is the intended fail-closed behavior. More rows from the same generator are not authorized.

## Persistence and rollback

The authoritative GitHub artifact stores the exact unmodified release tree. The complete release contains 87 files and 299,079,028 bytes according to `V2_RELEASE_MANIFEST.json`.

Layer sizes recorded in the immutable manifest:

- Bronze: 239,073,223 bytes;
- Silver: 930,861 bytes;
- Gold: 1,647,617 bytes;
- Quality/external evidence: 57,427,327 bytes.

Private Hugging Face persistence completed successfully:

- repo: `Maksim123321/remote-admin-anomaly-v1`;
- path: `v2/quarantine/data-run-31831956891-final-31835350024`;
- status: `uploaded`.

The HF copy preserves all four release layers: `bronze`, `silver`, `gold`, `quality`.

One transport-only transformation is necessary for Hub compatibility: Windows `capture.txt` is UTF-16 and is stored in the HF transport copy as deterministic lossless `capture.txt.gz`. `HF_PERSISTENCE_TRANSFORMS.json` records the original/stored SHA-256 hashes, byte sizes and restore command. The authoritative GitHub artifact retains the original `capture.txt` unchanged.

Original pktmon text:

- size: 4,941,660 bytes;
- SHA-256: `db2044591fa3e2f2078d5b71fe2af7cb278840987dfefff622bd0e574bfa3f31`.

HF gzip transport object:

- size: 108,890 bytes;
- SHA-256: `4850608d7834399678399dbde9c50019900decbaa647bf2ff189225f6e1918a8`.

## What V2 solved compared with V1

V2 closes the major dataset-engineering gaps identified after V1:

- native Windows evidence exists and is external-only;
- an independent LANL-derived operational reference exists and is external-only;
- the primary representation is session-level, with a campaign layer above it;
- counterfactual behavior is a property of the captured corpus, not only post-hoc documentation;
- semantic families and hard benign cases are substantially broader;
- implementation holdouts are explicitly isolated;
- external evidence cannot enter fit or threshold selection;
- research failure and technical release failure are separate states;
- persistence contains complete rollback/provenance evidence.

What V2 does **not** prove is that the current network feature representation is already sufficient for production Remote Admin Anomaly detection. The final shortcut audit and PR-AUC values show that it is not.

## Next authorized research step

Do **not** run `1k -> 4k` from this generator yet.

The next V3 research iteration should target the failed signal rather than volume, especially:

- remove/rebalance time-of-day shortcut structure across benign/suspicious counterfactuals;
- increase campaign continuity so train/validation/test contain materially more independent campaigns while preserving challenge holdouts;
- create matched same-time legitimate and suspicious sequences;
- strengthen historical graph/context differences while keeping current-session packet statistics matched;
- add a native Windows RDP environment outside hosted GitHub runners if interactive RDP fidelity is required;
- obtain wire-verified DCOM in a Windows environment where TCP/135/RPC endpoint mapper traffic is observable;
- repeat the 1k gate before any 4k scale authorization.
