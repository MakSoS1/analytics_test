# Remote Admin Anomaly Lab V1 — Design Specification

**Status:** APPROVED — 2026-08-14  
**Branch:** `remote-admin-anomaly-lab-v1`  
**Repository:** `MakSoS1/analytics_test`  
**Primary purpose:** build a reproducible, network-first laboratory and dataset for detecting anomalous remote-administration activity in an NGFW/NDR setting using Suricata telemetry plus behavioral ML.

## 1. Research objective

V1 must replace the previous packet-builder-only ML approach with a real-wire laboratory in which actual client and server implementations communicate across an isolated Linux network, while retaining the old synthetic PCAP generator only as a protocol/rule regression suite.

The central research question is not “does a Suricata SID fire on a hand-crafted positive PCAP?” but:

> Can a network-only detector distinguish legitimate remote administration from suspicious remote administration when both use the same protocols, normal ports, valid lab credentials, realistic timing, overlapping hosts, overlapping network conditions, and hard counterfactual pairs?

The production visibility target is restricted to what can reasonably be available to an NGFW/Suricata pipeline: packet/flow/session/protocol metadata, temporal windows, topology/novelty state and graph-derived network behavior. Host and identity telemetry may be generated or retained as ground truth/context, but it must not silently leak into the network-only production model.

## 2. What V1 deliberately does not include

V1 does **not** run Sliver, Mythic, Havoc, Cobalt Strike, Metasploit payloads, malware, credential dumping, persistence, unrestricted proxying, external C2, or real-world targets.

Reasons:

1. First establish a clean remote-admin behavioral baseline before introducing framework-specific artifacts.
2. Avoid allowing a model to learn “Sliver fingerprint = malicious” instead of anomalous administrative behavior.
3. Keep the dataset attribution clear: remote-service anomaly first, adversarial C2/pivoting challenge later.
4. Keep GitHub-hosted runners isolated and safe.

A future V2/V3 challenge phase may add bounded C2/pivot simulations only after V1 baseline and holdout performance are stable.

## 3. Corrections to the previous research approach

The old 28-PCAP experiment is reclassified as a **Suricata/protocol regression suite**, not an ML generalization benchmark.

### 3.1 Problems to remove

- Positive PCAPs were intentionally constructed to satisfy known SID/flowbit conditions.
- Negative PCAPs were intentionally constructed to break those conditions.
- Labels were too strongly correlated with source network, scenario name, timing and generator choices.
- The dataset was too small for behavioral ML.
- Generated packets approximated protocol behavior rather than exercising real implementations and kernel TCP/IP stacks.
- Suricata output was too close to the generation logic to serve as independent ground truth.
- A random row split could leak related users, host pairs, campaigns and generators between train and test.
- Some proposed feature fields are not necessarily available on the target NGFW and therefore must not enter the production feature contract by assumption.

### 3.2 Required corrections

- Ground truth comes from the scenario orchestrator, never from Suricata alerts.
- Real client/server processes generate the main corpus.
- Same hosts, time ranges, netem profiles and implementations appear in both classes.
- Bronze PCAP is retained as the rollback source of truth.
- Challenge splits hold out users, host pairs, time blocks and implementations.
- Hard benign and hard suspicious examples are first-class dataset stages.
- Old synthetic builders remain only under `protocol-regression/` for parser/rule edge cases.

## 4. Core architecture

Each GitHub-hosted Ubuntu runner creates a self-contained virtual enterprise network using Linux network namespaces, veth pairs and one monitoring bridge.

A typical shard contains 20–30 endpoint identities:

- admin workstations / PAWs;
- jump host;
- developer workstations;
- ordinary user workstations;
- Linux servers;
- file server;
- RDP server;
- VNC server;
- RPC/Samba service host;
- monitoring namespace / bridge capture point.

Each namespace has:

- its own IPv4 address and role metadata;
- no unrestricted default route to the Internet;
- only explicitly defined routes inside the lab;
- one or more real service/client processes;
- scenario-scoped credentials and files containing inert synthetic data only.

The monitoring bridge is captured with `tcpdump`. The resulting PCAP is processed offline by Suricata and Zeek.

## 5. Protocol fidelity plan

### 5.1 SSH — high fidelity

Real OpenSSH server/client, including:

- interactive command sessions using harmless commands;
- `scp`/`sftp` transfers of inert generated files;
- jump-host style access;
- successful and failed authentication attempts inside the lab;
- repeated and low-and-slow connection patterns.

### 5.2 SMB — high fidelity for SMB wire behavior

Real Samba + `smbclient`:

- ordinary user shares;
- administrative-style shares in the isolated lab;
- small and bulk file transfers;
- repeated share access;
- multi-target administrative access patterns.

No payload execution or malware deployment is performed. Suspicious file transfers use inert marker files.

### 5.3 RDP — real RDP wire behavior on Linux

Use xrdp/FreeRDP where practical on GitHub-hosted Ubuntu runners.

Scenarios include:

- ordinary administrative sessions;
- helpdesk-like short sessions;
- long sessions;
- reconnects;
- repeated short sessions;
- new source/destination relationships;
- off-profile but legitimate hard negatives.

Native Windows RDP semantics are reserved for a later Windows-fidelity challenge corpus.

### 5.4 VNC / RFB — real implementation

Use a lightweight VNC server/client pair where available on the runner. Retain RFB handshake/auth/session metadata in Suricata/Zeek when exported.

### 5.5 DCE/RPC — real wire traffic, partial DCOM semantics

Use Samba/RPC tooling to generate real DCE/RPC traffic. Mark fidelity explicitly:

- `wire_fidelity=real_dcerpc_samba`
- `semantic_fidelity=partial_dcom`

Do not claim that Linux Samba traffic reproduces all native Windows DCOM behavior.

### 5.6 WinRM — partial fidelity in V1

Where practical, generate WS-Man/HTTP(S)-style management traffic with explicit `semantic_fidelity=partial_winrm`.

Native Windows WinRM becomes a later fidelity holdout.

## 6. Personas and behavior

Personas are independent of labels. A normally trusted persona can participate in a suspicious scenario, and a workstation that superficially looks unusual can participate in a benign scenario.

Initial personas:

- `DomainAdmin`
- `ServerAdmin`
- `LinuxAdmin`
- `Helpdesk`
- `Developer`
- `ServiceAccount`
- `RegularUser`
- `RemoteWorker`
- `JumpHost`
- `CompromisedWorkstation`

Behavior is generated from role-dependent distributions for:

- protocol preference;
- destination preference;
- session duration;
- session count;
- bytes transferred;
- reconnect probability;
- authentication-failure probability;
- fan-out;
- start/end of workday;
- maintenance windows;
- occasional legitimate off-hours work.

Time-of-day must never be a deterministic label shortcut.

## 7. Scenario taxonomy

### Stage A — wire/parser smoke

Purpose: prove that real services, capture, Suricata, Zeek and manifest mapping work before expensive fan-out.

Target: ~1,000 short sessions across supported protocols.

### Stage B — ordinary benign

Target: ~60,000 sessions.

Examples:

- PAW/jump-host administration;
- SSH/SFTP maintenance;
- normal file-share use;
- scheduled backup-like SMB activity;
- ordinary helpdesk RDP/VNC;
- developer SSH.

### Stage C — hard benign

Target: ~40,000 sessions.

Examples:

- emergency off-hours maintenance;
- new administrator or new PAW;
- legitimate multi-host deployment;
- legitimate administrative share access;
- repeated password typo/reconnect;
- long transfer;
- rare VNC support;
- trusted jump-host fan-out.

### Stage D — ordinary suspicious

Target: ~30,000 sessions.

Examples:

- burst authentication attempts;
- unusually high fan-out;
- repeated short remote sessions;
- novel destination relationships;
- unusual protocol for a source role;
- unusual bulk transfer.

### Stage E — hard suspicious

Target: ~30,000 sessions.

Examples:

- valid lab credentials;
- internal compromised source;
- activity during ordinary business hours;
- slow/low-rate attempts;
- one destination at a time;
- normal ports;
- normal client implementation;
- normal latency;
- trusted-subnet source with anomalous relationship;
- gradual lateral expansion.

### Stage F — counterfactual pairs

Target: ~20,000 sessions.

Each pair minimizes superficial differences while changing intent/context. Pair members must stay in the same dataset split.

### Stage G — sequence/campaign corpus

Target: ~10,000 sessions/events grouped into multi-step administrative campaigns for sequence and graph analysis.

### Stage H — challenge holdout

Target: ~10,000 sessions covering held-out users, host pairs, time periods, implementations, and difficult nuisance profiles.

V1 target total: approximately 200,000 completed remote-admin sessions.

## 8. Counterfactual design

Counterfactual pairs are mandatory.

Example family 1:

- benign: PAW → server, RDP, normal hours, valid lab credentials, 15 minutes;
- suspicious: ordinary workstation → same server, same RDP implementation, same hours, same approximate duration, valid lab credentials, but the relationship is novel and part of a suspicious campaign.

Example family 2:

- benign: jump host → many SSH destinations for deployment;
- suspicious: same jump-host identity → many SSH destinations as a lateral-expansion campaign.

Labels must not be recoverable from obvious source ranges, filenames, scenario IDs or generation seeds.

## 9. Network nuisance profiles

Profiles are assigned independently of label:

- `clean`
- `lan_jitter`
- `wan_20ms`
- `wan_80ms`
- `remote_vpn`
- `lossy_wifi`
- `constrained`
- `reorder`
- `low_mtu`

Both benign and suspicious traffic must cover every supported profile where technically possible.

## 10. Canonical ground truth

The scenario orchestrator writes the source-of-truth manifest before/while executing each scenario.

Required fields:

- `campaign_id`
- `scenario_id`
- `session_id`
- `pair_id`
- `label_binary`
- `label_family`
- `mitre_technique`
- `src_role`
- `dst_role`
- `src_host_id`
- `dst_host_id`
- `protocol`
- `wire_fidelity`
- `semantic_fidelity`
- `ground_truth_source`
- `netem_profile`
- `generator_seed`
- `start_ts`
- `end_ts`

The following fields are forbidden from production ML features:

- label fields;
- `scenario_id`;
- `campaign_id`;
- `pair_id`;
- `generator_seed`;
- expected Suricata SID;
- filenames containing labels/scenario families;
- orchestration-only markers.

## 11. Bronze / Silver / Gold storage contract

PCAP must **not** be published as GitHub Releases.

### Bronze — immutable rollback source

`release/bronze/<shard>/`

Contains:

- `captures/<shard>.pcap.zst` — complete packet capture;
- `manifests/campaigns.parquet`;
- `manifests/sessions.parquet`;
- `manifests/hosts.parquet`;
- `manifests/ground_truth.parquet`;
- `reproducibility.json`;
- checksums.

Bronze is retained so that any future parser/feature contract can be regenerated without re-running traffic generation.

### Silver — parser output and normalized telemetry

`release/silver/<shard>/`

Contains:

- `suricata/eve.json.zst`;
- raw Zeek logs compressed individually;
- normalized flow/session/protocol Parquet tables;
- parser version metadata.

### Gold — ML-ready features

`release/gold/<shard>/`

Contains:

- `flow_features.parquet`;
- `window_features.parquet`;
- `graph_features.parquet`;
- `sequence_features.parquet` when applicable;
- `splits.parquet`;
- feature contract hash;
- leakage-audit report.

### Quality

`release/quality/<shard>/`

Contains:

- capture health;
- parser health;
- mapping coverage;
- checksums;
- leakage checks;
- scenario counts;
- class/profile distributions.

## 12. Persistence policy

Primary large-artifact persistence target is Hugging Face dataset storage, not GitHub Releases.

Expected policy:

1. Source code/config/docs live in GitHub.
2. Every completed shard is uploaded to a unique HF path immediately after quality gates pass.
3. GitHub Actions artifacts retain the same shard temporarily for recovery/debugging.
4. Bronze PCAP remains available in HF so Silver/Gold can be regenerated.
5. No secret or token value is written to logs, manifests or source.

The workflow expects a repository secret named `HF_TOKEN` in `MakSoS1/analytics_test`.

A secret stored only in another repository cannot be read back or copied by code because GitHub repository secrets are intentionally non-readable. Therefore V1 will:

- first test whether `analytics_test` already has a usable `HF_TOKEN` by attempting an authenticated, non-secret-printing HF operation;
- if absent, preserve artifacts in GitHub Actions and clearly report that one-time secret provisioning is required;
- never print or exfiltrate a secret from `Ansible_lab`.

Default HF dataset repository name for V1: `Maksim123321/remote-admin-anomaly-v1` unless an existing compatible dataset repository is discovered/configured.

## 13. Feature contract

### 13.1 Flow/session features

- duration;
- bytes/packets by direction;
- directional ratios;
- TCP state/flags;
- resets;
- retransmission-related counters when available;
- application protocol;
- service port category;
- Suricata flow/app-proto metadata.

### 13.2 Timing features

- packet/session IAT statistics;
- burstiness;
- duration relative to source/protocol baseline;
- reconnect spacing;
- periodicity proxies.

### 13.3 Novelty features

- new destination for source;
- new source/destination pair;
- new protocol for source;
- days/time since pair last observed;
- pair/source frequency percentiles.

### 13.4 Stateful windows

Required windows:

- 1 minute;
- 5 minutes;
- 15 minutes;
- 1 hour;
- 24-hour baseline;
- 7-day baseline where corpus chronology permits it.

Examples:

- connections per window;
- unique destinations;
- unique remote-admin protocols;
- failed/short/reset session rate;
- fan-out/fan-in;
- bytes per window;
- new-edge count.

### 13.5 Graph-derived features

Treat hosts as nodes and remote-admin sessions as directed edges.

Features include:

- new edge;
- source out-degree change;
- destination fan-in;
- component expansion proxy;
- destination rarity;
- protocol entropy;
- first-time traversal;
- edge recurrence/frequency.

## 14. Dataset split contract

No random row split.

Nominal allocation:

- train: 60%;
- validation: 15%;
- test: 15%;
- challenge: 10%.

Constraints:

- campaigns never cross splits;
- counterfactual pairs never cross splits;
- selected users are completely held out;
- selected host pairs are completely held out;
- a final temporal block is test/challenge only;
- at least one client implementation per relevant protocol is held out when more than one implementation exists;
- scenario-family challenge cases may be absent from train by design.

## 15. Model plan

### M0 — deterministic Suricata baseline

Purpose: measure what signatures, thresholding and policy rules already detect.

### M1 — LightGBM supervised production candidate

Primary input:

- flow/session;
- temporal windows;
- novelty;
- graph aggregates.

Outputs:

- calibrated binary suspiciousness score;
- optional family classifier.

LightGBM is preferred for V1 because the feature space is heterogeneous/tabular and inference must remain lightweight enough for an NGFW-adjacent sidecar.

### M2 — benign-only anomaly expert

Initial methods:

- robust per-role/per-protocol quantile/MAD baseline;
- Isolation Forest.

Purpose: measure generalization to suspicious behavior absent from supervised training.

### M3 — sequence model after tabular baseline

Use a small TCN over the last 32/64/128 remote-admin events after M1/M2 are validated.

GNNs and Transformers are explicitly deferred unless ablations show a material residual gap.

## 16. Evaluation contract

Report at minimum:

- PR-AUC;
- ROC-AUC;
- Precision;
- Recall;
- F1;
- Recall at FPR 1%;
- Recall at FPR 0.1% when support is sufficient;
- false positives per 10,000 benign sessions;
- Brier/calibration error;
- per-protocol metrics;
- per-scenario-family metrics;
- hard-benign FPR;
- hard-suspicious recall;
- unseen-user metrics;
- unseen-host-pair metrics;
- temporal holdout metrics;
- held-out implementation metrics.

For sequence/campaign models also report:

- campaign recall;
- events-to-detection;
- time-to-detection.

Bootstrap confidence intervals must resample by campaign, not individual rows.

## 17. NGFW integration design

The target architecture uses three layers rather than trying to convert ML into Suricata signatures.

### Layer 1 — Suricata deterministic detection

Use signatures/thresholds for:

- forbidden protocol/zone combinations;
- known policy violations;
- obvious rate bursts;
- protocol-specific deterministic evidence available to Suricata.

### Layer 2 — ML sidecar/post-analysis

Data path:

`Suricata EVE -> normalizer/state store -> feature builder -> M1/M2/(M3) -> calibrated risk event`

The production feature builder must consume only fields available in the target network telemetry contract.

### Layer 3 — optional controlled feedback

Initial V1 mode is alert-only.

Blocking/dynamic Suricata dataset feedback is not enabled solely from an anomaly score. A future mitigation mode may require multiple independent signals and explicit acceptance testing.

## 18. Safety boundary

- No Internet targets are attacked or scanned.
- No unrestricted proxy is created.
- No malware or C2 agent is executed in V1.
- No real credentials or user documents are used.
- Suspicious transfers use generated inert marker data.
- Simulated hosts have no unrestricted external route.
- Workflows must fail closed if isolation cannot be established.

## 19. CI/CD architecture

Workflows:

1. `remote-admin-smoke.yml`
   - install dependencies;
   - create topology;
   - generate a small real-wire corpus;
   - capture PCAP;
   - run Suricata/Zeek;
   - validate manifest mapping and storage contract.

2. `remote-admin-dataset.yml`
   - smoke gate first;
   - matrix shards with bounded parallelism;
   - Stage B–H generation;
   - quality gates;
   - artifact retention;
   - HF upload when `HF_TOKEN` is available.

3. `remote-admin-train-eval.yml`
   - merge/reuse Gold shards;
   - leakage audit;
   - train M0/M1/M2;
   - evaluate challenge splits;
   - retain models/reports.

4. `remote-admin-release.yml`
   - publish dataset/model metadata and checksums;
   - do **not** publish PCAP as GitHub Release assets.

## 20. Required quality gates

A shard fails if any of the following is true:

- PCAP missing or empty;
- capture cannot be parsed;
- Suricata exits non-zero or EVE is empty;
- Zeek exits non-zero or `conn.log` is empty;
- less than 99% of expected completed sessions map to network evidence for protocols where deterministic mapping is implemented;
- duplicate `session_id`/`campaign_id` violates schema;
- class labels leak into feature columns;
- counterfactual pair crosses splits;
- held-out user/host-pair leaks into train;
- required checksums/reproducibility metadata are absent;
- isolation/default-route safety check fails.

## 21. Living progress and result tracking

The implementation must maintain `remote-admin-anomaly-lab/PLAN.md` as a live tracker.

Every completed milestone records:

- completion date/time;
- commit SHA or workflow run identifier;
- test result;
- generated session/PCAP counts;
- parser coverage;
- artifact/HF path;
- discovered limitations;
- any design change and its reason.

No task is marked complete merely because code exists; the corresponding test/evidence must exist.

## 22. Definition of done for V1

V1 is complete only when all of the following hold:

1. Separate branch and documented design/implementation plan exist.
2. Isolated real-wire topology runs on GitHub Actions.
3. SSH and SMB real-wire smoke corpus passes end-to-end.
4. RDP/VNC/DCE-RPC/partial WinRM support is implemented or explicitly quality-gated as unavailable with evidence, without falsifying fidelity.
5. Bronze/Silver/Gold/quality layers are produced.
6. Bronze retains full PCAP and ground-truth manifests.
7. Suricata and Zeek parse the corpus.
8. Split/leakage audits pass.
9. M0, M1 and M2 baselines are trained/evaluated from Gold data.
10. Challenge metrics are reported separately from ordinary test metrics.
11. Dataset shards are persisted to HF when credentials are available; otherwise recoverable GitHub Actions artifacts remain and the missing credential is reported without leaking secrets.
12. `PLAN.md` contains actual results and final storage locations.
13. No PCAP is published as a GitHub Release asset.
