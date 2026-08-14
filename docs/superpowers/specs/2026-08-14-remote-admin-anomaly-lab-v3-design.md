# Remote Admin Anomaly Lab V3 — Signal Design Specification

Date: 2026-08-14
Branch: `remote-admin-anomaly-lab-v3`
Parent baseline: final V2 release commit `8f4029bbc13a4422fd94143931bf71041ebac920`

## 1. Goal

V3 fixes the scientific failure mode demonstrated by V2: nuisance/time-only features must no longer explain the label better than the intended behavioral/history signal.

The objective is not to increase row count first. The objective is to construct a 1,000-session real-wire corpus where benign and suspicious current sessions are deliberately hard to separate by current bytes, duration, rate, implementation, network impairment, or time-of-day, while remaining separable through prior graph/history and multi-session sequence context.

V3 keeps the defensive isolated-lab scope. No external targets, payload execution, malware, credential theft, or C2 frameworks are introduced.

## 2. Hard constraints

- Compute: GitHub-hosted runners only.
- Linux corpus: isolated `10.77.0.0/24` network namespace lab, no default route.
- Windows fidelity: GitHub-hosted `windows-2025` only.
- Native Windows RDP/DCOM are fail-closed: V3 records them as validated only when the hosted runner produces both completed session evidence and packet-level wire evidence. Otherwise they remain `attempted_unverified`/`unavailable_hosted_runner`.
- HF is the persistent final storage destination.
- V1/V2 GitHub Actions artifacts/runs and HF dataset paths are deleted only after V3 final artifact, checksum manifest, HF upload, and HF verification all pass.
- No GitHub Releases for PCAP storage.

## 3. Chosen approach

Three design families were considered:

1. **Time rebalance only.** Removes the strongest V2 shortcut but leaves current-session nuisance correlations and weak graph contrast.
2. **More campaign/history features only.** Adds representation without fixing the data-generating confounders.
3. **Matched current-session controls + matched time + stronger prior-history/graph contrast + campaign-balanced splits.**

V3 uses approach 3.

## 4. V3 data-generating principle

### 4.1 Current-session matching

For a matched benign/suspicious pair, the following must be equal or statistically matched before wire execution:

- protocol;
- simulated start hour bucket and weekday bucket;
- current-session behavior profile;
- wire attempt count;
- transfer-size bucket;
- network impairment profile;
- client implementation family;
- server implementation family;
- current-session action family where semantically possible.

Labels must not be inputs to wire-control generation.

### 4.2 Intentional difference moves to prior context

The intended class signal is created in prior state and sequence context:

Benign examples:
- established source→destination relation;
- protocol already normal for the source/persona;
- approved jump-host path;
- regular scheduled maintenance sequence;
- prior successful administrative activity with similar targets;
- approved emergency/incident-response fan-out;
- service-account automation with stable destination set.

Suspicious examples:
- rare/new source→destination edge;
- first use of protocol for source;
- unusual destination expansion relative to prior history;
- failed→successful remote-admin sequence;
- low-and-slow lateral sequence across new targets;
- protocol switching after a new edge appears;
- short campaign-level fan-out across previously unseen targets.

The current remote-admin session should often be visually plausible in Wireshark for either class. The difference should emerge from the preceding graph/history and sequence.

## 5. Time shortcut elimination

V3 adds a dedicated matching layer before balanced selection:

- pair benign/suspicious candidates within the same protocol;
- require same hour-of-day bucket (one-hour exact bucket for primary matched cohort);
- require same weekday/weekend category;
- maintain global class distribution per hour within a small tolerance;
- require `time_only` label predictiveness to remain near chance in planner-only diagnostics.

Planner gate thresholds:

- absolute difference in benign/suspicious fraction per occupied hour bucket <= 0.10;
- at least 80% of matched pairs have identical hour bucket;
- no protocol may have a single hour bucket containing >20% of one label while the opposite label is absent.

## 6. Campaign design

V3 increases the number of independent campaign components rather than making a few campaigns longer.

Target for 1k corpus:

- >= 180 campaign groups;
- median campaign size 3–6 sessions;
- >= 60 benign campaign groups;
- >= 60 suspicious campaign groups;
- >= 25 hard-benign campaign groups;
- >= 30 multi-protocol campaign groups;
- no single campaign >2.5% of the corpus;
- counterfactual pair IDs and campaign IDs remain atomic split components.

Campaign families include:

Benign:
- scheduled maintenance;
- patch deployment;
- backup/recovery;
- incident response;
- helpdesk escalation;
- deployment/release;
- service-account automation;
- new-server onboarding;
- first-day administrator/bootstrap;
- approved emergency access;
- jump-host diagnostics.

Suspicious:
- low-and-slow lateral movement;
- rare-edge expansion;
- failed→successful access chain;
- protocol switching;
- fan-out to new targets;
- new-protocol-for-source sequence;
- multi-target lateral walk.

## 7. Split policy

V3 keeps connected-component grouping by campaign and counterfactual pair, but budgets challenge slices so train/validation/test remain statistically useful.

Target after mapping for session-level Gold:

- train: 55–65%;
- validation: 12–18%;
- test: 12–18%;
- challenge: 15–25%;
- validation >= 120 mapped sessions;
- test >= 120 mapped sessions;
- both classes present in every generic split and every protocol represented in validation/test.

Challenge families remain independent and can include:

- unseen client implementation;
- unseen persona;
- unseen source-destination relation;
- temporal future;
- Windows-native external holdout;
- LANL-derived reference remains external-only and is not given synthetic binary labels.

If a requested holdout cannot fit its impact budget, it is marked unavailable rather than stealing arbitrary fractions of the generic splits.

## 8. Bronze PCAP layout

V3 optimizes Bronze for human inspection.

Authoritative persisted layout:

```text
bronze/V3-1k/
├── sessions/
│   ├── benign/
│   │   └── <protocol>/<session_id>.pcap.zst
│   └── suspicious/
│       └── <protocol>/<session_id>.pcap.zst
├── campaigns/
│   ├── benign/<campaign_id>.pcap.zst
│   └── suspicious/<campaign_id>.pcap.zst
├── manifests/
│   ├── sessions.jsonl
│   ├── sessions.parquet
│   ├── campaigns.parquet
│   ├── pcap_index.parquet
│   └── pcap_index.csv
├── checksums.sha256
└── reproducibility.json
```

`pcap_index.csv/parquet` contains human-friendly columns: label, protocol, semantic family, session_id, campaign_id, start time, source/target role IDs, implementation ID, fidelity status, relative PCAP path, packet count, bytes, and SHA256. These identity/context columns are inspection metadata only and are never production model features.

A merged PCAP is allowed only as an ephemeral local file for Suricata/Zeek replay. It is not uploaded to HF and is not authoritative.

### 8.1 Capture strategy

A single long tcpdump capture is retained only temporarily while scenarios execute. After execution, V3 slices packets using execution timestamps into per-session PCAPs, then merges the relevant session PCAPs into per-campaign PCAPs. This avoids starting/stopping tcpdump one thousand times and keeps wire timing unchanged.

Quality gates:

- >= 99% successful sessions have a non-empty session PCAP;
- every campaign with >=1 successfully mapped session has a campaign PCAP;
- each PCAP has SHA256 and packet/byte counts;
- no persisted merged PCAP;
- random sample of at least 20 session PCAPs is reparsed by tshark in CI.

## 9. Gold representation

V3 keeps three levels:

1. `flow_gold` — Suricata EVE production-source baseline.
2. `session_gold` — primary supervised representation.
3. `campaign_gold` — sequence/context representation and campaign-level evaluation.

Primary V3 model features emphasize causal prior state:

- source connections in 1h/24h/7d/30d before current session;
- distinct prior destinations in 24h/7d/30d;
- pair seen count before current session;
- time since previous source→destination connection;
- new destination indicator;
- new protocol-for-source indicator;
- prior protocol diversity;
- prior failed/short attempt counts when observable;
- prior destination fan-out rate;
- recent source graph expansion rate;
- campaign transition count;
- protocol-switch count;
- count of new targets within recent sequence window.

Current-session bytes, duration, packets, rates and hour features remain available for auditing/ablation but must not dominate the primary model.

## 10. Shortcut gates

The V3 1k research gate fails if any of these hold:

- `time_only` validation PR-AUC > 0.55;
- current-session-only baseline is within 0.05 PR-AUC of the full session model;
- best nuisance baseline is within 0.05 PR-AUC of the full session model;
- full session validation PR-AUC < 0.60;
- full session test PR-AUC < 0.58;
- challenge recall at FPR <=1% is zero;
- hard-benign FPR >5%;
- leakage audit fails;
- mapped session coverage <98%;
- external data enters training or threshold selection.

A 4k run is allowed only if all mandatory V3 1k gates pass.

## 11. Windows-2025 fidelity

V3 performs a fresh same-release Windows job.

Required probes:
- Windows OpenSSH;
- native SMB;
- WinRM / PowerShell Remoting;
- DCOM/RPC endpoint mapper with explicit packet search for TCP/135;
- native RDP attempt with explicit evidence status.

For DCOM, the validator must search packet evidence for TCP/135 and any dynamically negotiated follow-on RPC connection. A completed local API call without wire evidence is insufficient.

For RDP, hosted-runner limitations are recorded honestly. V3 does not fabricate a native RDP validation if an interactive mstsc session cannot be established.

Windows data is external challenge/reference only and never enters supervised training.

## 12. Independent reference

The LANL-derived public reference lineage from V2 remains valid and is freshly acquired in the V3 release job.

It remains:
- external only;
- unlabeled for V3 binary intent;
- forbidden for training and threshold tuning;
- scored only after threshold/model selection on the synthetic Linux training world.

## 13. Research decision and scaling

`V3_RESEARCH_DECISION.json` has two independent outcomes:

- technical release status: `READY` / `BROKEN`;
- research status: `PASS` / `FAIL`.

Possible scale decisions:
- `ALLOW_4K` only if all 1k mandatory gates pass;
- otherwise `STOP_AT_1K` with explicit failed gates.

No 4k or 10k workflow runs automatically from mere artifact existence.

## 14. Persistence and destructive cleanup

Final order is strictly:

1. build V3 release tree;
2. create immutable checksum/release manifest;
3. upload V3 to private HF path `v3/candidate/<release-id>`;
4. verify required files and checksums from HF-side listing/download logic;
5. upload final GitHub Actions V3 artifact;
6. commit `V3_FINAL_STATUS.md` and persistence evidence;
7. only then run destructive cleanup.

Cleanup policy selected by the user: **B — V3 replaces V1/V2 storage**.

After V3 verification:

GitHub Actions:
- delete V1/V2 intermediate/smoke/planner/research artifacts;
- delete V1/V2 final artifacts;
- delete obsolete V1/V2 workflow runs where API permissions allow;
- retain V3 final workflow run/artifact and current V3 contract evidence.

Hugging Face:
- delete old V1/V2 `quarantine`, `releases`, intermediate and final paths;
- retain only V3 current candidate/promoted path plus any small provenance manifest needed to document deletion lineage.

The cleanup workflow is fail-closed and refuses to run unless V3 persistence evidence says both GitHub artifact verification and HF verification passed.

## 15. Verification sequence

Implementation must follow this order:

1. V3 unit/static contracts.
2. Planner-only 1k audit: time matching, class/protocol balance, campaign counts, pair validity, split viability.
3. 80-session real-wire smoke with per-session/per-campaign PCAP slicing.
4. Windows-2025 fidelity smoke.
5. Fresh LANL reference acquisition.
6. Full V3 1k real-wire release.
7. Suricata/Zeek parsing.
8. flow/session/campaign Gold.
9. leakage and split checks.
10. full vs shortcut models.
11. hard-benign and low-FPR evaluation.
12. external Windows/LANL scoring.
13. V3 research decision.
14. HF persistence and verification.
15. final GitHub artifact and status.
16. destructive V1/V2 cleanup.
17. final branch contract after cleanup metadata changes.

## 16. Non-goals

- No C2 frameworks in V3 training.
- No cloud T1021.007/.008 mixing into the PCAP corpus.
- No automatic 4k/10k before 1k signal gate passes.
- No production claim based solely on high validation PR-AUC.
- No label-conditioned packet volume/time/network conditions.
