# Remote Admin Anomaly V1 — Implementation Status V2

Date: 2026-08-14

This file deliberately distinguishes **validated evidence** from code that has been implemented but is still awaiting the final integrated workflow gate. Do not promote a pending item merely because its source file exists.

## Validated evidence

### Core configuration / planner / topology

- Configuration contract: PASS — Actions run `31787756618`.
- Canonical planner/manifest contract: PASS — run `31787949680`.
- Isolated namespace topology: PASS — run `31788233293`.
- 15 endpoint namespaces were present; in-lab connectivity worked; endpoint default routes were absent; direct `1.1.1.1` connectivity failed as required.

### Real SSH / SMB wire

- Final core real-wire smoke: PASS — run `31788947200`.
- 40/40 behavioral sessions completed.
- SSH: 25; SMB: 15.
- Benign: 32; suspicious: 8.
- No synthetic replacement was used for these protocol sessions.

### Immutable Bronze

- Final Bronze gate: PASS — run `31789649604`.
- 40 sessions.
- Raw PCAP: 2,710,821 bytes.
- Retained lossless zstd PCAP: 1,851,067 bytes.
- Eight checksum entries verified.
- Actions artifact: `remote-admin-bronze-smoke-31789649604`, artifact ID `9214949423`, 90-day retention.

### Suricata / Zeek Silver

- Final Silver gate: PASS — run `31790538926`.
- Suricata: `7.0.3 RELEASE`; Zeek: pinned `8.2.1`.
- 40 behavioral sessions generated 102 parser-observed TCP connections.
- Suricata: 304 EVE lines; 102 flow events; 66 SSH-related; 179 SMB-related.
- Zeek: 102 conn lines; 45 SSH log lines; 60 SMB log lines.
- This is the evidence that one behavioral session cannot be treated as one TCP flow.
- Combined Bronze/Silver artifact: `remote-admin-dataset-smoke-31790538926`, artifact ID `9215318136`, 90-day retention.

### DCE/RPC fidelity probe

- Fidelity run `31791464876` established a real `rpcclient` -> Samba DCE/RPC transaction.
- Classification is **`real_dcerpc_samba` / `partial_dcom`**.
- It is not promoted as native Windows DCOM and is excluded from V1 train data.
- The same probe initially misreported RDP/VNC/WinRM listener availability because it inspected the peer column of `ss`; listener detection was corrected afterward. Therefore those three statuses from this run are not final evidence.

## Implemented; final integrated evidence still required

### Extended wire

Implemented:

- xrdp + FreeRDP transport/negotiation adapter;
- TigerVNC/RFB adapter;
- bounded WS-Man SOAP fixture (`partial_winrm`, Stage-H challenge only);
- balanced extended scenario selection;
- no DCE/RPC in training protocols;
- parser-gated RDP wire proof rather than client-exit-code proof;
- extended full-PCAP capture and Bronze packaging.

Required before promotion:

- integrated run contains nonzero SSH, SMB, RDP and VNC behavioral sessions;
- every scenario succeeds;
- retained PCAP is readable;
- session mapping coverage >= 0.95;
- production flow mapping coverage >= 0.90;
- UID label alignment = 1.0.

### Gold and leakage controls

Implemented:

- research/session Gold;
- explicit session -> many parser flows mapping;
- prior-only 1m/5m/15m/1h window features;
- novelty and graph state;
- feature allowlist / forbidden-generator metadata contract;
- grouped campaign/counterfactual split;
- unseen source-host / host-pair / temporal holdouts;
- global post-shard split reassignment;
- shard-scoped session/campaign/pair/flow identifiers before global merge;
- Stage H / `partial_winrm` forced to challenge by whole group.

### Production-flow Gold

The production model unit is now a **parser-observed flow**, not an orchestrator session.

Implemented:

- `build_flow_gold_v2.py` derives rows from Zeek `conn.log`;
- labels are joined explicitly by `flow_uid + session_id`, never by row order;
- orchestrator metadata is used only for ground-truth labels and grouped split membership;
- raw IPs are only state keys and are forbidden model inputs;
- `merge_production_flow_gold_v2.py` namespaces shard-local IDs before global grouping;
- final model matrix contains only production allowlist + `label_binary` + `split`.

### Models

Implemented:

- M0 deterministic behavioral baseline;
- separate Suricata M0 rule baseline in `rules/remote-admin.rules`;
- M1 LightGBM;
- M2 benign-only Isolation Forest;
- deterministic threshold selection using validation FPR <= 0.05;
- test/challenge metrics where defined;
- evidence-driven learning curve.

Sequence TCN remains intentionally deferred until the promoted flow/window/graph model leaves a measurable campaign-level gap.

### NGFW integration

Implemented:

- prior-only online `EveFeatureState` for Suricata `event_type=flow`;
- EVE streaming M1 sidecar scorer;
- exact production feature allowlist;
- M2 shadow-only policy;
- M0 Suricata rules as independent real-time evidence;
- V1 alert/enrichment only; automatic blocking explicitly deferred.

See `docs/NGFW_INTEGRATION.md`.

### Persistence

Implemented:

- private HF target: `Maksim123321/remote-admin-anomaly-v1`;
- shard uploader keeps `bronze`, `silver`, `gold`, `quality` together;
- upload runs only after the 90-day Actions artifact has been created;
- missing `HF_TOKEN` is a non-destructive explicit skip;
- no PCAP is uploaded as a GitHub Release asset;
- full `.pcap.zst` remains the rollback source.

## Current final-gate policy

The self-contained integrated release workflow is `Remote Admin Anomaly V1 Master V2`. Its successor/fallback code fixes two additional risks before any further scale:

1. RDP success is proven by retained PCAP/parser mapping rather than FreeRDP exit status.
2. Global merge scopes shard-local session/campaign/pair/flow identifiers to prevent accidental cross-VM ID collisions.

No 201k blind fan-out is accepted as a quality objective. First release quality is decided by real-wire throughput, parser coverage, leakage audit and learning curve. The ~201k figure is only an upper scale envelope.
