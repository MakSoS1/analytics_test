# Remote Admin Anomaly V3 — Causal NGFW Signal Redesign

## Goal

Repair V3 in place so benign and suspicious labels are consequences of different **production-observable network histories and sequences**, while keeping the current remote-admin session deliberately overlapping enough that the model cannot solve the task from trivial size/time/client fingerprints. The trained primary model must be reproducible from Suricata EVE plus prior rolling state on an NGFW.

## Production boundary

The required production input is Suricata EVE flow/application metadata plus state derived only from earlier EVE events. No feature may require scenario IDs, campaign IDs, labels, generator seeds, personas, usernames, AD/EDR data, or future events. Identity enrichment may be evaluated separately, but is not required by the primary model.

The primary runtime state keys are network-observable entities: source IP, destination IP, source-destination pair, protocol/application protocol, destination port, and bounded rolling windows. IP values are state keys only and are not emitted as raw model features.

## Root cause being corrected

Previous V3 chose a balanced list of labels and shuffled it before task/protocol/behavior generation. Malicious semantics were then assigned after the fact from the label. Because current-session controls were intentionally label-neutral and semantic metadata was correctly excluded from the model, many rows had nearly identical observable features with opposite labels. V3 also collapsed 58 personas onto a small set of source hosts, diluting per-source history, and session history was replayed globally across split boundaries.

## Causal scenario design

The generator is changed from `label -> semantic description` to `baseline -> scenario intent -> observable graph/sequence mutation -> label`.

Every generated corpus starts with a benign warm-up history. Suspicious sessions are then produced by one of the following causal families:

- `rare_pair`: source that has a stable destination set contacts a destination absent from its prior 7d/30d history.
- `sudden_fanout`: a normally low-degree source creates several new destination edges inside a short window.
- `new_protocol`: a source with a stable protocol baseline starts a remote-admin protocol not previously observed for that source.
- `protocol_switch`: a short sequence changes protocol across targets after a stable single-protocol history.
- `failed_then_success`: failed authentication-like connection attempts precede a successful remote-admin session to a new/rare pair.
- `target_chain`: one source walks across multiple new targets in sequence.
- `source_drift`: a workstation/source class with little or no prior administration starts remote-admin access.
- `low_slow_lateral`: new edges appear sparsely enough to avoid simple burst/rate thresholds while still violating long-term pair history.

Hard-benign families deliberately imitate the same coarse shapes without sharing the causal anomaly:

- scheduled maintenance fan-out from a source with a learned fan-out baseline;
- approved first-seen destination from a source that regularly adds new targets;
- helpdesk multi-protocol activity from a source with multi-protocol history;
- backup/bulk SMB transfer from a source-target pair with recurring history;
- off-hours incident response from a source that already has off-hours administration history.

The label is assigned only after the generator has successfully materialized the requested causal family and its invariants.

## Endpoint population

The logical lab remains a single isolated GitHub-hosted runner, but the topology is expanded from a handful of source identities to many lightweight network namespaces/addresses. At least 32 source endpoints are required for the 1k gate, spanning admin, helpdesk, developer, service, regular-user/remote-worker, jump-host and compromised-workstation-like roles. Destination services remain bounded to the isolated lab.

Personas are generator/evaluation metadata only. Multiple personas may not silently share one production baseline key during the benchmark unless that sharing is an explicit test case.

## Counterfactual contract

Matched benign/suspicious twins keep the same current-session nuisance controls where possible:

- protocol and destination port;
- application action class;
- client/server implementation;
- netem profile;
- duration bucket;
- transfer/attempt budget;
- time-of-day bucket.

But every pair must differ in at least one **production-observable prior-state feature** that is causally relevant to the assigned family. The planner fails closed if a matched pair has identical intended-history vectors.

## Features

Current-session features remain available but are explicitly treated as nuisance controls. History features are computed from strictly earlier events only.

Required session-history features include:

- prior sessions in 1m/5m/15m/1h/24h/7d/30d;
- distinct destinations in 1h/24h/7d/30d;
- pair seen count and pair recency;
- source protocol diversity and protocol novelty;
- new-edge counts and new-edge ratio in 1h/24h;
- source out-degree and graph expansion rate;
- recent protocol switches;
- recent failed/aborted connection count when observable from EVE flow state;
- destination popularity from prior corpus state;
- source remote-admin prevalence and destination remote-admin prevalence;
- source-to-protocol and pair-to-protocol familiarity.

`protocol`/`app_proto` may be included as a categorical context feature because the corpus is label-balanced by protocol and protocol-only performance is audited separately. Raw IP/host IDs remain forbidden model features.

## Split and state replay

Campaigns and counterfactual pairs remain connected components and never cross splits. Split assignment happens before state feature construction.

For the benchmark, train, validation, test and challenge each receive an independent causal replay of only the events belonging to that split, ordered by event time. No validation/test feature may depend on train events unless the evaluation mode explicitly models a deployed pre-trained baseline; that deployment mode, if added, is reported separately.

The primary reported benchmark is strict split-isolated replay.

## Model and shortcut audit

The same estimator family and hyperparameters are used for the full model and all feature ablations. The audit includes:

- label-only prevalence baseline;
- protocol-only;
- time-only;
- bytes/packets-only;
- duration/rate-only;
- current-session-only;
- history-only;
- full production feature set.

The 1k research gate requires the full model to beat every nuisance-only baseline by at least 0.05 validation PR-AUC and requires history-only to beat random/prevalence materially. Metrics are also reported on test and challenge at low-FPR operating points.

## NGFW parity

Offline training features must be produced by the same state machine used by the EVE scoring sidecar. A parity test replays the same EVE sequence through offline and online paths and requires identical feature vectors before the current event is inserted into state.

Suricata EVE is authoritative for the production model. Zeek remains a research/reference parser and may not silently contribute features to the primary model.

## Quality gates for regenerated V3-1k

The new V3-1k release is accepted only if all are true:

1. 1000/1000 executed sessions succeed.
2. 500 benign / 500 suspicious.
3. SSH/SMB/RDP/VNC remain balanced at 250 each with 125/125 labels per protocol.
4. At least 32 distinct production source endpoint identities are present.
5. At least 40% of rows belong to valid current-session-matched counterfactual pairs.
6. Every counterfactual pair differs in at least one required intended-history feature.
7. Session mapping coverage is >= 99.5% overall and >= 99.0% for every protocol.
8. No forbidden feature or cross-split state dependency is detected.
9. Protocol-only and time-only shortcuts do not materially solve the task.
10. Full validation PR-AUC >= 0.70 at the 1k research gate and exceeds the best nuisance-only baseline by >= 0.05.
11. Test and challenge PR-AUC are each >= 0.65.
12. Recall at FPR <= 1% is non-zero on test and challenge and is reported with exact counts.
13. Hard-benign FPR is reported and must be <= 1% at the selected validation threshold.
14. Learning-curve scaling remains fail-closed; 4k is not allowed unless the corrected 1k gate passes.

These thresholds are promotion gates, not targets to be optimized by leaking labels into generation or features.

## Persistence

V3 remains the same branch and release namespace. The old V3 release is retained as a negative/control snapshot until the corrected V3 release passes full verification. The corrected release is written to a new immutable `v3/final/run-<run-id>` prefix and only then may the previous V3 final prefix be archived or removed according to the existing cleanup policy.
