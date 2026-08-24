# LOTS Production v5 Design

## Goal

Build a defensible LOTS detector release that expands coverage from the existing six-service corpus to the current LOTS Project catalog while preserving the constraints learned from the previous research: exact traffic-to-label linkage, paired benign/malicious mechanisms, real Suricata parity, explicit unknown-service behavior, site calibration, safety-floor protection, and production-safe SOC output.

## Scope

The source catalog is the current LOTS Project table (175 domain/domain-pattern entries with tags C&C, Download, Exfiltration, Phishing). Coverage means catalog-driven scenario generation and evaluation, not blindly treating every catalog domain as malicious. Phishing-only entries are hard negatives / context-only because this network detector cannot observe webpage semantics behind TLS. C&C/Download/Exfiltration entries are eligible for LOTS-positive mechanisms.

## Safety model

No malware, credentials theft, real phishing, or third-party data exfiltration is performed. Public third-party services receive only benign read-only probes where safe and useful. Write-side C2, exfiltration, uploads, and credentialed actions are reproduced in a controlled TLS harness that preserves the network-observable mechanism (SNI/domain family, connection cadence, directionality, payload-size distribution, session reuse policy, redirects/CDN behavior where available) without sending sensitive data to public services.

## Data architecture

Every generated action receives campaign_id, scenario_run_id, action_id, wall-clock and monotonic timestamps, expected mechanism, intended outcome, actual outcome, client profile, and exact connection identity. Gold data accepts only exact/high-confidence action↔flow matches. Ambiguous/unmatched records remain audit artifacts and never enter training.

The generator creates paired examples. For each LOTS-positive mechanism, a benign twin matches service/provider family, HTTP verb class, timing family, client stack, payload-size range, connection reuse, and response-size regime. The distinguishing signal must be mechanism-level behavior across time or direction, not a trivial service identity or scenario-role field.

Scenario families:

- c2_poll: periodic command polling, slow/medium/fast, jittered, low-volume, burst-reset variants.
- dead_drop: read-only polling of stable content/metadata with state changes represented in the controlled harness.
- c2_bidirectional: read→write/result coupling, periodic and jittered.
- staging_download: single, staged, repeated, burst, and low-and-slow downloads.
- exfil_upload: single large, chunked, low-and-slow, burst, and read→write coupled uploads.
- mixed_legit_attack: benign use and LOTS behavior interleaved on the same host/service without mixed labels at the action level.
- evasion: volume reduction, cadence jitter, distributed services, session reuse, long idle, multi-service fanout.
- quic_observable: separate coverage/evaluation lane where Suricata telemetry is available; never silently coerced into TLS/SNI features.
- phishing_only: hard-negative/context lane; never labeled LOTS-positive from domain membership alone.

## Three-stage traffic validation before training

1. Contract validation: intended scenario parameters, unique action IDs, exact labels, expected service/tag/mechanism, no mixed windows, no stale/failed retries admitted.
2. Packet/EVE validation: real PCAP is parsed by Suricata; required TLS/flow events are present; SNI/service attribution and bytes/duration/direction agree with generator ground truth; checksum-offload is handled explicitly in offline replay; every accepted action has one exact/high-confidence flow match.
3. Mechanism validation: measured cadence, jitter, upload/download ratio, burst structure, read→write coupling, connection count, and session span are compared against the intended family and against reference LOTS descriptions. A scenario is rejected if its measured network shape does not match its declared mechanism.

No batch enters model training until all three gates pass.

## Feature/model architecture

Keep service identity out of the core detector. Use service-agnostic flow/window/session shape features that remain defined for one connection. Preserve the proven 12 base features plus the 15 shape features and add explicit evidence-quality/context features that are observable on NGFW: n_conns, observation_span, n_distinct_dst, session_age, read_write_coupling, upload/download dominance, burstiness, idle structure, destination churn, service-family metadata only as a coarse expert-routing feature, not a direct maliciousness feature.

The cascade is revised to avoid the observed fast-tier pathology where a single harmless GET received an extreme LOTS score. The fast tier has a minimum-evidence gate: no alert-grade score before either >=3 correlated connections or a deterministic high-confidence mechanism such as repeated read→write coupling. Single-connection fast predictions can only be telemetry/watch and are excluded from alert calibration.

The confirmation tier uses completed 20-minute windows and aggregated session evidence. Candidate models are LightGBM classifiers calibrated on campaign-disjoint training. Service-family experts may be used only when they improve provider-disjoint validation; the generalist remains mandatory for unknown services. Final alert logic combines fast evidence, completed-window evidence, safety floor, and incident lifecycle without allowing service identity alone to trigger.

No-SNI/ECH remains a separate watch lane unless independently validated to production alert quality. QUIC is a separate telemetry/model lane.

## Validation and release gates

Splits are fixed before training and are campaign-disjoint. Metrics are reported on:

- locked campaign-disjoint test;
- service-disjoint / LOSO;
- provider-disjoint holdout;
- mechanism-disjoint stress slices;
- evasion holdout;
- real background from the existing corpus plus any new valid background available;
- end-to-end PCAP→Suricata→streaming runtime parity.

Primary release target: incident precision >=0.95, incident/campaign recall >=0.95, macro-F1 >=0.95 on the locked in-scope test. A second transfer gate requires strong service/provider-disjoint performance; if unknown-service recall remains below target, unknown services stay watch-only and the model card states the measured number.

Production false-positive claims must be measured on real background with a denominator large enough for the requested alert budget. The runtime must not claim 5 alerts/1000 hosts/day when the calibration sample is too small. It uses host-hour-based calibration and the fixed safety floor. The current min-one-alert-per-tick budget defect must be removed and replaced with a real token-bucket/sliding budget that can emit zero ordinary alerts in a tick while never suppressing safety-floor alerts.

## Infected-site / online adaptation protections

Calibration uses the site's background only to set the ordinary threshold. The safety floor is computed from held-out known attacks and cannot be raised by local background. Online/imported background above the safety floor is quarantined and never auto-labeled benign. Drift monitoring may trigger recalibration but not silent model retraining on unreviewed live traffic.

## Runtime/output

Input remains native Suricata EVE JSON Lines. TLS and flow records are correlated by flow_id. The authoritative output remains append-only events.jsonl, with events.csv for triage and last_result.json/state.json for runtime state.

Channels:

- watch/suspected: early fast evidence, unknown/unvalidated service, no-SNI fallback, or insufficient confirmation.
- alerts/confirmed_window: production confirmation tier or safety-floor hit after the release gates.
- resolved/expired_unconfirmed: watch incidents that age out without confirmation.

The runtime must preserve incident_id across state transitions, deduplicate repeated evidence, and emit top local feature contributions for confirmed alerts.

## Production blockers that must be explicitly closed or disclosed

- strict daily alert-budget implementation;
- rotation-safe EVE tail handling;
- fast-tier minimum evidence and calibration;
- all accepted corpus batches passing three-stage traffic validation;
- unknown-service/provider-disjoint metrics;
- QUIC coverage status;
- no-SNI/ECH lane status;
- Suricata config validation with the actual shipped config;
- deterministic bundle, manifest verification, no training data/secrets/dev paths in SOC archive;
- site calibration runbook and insufficient-background behavior;
- long-run incident dedup/state persistence test.

## Deliverables

1. Catalog snapshot and normalized scenario plan covering all 175 LOTS entries by tag and safe generation mode.
2. GitHub Actions workflows for sharded safe traffic generation and Suricata EVE/PCAP validation.
3. Reproducible dataset manifests and QC reports.
4. Retrained model artifacts with locked-test/LOSO/provider/evasion/background reports.
5. Updated runtime with strict budget, fast evidence gate, rotation-safe ingestion tests, and unchanged native EVE contract.
6. Deterministic SOC tar.gz with README, MODEL_CARD, calibration/runbook, examples, manifests, and production/shadow status derived from measured gates rather than aspiration.
