# Cover Channel Audit V4

This revision hardens the dataset and model pipeline against the audit findings that can invalidate encrypted-traffic claims or create benign shortcuts.

## Visibility contract

- `B1-content`: visible/plaintext only.
- `B2-session`: visible/application-transaction only.
- `B2-visible-sequence`: visible/application-transaction TinyTCN only.
- `B3-opaque`: opaque network/tree expert.
- `B2-opaque-sequence`: packet/transport-only TinyTCN derived exclusively from retained raw PCAP.
- `fusion-router`: masks every plaintext-derived expert when TLS/application plaintext is unavailable or inspection is bypassed.

The opaque sequence table contains only direction, packet size, inter-arrival time, transport, TCP flags/retransmission proxy, and flow boundaries. It never reads server-side decrypted traces, HTTP headers/bodies, paths, methods, status codes, SNI, or transaction type.

## Benign temporal hard negatives

Stage K targets 60,000 benign sessions with matched multi-event temporal patterns and an event-count distribution spanning single-event through 60+ event sessions. Wire scenarios are selected from an explicit allowlist so the stated benign pattern is compatible with the generated protocol family and the requested event count corresponds to actual logical events.

## Timing

Hosted Actions collects multi-event real-time 5s, 30s, 120s, and 300s timing challenge profiles with fixed/jitter/burst/backoff/phase-transition modes. 1200s and 3600s profiles are not faked or accelerated in hosted CI; strict promotion requires separately imported wire-real self-hosted isolated-lab evidence for them.

## Acceptance

Model promotion is separate from dataset/model artifact creation. Strict gates cover expert, fusion, frozen Stage D, leave-one-family-out, compositional, external-framework, ECH, environment-diversity, and long-timing evidence. Missing external evidence keeps `model_candidate=false` without deleting or invalidating an otherwise valid dataset/model bundle.

## Resume/backfill

Existing validated B/C/F/G/H/D raw PCAP can be reused. Packet-only temporal features are deterministically backfilled from the retained compressed PCAP, preserving raw capture as source of truth without regenerating otherwise valid wire traffic.
