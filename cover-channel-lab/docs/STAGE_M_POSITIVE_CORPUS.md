# Stage M — positive-only cover-channel corpus

Stage M extends the retained V5 CoverLab corpus with implementation diversity for the network forms that matter most to an office NDR. It intentionally contains **no legitimate/benign class**. Office negatives are a later, separate composition step.

## Scope

The catalog contains 4,950 positive campaigns across 13 families: HTTPS beacon, shared-front HTTPS, low-entropy HTTPS, short-fragment HTTPS, plaintext HTTP on 80/443, DNS beacon, DNS bulk, DoH, two-phase dead-drop, long WSS, bounded bidirectional tunnel shape, HTTPS/DNS fallback, and RMM-like poll/burst shape.

For the important families, campaigns vary entire client implementations rather than only seeds. The catalog uses Python/httpx, curl, Go net/http, Node fetch, Python stdlib, Chromium/BoringSSL, several DNS clients, several WebSocket clients, and four bounded raw-TCP shape clients. Each family reserves one complete implementation as `implementation_holdout`; that implementation never appears in the family’s `train_candidate` subset.

Every campaign also varies one of five real kernel network profiles (`clean`, `wan_20ms`, `wan_80ms`, `lossy_wifi`, `constrained`), event counts (3/5/10/20/50/100), payload style, direction/asymmetry, connection policy, and timing/jitter. DNS is generated both directly to a local authoritative server and through a local recursive resolver. All DNS names are under `.stage-m.test`.

## Safety boundary

All endpoints live on the isolated `10.20.0.0/24` lab segment, which has no default Internet route. The Stage M DNS server refuses names outside `.stage-m.test`; the recursive fixture can forward only to the local authoritative fixture. The tunnel fixture has no destination field and performs no proxying or command execution: it only produces bounded bidirectional byte-shapes against a local echo-like service.

## Timing fidelity

The scalable 4,950-campaign corpus is captured with compressed wall-clock waits and then **retimed at the PCAP timestamp layer** from each campaign’s nominal schedule. Both captures are retained:

- `*.raw-runtime.pcap.zst`: what actually traversed the isolated lab during generation;
- `*.pcap.zst`: timestamp-retimed capture used by Suricata/Zeek and feature extraction.

The manifest records `nominal_interval_seconds`, jitter, event count and `timestamp_retime_required=true`. This must not be described as a real 15/60-minute wall-clock holdout. Existing Stage L/self-hosted real-time evidence remains the place for strict long-duration timing validation.

## Splits

`primary_split` has only two Stage M values:

- `train_candidate`: positive samples eligible for a future model once real office negatives are available;
- `implementation_holdout`: positive samples from an entirely unseen implementation, always `training_eligible=false`.

`stage_m_export` additionally publishes rotating leave-one-out definitions for implementation, network profile, payload style and nominal interval. These are positive-only generalization tests; precision/FPR/accuracy are not meaningful until an actual negative population is added.

## Artifacts

Every shard retains campaign/event manifests, decrypted local fixture traces, raw runtime PCAP, retimed PCAP, Suricata EVE, Zeek logs, normalized/silver layers, gold feature tables, dataset contract validation, retiming report and Stage M catalog/split metadata. Full workflow shards are uploaded to GitHub Actions artifacts and the private Hugging Face dataset configured by the workflow.
