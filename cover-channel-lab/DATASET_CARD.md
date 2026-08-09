---
pretty_name: Cover Channel Web Protocols Synthetic Network Dataset
language:
- en
- ru
task_categories:
- tabular-classification
tags:
- cybersecurity
- network-security
- suricata
- zeek
- covert-channel
- web-protocols
- synthetic
- quic
- http3
---

# Cover Channel Web Protocols Synthetic Network Dataset

This private research dataset contains safely generated network traffic for network-only detection of covert storage/timing channels, Web-C2 mimicry, WebSocket/WSS tunnels, HTTP/2 and HTTP/3 challenge traffic, MQTT-over-WSS, gRPC and matched benign hard negatives.

Trusted-site / LOTS-inspired traffic is **not a positive Cover Channel class**. It is retained only as a benign `hard_negative` background slice (`G_trusted_background`) so a detector does not learn the invalid shortcut “trusted service usage = covert channel”. Any suspicious sample in a mixed capture must use an actual Cover Channel carrier; trusted-site-inspired traffic may only contribute benign/background context.

## Layers and rollback

**Bronze** is the immutable rollback source: compressed PCAP, campaign/event manifests, reproducibility metadata and laboratory decrypted ground truth. **Silver** contains raw Suricata/Zeek outputs plus normalized Parquet. **Gold** contains field/transaction/session feature tables, campaign-level split assignments and quality/leakage metadata.

Bronze is retained even after Gold exists so the corpus can be reparsed after Suricata/Zeek upgrades or regenerated into a different feature schema without recreating the original traffic.

## Dataset correctness contract

Contract revision 2 validates campaign and event ground truth before a shard is accepted into Bronze. Campaign IDs must be unique, every event must reference a known campaign, and event/campaign labels must agree.

For trusted-site-inspired hard negatives the required contract is `label_binary=0`, `label_family=benign`, `label_intent=benign`, `attack_mapping=[]`, `experiment_stage=G_trusted_background`, `dataset_role=hard_negative`, `source_family=trusted_site_inspired`, `target_task=cover_channel_detection`. These semantics are forced **before wire generation**, not created by relabeling suspicious traffic afterwards.

`G_trusted_background` / `hard_negative` rows are challenge-only and are forbidden from train, validation and ordinary test partitions. Positive `D_mixed` points are also forbidden from using LOTS/trusted-service scenarios as their attack carrier.

## Visibility and model-input contract

Content-visible and opaque branches are intentionally separated. Laboratory decrypted fields are supervision only and must not enter the opaque HTTPS/WSS/H3 model. The opaque branch uses packet/flow/TLS/QUIC/parser/session metadata that can be mapped to the target NGFW export schema.

Laboratory-only fields such as `expected_events`, generator seed/provenance identifiers and plaintext hashes are forbidden from model matrices. `suricata_alerts` is also excluded from the default **ML-only** B1/B2/B3 baselines so rule-assisted performance is not silently reported as pure ML performance. A separate rule+ML evaluation may be added without changing this baseline contract.

Numeric missingness receives explicit `__missing` indicators before numerical imputation. This prevents “not observed” from being indistinguishable from a genuine numeric zero in the baseline matrix. The current implementation does **not yet** claim a complete production taxonomy distinguishing every cause such as packet loss, parser failure and exporter omission.

## Labels and provenance

Important fields include `label_binary`, `label_family`, `label_intent`, `carrier`, `attack_mapping`, `visibility_mode`, `inspection_policy`, `inspection_outcome`, `sni_visibility`, `client_impl`, `configured_client_impl`, `persona`, `infra_category`, `generator_name`, `generator_version`, `generator_commit`, `campaign_id`, `configuration_id`, `experiment_stage`, `dataset_role`, `source_family`, `target_task` and `implementation_fidelity`.

`implementation_fidelity` is intentionally explicit. Examples:

- `wire_real_http3_quic` — actual aioquic QUIC/HTTP/3 exchange;
- `wire_real_grpc_http2` — actual grpcio HTTP/2 RPC;
- `wire_real_mqtt_over_wss` — Paho MQTT through a local Mosquitto WSS listener;
- `wire_real_http_connect_bounded_echo` — actual HTTP/1.1 CONNECT handshake followed only by bounded local echo;
- `semantic_h2_extended_connect_fixture_not_rfc8441_wire_real` — semantic challenge, not real RFC 8441 frames;
- `ohttp_media_type_binary_fixture_not_full_rfc9458_hpke` — privacy hard negative, not a full OHTTP cryptographic implementation;
- TLS ECH/0-RTT/pinning-like scenarios likewise declare when they are visibility/ground-truth fixtures rather than wire-real protocol behavior.

This prevents downstream evaluation from treating a scenario label as proof that a protocol mechanism was actually present on the wire.

## Parsers and quality gates

Every accepted shard must contain a non-empty PCAP, successful Suricata offline output with `eve.json`, successful pinned Zeek 8.2.1 output with `conn.log`, campaign-to-packet coverage of at least 0.95, checksums, a passing leakage audit and a passing dataset correctness contract.

A physical **capture-tail guard** is applied in addition to aggregate mapping coverage. The last packet timestamp must reach the start of the latest successfully completed campaign within the configured tolerance. This prevents a large shard from passing a 0.95 aggregate mapping threshold while silently losing its final sessions during tcpdump teardown.

Transport fixtures are fail-fast prerequisites. Smoke validation covers HTTP/HTTPS/H2/WSS, HTTP/3 request traffic, H3 CONNECT-UDP DATAGRAM, WebTransport, gRPC, MQTT-over-WSS, all registered scenario IDs, four-persona sequence concurrency, parser/Gold construction and an exact `future-02` regression. The smoke also trains/scorers the compact B1/B2/B3 code path before a long corpus run is allowed to start.

## Resume / recovery semantics

Corpus recovery is shard-oriented. A historical shard is not reused merely because an earlier GitHub job was green. Before reuse, the recovery path checks its previous quality result, contract revision, retained SHA256 material, decompresses the raw PCAP and applies the current capture-tail guard.

If validation fails, only that shard is regenerated. Every shard that passes the current checks is mirrored to a stable `releases/resume/<shard>` slot on Hugging Face. Later recovery runs prefer the latest validated resume slot and fall back to the nominated historical release only when no corrected resume copy exists. This makes recovery monotonic: a successfully repaired shard is not regenerated because a different shard failed later.

Legacy trusted-background shards produced before contract revision 2 are intentionally not reused.

## Split methodology

Rows are never randomly split across the same campaign. Browser/future/trusted-background/adversarial challenge stages are excluded from train where appropriate for the evaluated expert. Selected clients, carriers and transforms are held out explicitly. Generator/client/carrier/timing dimensions remain in manifests so stricter grouped splits can be recomputed without regenerating PCAP.

Validation campaigns used for model calibration and threshold choice are split into disjoint calibration and threshold-selection subsets. Test/challenge partitions are not used for those two operations.

## Baselines

A complete release may include three model artifacts built from Gold:

- `B1-content`: content-visible transaction expert; field-level statistics from `field_features.parquet` are aggregated into the content feature space;
- `B2-session`: session/campaign expert with aggregate plus order-sensitive temporal features such as interarrival statistics, burst/silence ratios, sequence entropy/change rates and lag correlations;
- `B3-opaque`: packet/flow/TLS/QUIC/parser-availability metadata expert.

The default B1/B2/B3 artifacts are ML-only baselines. Model quality is reported separately from dataset completion.

## Stage D frozen evaluation and model acceptance

The 30 mixed captures are evaluation-only and are removed from baseline training input. Frozen B1/B2/B3 models are scored on Stage D after training. Reports include precision, recall, FPR, false positives per million objects and alerts per 10k objects.

A separate model-acceptance report checks held-out precision/recall targets and Stage-D session acceptance. Failure of a research baseline to meet that target does not invalidate a correctly collected PCAP corpus; dataset completeness and model acceptance are intentionally separate statuses.

## Randomized nuisance holdout

The post-baseline holdout contains exactly 500 newly generated suspicious sessions across supported carrier/client/timing/size combinations. It is a **deterministic randomized nuisance holdout**, generated without model feedback, then scored against the frozen B3 model. It is challenge-only and is not fed back into the same model training release.

It must not be described as a black-box gradient-free search. A true model-in-the-loop black-box optimizer that repeatedly scores, mutates and retains lower-scoring candidates is a separate future research stage.

## Safety and provenance

All payloads are synthetic. No malware is executed. No credentials, user documents, host persistence or Internet-facing C2 endpoint is used. Client namespaces have no default route. Trusted-service examples are local `.test` analogues and are benign hard negatives only. WSS tunnel messages never obtain arbitrary forwarding. The CONNECT fixture validates a fixed allowlist and then echoes locally rather than opening the requested onward connection.

## Known limitations

The GitHub-hosted implementation uses Linux network namespaces instead of the original Windows/QEMU mix. Windows Schannel/.NET/PowerShell-specific fingerprints therefore require a Windows-runner or physical/GNS3 supplement before claiming full Windows-client coverage.

The H3 challenge is wire-real QUIC/HTTP/3. The CONNECT-UDP-like case uses real H3 DATAGRAM and CONNECT semantics but is not represented as a complete RFC 9298 MASQUE implementation. OHTTP is a binary/media-type privacy fixture rather than RFC 9458 HPKE. ECH, forced TLS 0-RTT, true uTLS ClientHello parroting and certificate-pinning bypass are labelled fixtures unless a future release replaces them with wire-real implementations.

Real RFC 8441 H2 Extended CONNECT, wire-real standards-track ECH, long-timescale low-and-slow collection, broader Windows/Java/Rust transport stacks, systematic unseen-family/compositional holdouts and true model-in-loop adversarial search remain explicit future extensions rather than capabilities claimed by the current release.

## Intended use

Defensive network-security research, parser validation, feature engineering, model training, alert-budget testing, generalization testing and adversarial robustness evaluation for authorized environments.

## Prohibited use

The dataset and generator are not intended to deploy C2 infrastructure, proxy arbitrary third-party traffic, access real credentials/data, bypass authorization controls or operate against systems without permission.
