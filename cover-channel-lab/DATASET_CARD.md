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

This private research dataset contains safely generated network traffic for network-only detection of covert storage/timing channels, Web-C2 mimicry, WebSocket/WSS tunnels, HTTP/2 and HTTP/3 challenge traffic, local LOTS analogues, MQTT-over-WSS, gRPC and matched benign hard negatives.

## Layers and rollback

**Bronze** is the immutable rollback source: compressed PCAP, campaign/event manifests, reproducibility metadata and laboratory decrypted ground truth. **Silver** contains raw Suricata/Zeek outputs plus normalized Parquet. **Gold** contains field/transaction/session feature tables, campaign-level split assignments and quality/leakage metadata.

Bronze is retained even after Gold exists so the corpus can be reparsed after Suricata/Zeek upgrades or regenerated into a different feature schema without recreating the original traffic.

## Visibility contract

Content-visible and opaque branches are intentionally separated. Laboratory decrypted fields are supervision only and must not enter the opaque HTTPS/WSS/H3 model. The opaque branch uses packet/flow/TLS/QUIC/parser/session metadata that can be mapped to the target NGFW export schema. Missingness reason is conceptually distinct from a valid zero value.

## Labels and provenance

Important fields include `label_binary`, `label_family`, `label_intent`, `carrier`, `attack_mapping`, `visibility_mode`, `inspection_policy`, `inspection_outcome`, `sni_visibility`, `client_impl`, `configured_client_impl`, `persona`, `infra_category`, `generator_name`, `generator_version`, `generator_commit`, `campaign_id`, `configuration_id`, `experiment_stage` and `implementation_fidelity`.

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

Every accepted shard must contain a non-empty PCAP, successful Suricata offline output with `eve.json`, successful pinned Zeek 8.2.1 output with `conn.log`, campaign-to-packet coverage of at least 0.95, checksums and a passing leakage audit. JA4/JA4S/JA4H/JA4T/JA4L are retained when the parser exports them.

## Split methodology

Rows are never randomly split across the same campaign. Browser/future/commodity/adversarial challenge stages are excluded from train. Selected clients, carriers and transforms are held out explicitly. Generator/client/carrier/timing dimensions remain in manifests so stricter grouped splits can be recomputed without regenerating PCAP.

## Baselines and adversarial holdout

A complete release may include three model artifacts built from Gold:

- `B1-content`: content-visible transaction expert;
- `B2-session`: session/campaign aggregate expert;
- `B3-opaque`: packet/flow/TLS/parser metadata expert.

The post-baseline adversarial corpus contains 500 newly generated suspicious sessions sampled by a black-box gradient-free nuisance search over supported carrier/client/timing/size combinations. It is challenge-only and is scored against the frozen B3 release; it is not fed back into the same model training release.

## Safety and provenance

All payloads are synthetic. No malware is executed. No credentials, user documents, host persistence or Internet-facing C2 endpoint is used. Client namespaces have no default route. Commodity-service scenarios are local `.test` analogues. WSS tunnel messages never obtain arbitrary forwarding. The CONNECT fixture validates a fixed allowlist and then echoes locally rather than opening the requested onward connection.

## Known limitations

The GitHub-hosted implementation uses Linux network namespaces instead of the original Windows/QEMU mix. Windows Schannel/.NET/PowerShell-specific fingerprints therefore require a Windows-runner or physical/GNS3 supplement before claiming full Windows-client coverage.

The H3 challenge is wire-real QUIC/HTTP/3. The CONNECT-UDP-like case uses real H3 DATAGRAM and CONNECT semantics but is not represented as a complete RFC 9298 MASQUE implementation. OHTTP is a binary/media-type privacy fixture rather than RFC 9458 HPKE. ECH, forced TLS 0-RTT, true uTLS ClientHello parroting and certificate-pinning bypass are labelled fixtures unless a future release replaces them with wire-real implementations.

## Intended use

Defensive network-security research, parser validation, feature engineering, model training, alert-budget testing, generalization testing and adversarial robustness evaluation for authorized environments.

## Prohibited use

The dataset and generator are not intended to deploy C2 infrastructure, proxy arbitrary third-party traffic, access real credentials/data, bypass authorization controls or operate against systems without permission.
