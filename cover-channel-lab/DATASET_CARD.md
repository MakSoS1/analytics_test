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
---

# Cover Channel Web Protocols Synthetic Network Dataset

This private research dataset contains safely generated network traffic for network-only detection of covert storage/timing channels, Web C2 mimicry, WebSocket/WSS tunnels, local LOTS analogues and matched benign hard negatives.

## Layers

**Bronze** is immutable source data: compressed PCAP, campaign/event manifests and laboratory decrypted ground truth. **Silver** contains raw Suricata/Zeek output plus normalized Parquet. **Gold** contains feature tables, campaign-level splits and quality metadata.

## Visibility contract

Content-visible and opaque branches are intentionally separated. Laboratory decrypted fields are ground truth only and must not be used by the opaque HTTPS/WSS model. The opaque branch is expected to use flow/TLS/transport/session features available to the target NGFW export schema.

## Labels

Key fields include `label_binary`, `label_family`, `label_intent`, `carrier`, `attack_mapping`, `visibility_mode`, `inspection_policy`, `inspection_outcome`, `sni_visibility`, `client_impl`, `persona`, `infra_category`, `generator_name`, `generator_version`, `generator_commit`, `campaign_id`, and `configuration_id`.

## Safety and provenance

All payloads are synthetic. No malware is executed. No credentials, user documents, host persistence, Internet-facing C2 endpoint or unrestricted forwarding proxy is used. Commodity service scenarios are local analogues under `.test` hostnames.

## Split methodology

Rows are never randomly split across the same campaign. Challenge stages are excluded from training. Generator/client/carrier/hostname/timing dimensions are retained in manifests so stricter grouped splits and leakage audits can be recomputed without regenerating PCAP.

## Known limitations

The GitHub-hosted implementation reproduces the network semantics of the planned multi-VM lab with Linux network namespaces rather than Windows/QEMU guests. Windows Schannel/.NET/PowerShell-specific fingerprints therefore require a later Windows-runner or physical-lab supplement. HTTP/3/QUIC, true ECH, OHTTP HPKE and MASQUE are challenge extensions rather than production acceptance criteria in this first GitHub-hosted corpus.

## Intended use

Defensive network security research, parser validation, feature engineering, model training, alert-budget testing and robustness evaluation.

## Prohibited use

The dataset and generator are not intended to deploy C2 infrastructure, proxy arbitrary third-party traffic, access real credentials/data, evade authorization controls or operate against systems without permission.
