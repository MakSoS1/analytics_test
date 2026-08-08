# Architecture

## Runtime topology

```text
cc-office 10.20.0.10 ─┐
cc-dev    10.20.0.11 ─┤
cc-devops 10.20.0.30 ─┼─ ccbr0 / monitor 10.20.0.2 ─ cc-c2 10.20.0.20
cc-soc    10.20.0.31 ─┘
```

Every role is a Linux network namespace connected by veth to `ccbr0`. Client namespaces have no default route. `tcpdump` captures the bridge. The synthetic C2 namespace hosts two Hypercorn/FastAPI listeners: plaintext HTTP on `8080` and TLS with ALPN H2/H1 plus WSS on `8443`.

## Generator components

`orchestrate.py` chooses campaign/profile, seed, persona, client, transform/timing/payload-size dimensions and benign/suspicious counterfactual. `run_campaign.py` produces the actual exchange. `server.py` returns deterministic no-op synthetic responses and records decrypted ground truth. `pipeline.py` normalizes parser outputs, computes basic metadata/session features, builds strict campaign splits and runs quality checks.

## Why network namespaces instead of nested VMs

GitHub-hosted runners are ephemeral VMs but nested KVM/QEMU cannot be assumed. Namespaces preserve independent IP identities, routing isolation and packet capture without relying on nested virtualization. The dataset manifest explicitly records this capture source so later GNS3/Windows data can be kept as a separate generator/capture domain rather than silently mixed.

## Data lifecycle

1. Start local topology and TLS fixture.
2. Start bridge PCAP capture.
3. Generate campaigns with paired benign semantics.
4. Stop PCAP and write manifests/decrypted trace.
5. Run Suricata and Zeek offline.
6. Normalize parser output to Parquet.
7. Produce Gold session/metadata features and grouped splits.
8. Calculate checksums and quality/leakage reports.
9. Compress PCAP with Zstandard.
10. Upload the shard into a versioned Hugging Face Dataset repository.

## Production boundary

Gold is not assumed to equal the final NGFW input. `docs/PRODUCTION_FEATURE_CONTRACT.md` defines which fields can be promoted into a model only after the target NGFW exporter proves that it emits an equivalent field with known truncation/missingness behavior.
