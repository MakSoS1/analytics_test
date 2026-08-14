# Remote Admin Anomaly Lab V1

A reproducible isolated GitHub Actions lab for behavioral detection of anomalous remote administration. V1 deliberately excludes Sliver/Mythic/Havoc/Cobalt Strike/Metasploit-style C2 framework traffic: the objective is to learn remote-admin behavior rather than framework fingerprints.

## Current architecture

- GitHub-hosted Ubuntu 24.04 runner.
- 15 isolated Linux network namespaces on `br-adminlab`, no default route/NAT from endpoint namespaces.
- Core real-wire protocols: OpenSSH and Samba SMB.
- Extended train wire: xrdp/FreeRDP RDP and TigerVNC/RFB after the extended gate.
- Challenge-only: bounded HTTP/SOAP WS-Man fixture labelled `partial_winrm`.
- Fidelity-only: Samba/rpcclient DCE/RPC labelled `partial_dcom`; it is not represented as native Windows DCOM/TCP-135 training data.
- Full bridge capture before scenario execution.
- Suricata + pinned Zeek 8.2.1 offline parsing.
- Research/session Gold plus final production-compatible parser-flow Gold.
- M0 deterministic baseline, M1 LightGBM and M2 benign-only Isolation Forest.

## Source of truth and rollback

Bronze is immutable for an accepted shard. The complete PCAP is compressed losslessly with zstd and retained with manifests/checksums. PCAP is never intentionally published as a GitHub Release asset and is never deleted merely because Gold features have been built.

```text
release/
├── bronze/<shard>/
│   ├── captures/<shard>.pcap.zst
│   ├── manifests/sessions.jsonl
│   ├── manifests/sessions.parquet
│   ├── manifests/ground_truth.parquet
│   ├── manifests/hosts.parquet
│   ├── manifests/campaigns.parquet
│   ├── reproducibility.json
│   └── checksums.sha256
├── silver/<shard>/
│   ├── suricata/eve.json.zst
│   ├── suricata-rules/eve.json.zst
│   ├── zeek/*.log.zst
│   └── parser_versions.json
├── gold/<shard>/
│   ├── flow_features.parquet
│   ├── window_features.parquet
│   ├── graph_features.parquet
│   ├── model_matrix.parquet
│   ├── production_flow_features.parquet
│   ├── production_flow_labels.parquet
│   └── production_model_matrix.parquet
├── quality/<shard>/
│   ├── capture_health.json
│   ├── parser_health.json
│   ├── mapping_health.json
│   ├── production_flow_mapping.json
│   └── leakage_checks.json
└── models/
```

The preferred persistent dataset repository is the private Hugging Face dataset `Maksim123321/remote-admin-anomaly-v1`. Each workflow retains a 90-day GitHub Actions artifact **before** attempting HF upload. If `HF_TOKEN` is absent, the HF step reports an explicit non-destructive skip and the Actions artifact remains the recovery copy.

## Local equivalent of one shard

The commands below require Linux root/network-namespace capability and the same packages as the GitHub runner:

```bash
cd remote-admin-anomaly-lab
python -m pip install -r requirements.txt
bash scripts/install_extended_runner_v2.sh
sudo -E env \
  ADMINLAB_PYTHON="$(command -v python)" \
  ADMINLAB_OUTPUT_UID="$(id -u)" \
  ADMINLAB_OUTPUT_GID="$(id -g)" \
  bash scripts/capture_shard_extended.sh A A-local-00 100 20260814 /tmp/adminlab
ADMINLAB_PYTHON="$(command -v python)" bash scripts/build_silver.sh /tmp/adminlab/release A-local-00
bash scripts/build_rule_baseline.sh /tmp/adminlab/release A-local-00
PYTHONPATH=src python scripts/build_gold.py --release /tmp/adminlab/release --shard A-local-00 --feature-contract configs/feature_contract.yaml --split-seed 20260814
PYTHONPATH=src python scripts/build_flow_gold.py --release /tmp/adminlab/release --shard A-local-00 --feature-contract configs/feature_contract.yaml --split-seed 20260814
```

## Quality gates

An accepted shard must have a readable non-empty full PCAP, valid SHA256 checksums, successful protocol executions, non-empty Suricata EVE and Zeek conn logs, parser versions, at least 95% behavioral-session mapping coverage, no forbidden model columns and a passing grouped-split leakage audit.

The final production model is promoted only from parser-flow Gold after global cross-shard split reassignment. Stage H and `partial_winrm` are forced into challenge groups before promoted model training.

## Workflows

- `Remote Admin Anomaly V1 Contract Tests` — fast TDD/static contracts.
- `Remote Admin Anomaly V1 Extended Corpus Smoke` — bounded extended-wire integration.
- `Remote Admin Anomaly V1 Stage A V2` — 1,000-session research/throughput/model gate.
- `Remote Admin Anomaly V1 Phase 1 Corpus` — gated diverse fan-out with complete shard persistence.
- `Remote Admin Anomaly V1 Production Flow Promotion` — rebuilds final model features from parser-observed flows after a successful Phase 1.

See `PLAN.md`, `docs/PLAN_AMENDMENT_WIRE_SCALE.md`, `docs/FIDELITY_MATRIX.md` and `docs/NGFW_INTEGRATION.md` for the living experiment record and deployment contract.
