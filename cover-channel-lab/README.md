# Cover Channel Web Protocol Traffic Lab

A reproducible, network-only laboratory for generating benign and suspicious synthetic traffic used to train and validate covert-channel / Web-C2 detection for an NGFW/NDR pipeline with Suricata and Zeek.

The lab intentionally does **not** run malware. It does not execute shell commands received over the network, read user files, collect credentials, persist on hosts, connect a synthetic C2 to the Internet, or provide an unrestricted SOCKS/proxy implementation. Tunnel scenarios only reproduce safe wire grammars and acknowledge allowlisted local targets.

## What is implemented

- isolated `10.20.0.0/24` topology using Linux network namespaces on a GitHub-hosted Ubuntu runner;
- roles matching Office, Dev, C2, DevOps, SOC and a monitor bridge;
- real HTTP/1.1, HTTPS, HTTP/2 negotiation, WebSocket/WSS, SSE, DoH-wire-format and browser-native local traffic;
- safe WSS tunnel/multiplexing message grammar with no arbitrary forwarding;
- request URI, standard/custom header, body, response, syntax, timing, WebSocket, H2, browser, SSE/long-poll, gRPC-wire-format, tunnel, TLS-visibility, LOTS-local-analogue, MQTT-over-WSS-like and DoH fixtures;
- paired benign hard negatives using the same carrier/service shape;
- multiple client implementations: httpx, curl, Node fetch, Go net/http, Python stdlib, H2-capable httpx, and genuine headless Chromium for browser challenge profiles;
- immutable Bronze, normalized Silver and feature-ready Gold layers;
- Suricata offline parsing and Zeek 8.2.1 offline parsing;
- campaign/event/decrypted-ground-truth manifests, checksums, campaign-level splits and leakage checks;
- sharded GitHub Actions orchestration with immediate Hugging Face upload when the write token is available.

## Storage layout

```text
release/
├── bronze/<shard>/
│   ├── captures/<shard>.pcap.zst
│   ├── manifests/campaigns.jsonl
│   ├── manifests/events.jsonl
│   ├── manifests/decrypted_transactions.jsonl
│   └── reproducibility.json
├── silver/<shard>/
│   ├── suricata-raw/
│   ├── zeek-raw/
│   └── normalized/*.parquet
├── gold/<shard>/
│   ├── session_features.parquet
│   ├── train_campaigns.txt
│   ├── validation_campaigns.txt
│   ├── test_campaigns.txt
│   └── challenge_campaigns.txt
└── quality/<shard>/
    ├── capture_health.json
    ├── checksums.json
    └── leakage_checks.json
```

Bronze is the rollback source of truth. Never delete it merely because Silver/Gold has been produced. Decrypted ground truth is laboratory-only supervision and must not be consumed by the opaque production model.

## CI stages

The workflow `.github/workflows/cover-channel-lab.yml` implements:

| Stage | Target |
|---|---:|
| A parser/observability | 600 sessions |
| B isolated core | 12,960 sessions |
| C sequence corpus | 720 campaigns × 60 transactions = 43,200 transactions |
| D mixed captures | 30 captures, 60/90/120 minutes, 3k–14.6k flows each, first 10 fully benign |
| F browser/tunnel/privacy challenge | at least 4,200 sessions |
| G commodity LOTS/MQTT/DoH | paired suspicious/benign profile corpus |

Stage E generalization is enforced through campaign-level split metadata and challenge-only stages; train files never include challenge stages.

## Running manually on Ubuntu

```bash
cd cover-channel-lab
python -m pip install -r requirements.txt
sudo apt-get update
sudo apt-get install -y software-properties-common tcpdump tshark zstd jq
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install -y suricata

docker pull zeek/zeek:8.2.1
./scripts/setup_netns.sh
./scripts/start_services.sh
./scripts/generate_stage.sh parser 0 1 /tmp/cc-stage /tmp/cc-stage/capture.pcap
./scripts/process_parsers.sh /tmp/cc-stage/capture.pcap /tmp/cc-stage /tmp/cc-parsers
./scripts/package_layers.sh /tmp/cc-stage /tmp/cc-stage/capture.pcap /tmp/cc-parsers /tmp/cc-release A-parser-00
./scripts/stop_services.sh
```

## Hugging Face persistence

The default remote is `Maksim123321/cover-channel-web-protocols` as a **private dataset repository**. A GitHub Actions repository secret named exactly `HF_TOKEN` must contain a Hugging Face user access token with write permission. No token is written to the repository or dataset manifests.

Each job uploads only its unique shard path. GitHub is the durable source for code/configuration/documentation; Hugging Face is the durable source for generated Bronze/Silver/Gold data.

## Safety boundary

The simulated clients have no default route. `.test` hostnames resolve only to `10.20.0.20`. The WSS tunnel endpoint only acknowledges `synthetic-api.test`, `echo.test`, or `cover-api.test` on fixed lab ports and never performs the requested onward connection. DoH requests are echoed locally and never forwarded to an upstream resolver.

See `docs/ARCHITECTURE.md`, `docs/RUNBOOK.md`, and `docs/PRODUCTION_FEATURE_CONTRACT.md` for details.
