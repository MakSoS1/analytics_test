# Cover Channel Web Protocol Traffic Lab

A reproducible, network-only laboratory for generating benign and suspicious synthetic traffic for covert-channel / Web-C2 detection in an NGFW/NDR ML pipeline with Suricata and Zeek.

The lab intentionally does **not** run malware. It does not execute received commands, read user files, collect credentials, persist on hosts, connect a synthetic C2 to the Internet, or provide unrestricted proxying. Every simulated client namespace has no default route and all attacker/service fixtures terminate inside the isolated `10.20.0.0/24` lab.

## What is implemented

- GitHub-hosted Ubuntu topology using Linux network namespaces for Office, Dev, C2, DevOps and SOC personas plus a monitor bridge;
- real HTTP/1.1 and HTTPS exchanges;
- real HTTP/2 traffic, plus real gRPC unary/server-stream/client-stream/bidi RPC via `grpcio`;
- real WebSocket/WSS traffic with a dedicated TLS listener and sustained lifecycle stress gate;
- real MQTT v5 over WSS using Paho + a local Mosquitto WebSocket listener;
- real QUIC/HTTP/3 using `aioquic`, including parallel/sparse H3 streams and a real H3→H2→H1 fallback campaign;
- H3 DATAGRAM + CONNECT-UDP-like challenge and real WebTransport stream challenge;
- bounded HTTP/1.1 CONNECT fixture that returns a local echo channel but **never** forwards to the requested target;
- H2 extended-CONNECT/RFC8441 cases kept as explicitly labelled semantic fixtures rather than falsely represented as wire-real;
- OHTTP media-type/binary privacy hard negative explicitly labelled as a fixture rather than full RFC 9458 HPKE;
- SSE, long polling, local DoH wire-format, genuine headless Chromium browser primitives and browser-originated WSS;
- request URI, standard/custom header, body, response, syntax, timing, WSS tunnel, TLS-visibility and control-plane/data-plane Cover Channel scenarios;
- trusted-service / LOTS-inspired examples retained **only as benign hard negatives/background**, never as a positive Cover Channel target;
- paired benign hard negatives and counterfactual-style pairs using the same service/carrier family;
- independent client stacks: httpx H1/H2, curl, Node fetch, Go net/http, Python stdlib, Chromium, aioquic, grpcio and Paho MQTT;
- Suricata offline parsing plus pinned Zeek 8.2.1 offline parsing with fatal parser quality gates;
- JA4/JA4S/JA4H/JA4T/JA4L extraction when exported by the parser, plus HTTP/TLS/DNS/QUIC/WebSocket/session aggregates;
- Bronze, Silver and Gold dataset layers with campaign/event ground truth, checksums, strict splits and leakage audit;
- B1-content, B2-session and B3-opaque LightGBM baselines with calibration, test/challenge metrics, feature importance and SHAP summaries;
- a post-baseline 500-session black-box gradient-free nuisance search kept exclusively as adversarial holdout.

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
│   │   ├── eve.json
│   │   └── ...
│   ├── zeek-raw/
│   │   ├── conn.log
│   │   ├── http.log / ssl.log / dns.log / quic.log / websocket.log when present
│   │   └── ...
│   └── normalized/*.parquet
├── gold/<shard>/
│   ├── session_features.parquet
│   ├── parser_session_features.parquet
│   ├── transaction_features.parquet
│   ├── field_features.parquet
│   ├── campaign_splits.parquet
│   ├── train_campaigns.txt
│   ├── validation_campaigns.txt
│   ├── test_campaigns.txt
│   └── challenge_campaigns.txt
└── quality/<shard>/
    ├── capture_health.json
    ├── checksums.json
    └── leakage_checks.json
```

**Bronze is the rollback source of truth.** The compressed PCAP is retained together with generator manifests and laboratory-only decrypted ground truth, so Silver and Gold can be regenerated after parser, feature or schema changes. Decrypted ground truth must never be fed to the opaque production expert.

## Dataset stages

| Stage | Target |
|---|---:|
| A — parser/observability + transport gate | sustained WSS/H3/MQTT/gRPC smoke, then 600 parser-validation sessions |
| B — isolated core | 12,960 Cover Channel + paired benign sessions |
| C — sequence corpus | 720 campaigns × 60 transactions = 43,200 transactions |
| D — mixed realistic captures | 30 captures, actual 60/90/120 minutes, 3k–15k flows, first 10 fully benign |
| F — browser/WSS/gRPC/TLS challenge | ≥4,200 sessions |
| G — trusted-service background | LOTS-inspired / commodity-service traffic as **benign hard negatives only**; never a positive target |
| H — future transport holdout | 1,400 H3/QUIC, CONNECT, H3 datagram, WebTransport and privacy sessions |
| I — adversarial holdout | 500 post-baseline suspicious sessions, never train data |

Stage E generalization is enforced by campaign-level grouping and explicit holdouts. `node_fetch`/`python_stdlib`, selected carriers/transforms, browser challenge, trusted-background, future transport and adversarial stages are excluded from train according to the split contract.

The internal workflow key for Stage G remains `lots` for backward compatibility with the original generation plan, but its dataset contract is explicitly benign: `label_binary=0`, `label_family=benign`, `label_intent=benign`, `attack_mapping=[]`, `experiment_stage=G_trusted_background`, `dataset_role=hard_negative`. In mixed captures, a positive draw can never use a LOTS-family scenario; an actual Cover Channel carrier is substituted instead.

## Model artifacts

The full workflow trains three separate experts rather than early-fusing incompatible visibility modes:

- `B1-content.joblib` — content-visible HTTP transaction features;
- `B2-session.joblib` — campaign/session aggregates;
- `B3-opaque.joblib` — packet/flow/TLS/parser metadata only.

Validation uses isotonic calibration when both classes are present. The stored threshold targets high validation recall, while reports separately retain precision, recall, F1, ROC-AUC/PR-AUC where defined, test/challenge confusion matrices, feature importance and SHAP summaries.

The adversarial job generates 500 new wire sessions **after** these baselines exist, scores them against `B3-opaque`, and stores attack-success rate plus the lowest-scoring candidates without feeding them back into the same training release.

## Parser and transport quality gates

Before the expensive fan-out begins, Stage A must pass a sustained transport smoke that reproduces the failure modes found in the previous full run: 1,600 short-lived WSS sessions across four personas, required MQTT-over-WSS and gRPC readiness, H3 request traffic, CONNECT-UDP DATAGRAM round-trip and WebTransport echo, followed by a fresh WSS handshake. The same gate also asserts that the historical LOTS-inspired slice is wire-benign and labelled as a hard negative.

A shard is rejected if any of the following holds:

- PCAP is missing or empty;
- expected campaign traffic cannot be mapped to packets with at least 0.95 campaign coverage;
- Suricata exits non-zero or does not produce non-empty `eve.json`;
- Zeek exits non-zero or does not produce non-empty `conn.log`;
- campaign IDs are duplicated;
- a holdout client leaks into train or seed/payload identity crosses splits;
- source checksums are missing.

This prevents a successful GitHub job from masking a capture-only dataset whose parser layer is actually empty, and prevents a partially broken transport fixture from launching hours of invalid generation.

## Hugging Face persistence

The configured dataset repository is `Maksim123321/cover-channel-web-protocols`, created as a **private Hugging Face dataset repository** when credentials allow it. GitHub Actions expects one repository secret named exactly `HF_TOKEN` containing a Hugging Face user access token with write permission.

Persistence policy:

1. source code, configs, schemas and documentation live permanently in GitHub;
2. every generated shard is uploaded immediately to its unique Hugging Face release path when `HF_TOKEN` exists;
3. every complete Bronze/Silver/Gold shard is also stored as a GitHub Actions artifact for 90 days;
4. `.github/workflows/cover-channel-hf-sync.yml` can later import an already completed GitHub run into Hugging Face, so missing credentials do not require regenerating 60–120 minute captures.

No secret is committed to source code or dataset manifests.

## Manual smoke run

```bash
cd cover-channel-lab
./scripts/install_runner.sh
./scripts/transport_smoke_ci.sh
./scripts/run_shard_ci.sh parser 0 1 /tmp/coverlab A-parser-00
```

## Safety boundary

All `.test` names resolve only inside the isolated `10.20.0.0/24` lab. HTTP/H2/H3/MQTT fixtures use `10.20.0.20`; the dedicated custom WSS aliases use `10.20.0.21`. Simulated client namespaces have no default route. WSS tunnel messages can reference only fixed synthetic targets and the server acknowledges them without arbitrary forwarding. The HTTP CONNECT fixture only echoes bytes locally after validating an allowlist and never opens an onward connection. DoH is never forwarded upstream. H3 DATAGRAM, WebTransport, gRPC and MQTT fixtures likewise terminate inside the lab.

See `docs/ARCHITECTURE.md`, `docs/RUNBOOK.md`, and `docs/PRODUCTION_FEATURE_CONTRACT.md` for operational details.
