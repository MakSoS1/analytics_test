# Stage M — positive-only cover-channel diversity corpus

Stage M extends the existing CoverLab V5 corpus without replacing or regenerating it.
Its purpose is to increase **implementation diversity** for the positive class before
real office traffic is introduced as the negative class.

## Safety and scope

Stage M is an isolated-lab traffic-shape generator. It does not execute commands,
provide persistence, steal credentials, connect to Internet C2, or forward arbitrary
traffic. All hostnames use local `.test` aliases, all services live on
`10.20.0.0/24`, and client namespaces have no default route.

The dataset contract is explicitly positive-only:

- `label_binary = 1` for every Stage M campaign;
- `positive_only = true`;
- `negative_class_present = false`;
- `external_dependency = false`;
- `post_exploitation = false`;
- `arbitrary_forwarding = false`.

Office traffic is intentionally not synthesized here.

## Full corpus budget

| Family | Campaigns |
|---|---:|
| M-HTTPS-BEACON | 600 |
| M-HTTPS-FRONT | 500 |
| M-HTTPS-LOWENT | 300 |
| M-HTTPS-FRAG | 300 |
| M-HTTP-443 | 250 |
| M-DNS-BEACON | 500 |
| M-DNS-BULK | 350 |
| M-DOH | 250 |
| M-DEAD-DROP | 300 |
| M-WSS-LONG | 400 |
| M-TUNNEL | 300 |
| M-FALLBACK | 250 |
| M-RMM-SHAPE | 200 |
| **Total** | **4,500** |

The existing HTTP header/URI/body, H3, gRPC, MQTT, MASQUE, OHTTP and ECH-oriented
V5 captures remain separate. Stage M deliberately does not spend new volume on
those already-covered forms.

## Diversity axes

Each family is generated across independent implementation profiles rather than
only different random seeds.

HTTP/HTTPS clients:

- Python httpx H1;
- Python httpx H2;
- Python stdlib/OpenSSL;
- curl/OpenSSL;
- Go `net/http`;
- Node fetch;
- Java HttpClient;
- Rust reqwest/rustls.

WSS clients:

- Python `websockets`;
- a dependency-free Node RFC6455 implementation;
- Chromium-native WebSocket.

Server/front stacks:

- direct Hypercorn;
- nginx TLS reverse proxy to Hypercorn;
- nginx reverse proxy to the dedicated WSS server;
- nginx plaintext HTTP on ports 80 and 443;
- local authoritative DNS;
- a separate local recursive DNS forwarder namespace.

Network profiles are the existing real `tc/netem` profiles:

- clean;
- wan_20ms;
- wan_80ms;
- lossy_wifi;
- constrained.

The full catalog contains more than 70 distinct implementation profiles.

## DNS topology

Stage M captures both:

```text
client -> authoritative DNS
```

and:

```text
client -> recursive resolver -> authoritative DNS
```

The resolver is placed in a separate `cc-dns` namespace. Therefore the
resolver-to-authoritative leg crosses the bridge and is visible on the same
`v-c2` capture point.

No external recursion is possible. The forwarder accepts only the local
authoritative address `10.20.0.20`.

## Timing

Requested beacon intervals are:

- 30 seconds;
- 60 seconds;
- 5 minutes;
- 15 minutes;
- 60 minutes.

Jitter profiles are 10% and 30%. Event counts vary across:

`3, 5, 10, 20, 50, 100+`-style profiles.

The hosted Stage M workflow intentionally uses accelerated sleeps so it can
exercise shape generation in CI. Such campaigns are marked:

```json
"timing_fidelity": "accelerated_shape_only",
"timing_training_eligible": false
```

The manual **Cover Channel Stage M Real Timing** workflow runs on a
`[self-hosted, linux, coverlab]` runner and records real 15-minute and
60-minute intervals with:

```json
"timing_fidelity": "wire_real",
"timing_training_eligible": true
```

This avoids silently treating accelerated timing as real evidence.

## Payload and session variation

Stage M varies:

- high-entropy payloads;
- low-entropy short codes and GUID-like values;
- 2–6 character fragments;
- rare beacon / interactive / trickle / bulk volume profiles;
- small-small, small-large, large-small, upload-heavy, download-heavy and
  symmetric directional shapes;
- HTTP keepalive/reconnect differences inherited from independent client stacks;
- direct vs nginx-front TLS termination;
- WSS direct vs nginx-front paths;
- direct DNS vs recursive DNS;
- HTTPS -> DNS fallback;
- dead-drop pointer -> separate HTTPS channel.

## Holdout metadata

Every campaign stores:

- `implementation_id`;
- `leave_one_implementation_group`;
- `leave_one_client_group`;
- `leave_one_server_group`;
- `leave_one_network_group`;
- deterministic `holdout_fold`.

This allows future evaluation to split by an entirely unseen implementation
instead of randomly splitting campaigns from the same generator.

Mythic, Adaptix and Sliver remain external implementation holdouts and are not
part of Stage M training data.

## Artifacts

Every shard is captured at wire level and packaged through the existing
CoverLab pipeline:

- raw PCAP compressed as `.pcap.zst`;
- campaigns/events manifests;
- decrypted local transaction trace for ground truth;
- Suricata EVE;
- Zeek logs;
- normalized silver layer;
- gold feature tables;
- dataset contract;
- capture-tail guard;
- Stage M positive-only contract;
- per-shard inventory.

Artifacts are uploaded to GitHub Actions for temporary retention and, when
`HF_TOKEN` is configured, to the private Hugging Face dataset under a
run-specific Stage M release.

## Workflows

### Smoke / full positive corpus

`.github/workflows/cover-channel-stage-m.yml`

- `smoke`: one shard, all Stage M families, reduced campaign count;
- `full`: defaults to 10 shards and produces exactly 4,500 positive campaigns;
- full verification fails if any negative row appears or if a family/campaign
  is missing.

### Real long timing

`.github/workflows/cover-channel-stage-m-real-timing.yml`

Manual self-hosted capture for 15-minute and 60-minute HTTPS beacon/front
campaigns. It is intentionally separate because GitHub-hosted accelerated
timing is not valid training evidence for real periodicity.

## Local/CI entry points

```bash
# Smoke
COVERLAB_STAGE_M_MODE=smoke \
  bash ./scripts/run_stage_m_ci.sh smoke 0 1 clean /tmp/stage-m M-positive-00

# Full shard 3 of 10
COVERLAB_STAGE_M_MODE=full \
  bash ./scripts/run_stage_m_ci.sh full 3 10 lossy_wifi /tmp/stage-m M-positive-03
```

Pure contract/catalog tests:

```bash
PYTHONPATH=src pytest -q tests/test_stage_m.py
```
