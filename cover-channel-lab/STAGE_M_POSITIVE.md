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
| M-HTTPS-BEACON | 1,500 |
| M-HTTPS-FRONT | 600 |
| M-HTTPS-LOWENT | 400 |
| M-HTTPS-FRAG | 400 |
| M-HTTP-443 | 250 |
| M-DNS-BEACON | 750 |
| M-DNS-BULK | 750 |
| M-DOH | 800 |
| M-DOQ | 800 |
| M-H3-QUIC | 800 |
| M-DEAD-DROP | 300 |
| M-WSS-LONG | 800 |
| M-TUNNEL | 600 |
| M-FALLBACK | 600 |
| M-CLOUD-API | 1,500 |
| M-TIMING-XCARRIER | 2,000 |
| M-PUBSUB-MQTT | 500 |
| M-GRPC-BIDI | 400 |
| M-RMM-SHAPE | 400 |
| **Total** | **14,150** |

The existing HTTP header/URI/body and H3/QUIC/WebTransport V5 captures remain
separate and are not regenerated merely to inflate counts. Stage M now adds
wire-real local DoQ, MQTT-over-WSS and gRPC positive families. ECH/OHTTP/MASQUE
remain visibility/privacy challenges rather than automatic malicious labels.

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

The expanded catalog contains more than 100 declared implementation profiles
before VM/OS-specific implementation IDs are added.

## DNS topology

Stage M captures both:

```text
client -> authoritative DNS
```

and:

```text
client -> recursive resolver -> authoritative DNS
```

The resolver is placed in a separate `cc-dns` namespace. Stage M CI captures
on the `ccbr0` bridge rather than only `v-c2`, so both
`client -> resolver` and `resolver -> authoritative` legs are observable and
campaign-to-packet mapping remains valid.

No external recursion is possible. The forwarder accepts only the local
authoritative address `10.20.0.20`.

## Timing

Requested cadence buckets are:

- 5 seconds;
- 30 seconds;
- 120 seconds;
- 300 seconds;
- 1,200 seconds;
- 3,600 seconds.

Jitter buckets are 0%, 5%, 15%, 30% and 50%. Deterministic within-bucket
perturbations prevent seed-only duplicate configurations. Event counts vary across:

`3, 5, 10, 20, 50, 100+`-style profiles.

The hosted Stage M workflow intentionally uses accelerated sleeps so it can
exercise shape generation in CI. Such campaigns are marked:

```json
"timing_fidelity": "accelerated_shape_only",
"timing_training_eligible": false
```

The manual **Cover Channel Stage M Real Timing** workflow runs on a
`[self-hosted, linux, coverlab]` runner and records real 20-minute and
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

- CI/netns: raw PCAP compressed as `.pcap.zst`;
- VM-wire: archival master `.pcapng.zst` plus normalized `.pcap.zst`;
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
- `full`: defaults to 20 shards and produces exactly 14,150 positive campaigns;
- full verification fails if any negative row appears or if a family/campaign
  is missing.

### Main VM-wire corpus

`.github/workflows/cover-channel-stage-m-vm.yml`

This is the primary environment for training-eligible transport evidence. It
expects a pre-provisioned isolated lab with Linux/Windows client VMs, router,
server, resolver and sensor. The controller:

- bootstraps local services and client `.test` mappings;
- applies router `tc/netem` profiles;
- launches native Linux and Windows/SChannel clients;
- starts/stops `dumpcap` on the sensor VM;
- retrieves an archival pcapng master;
- creates a classic-PCAP parser derivative;
- runs Suricata and Zeek;
- builds Bronze/Silver/Gold;
- records SHA-256 for inventory, plan, pcapng and PCAP;
- uploads the shard and final manifest to Hugging Face.

Accelerated CI/netns campaigns are marked non-training for timing. VM-wire
campaigns are eligible only under the explicit contract in their manifest.

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

# Full CI shard 3 of 20
COVERLAB_STAGE_M_MODE=full \
  bash ./scripts/run_stage_m_ci.sh full 3 20 lossy_wifi /tmp/stage-m M-positive-03

# VM-wire shard
bash ./scripts/run_stage_m_vm.sh full 3 20 wan \
  /opt/coverlab/inventory.json /tmp/stage-m-vm M-vm-positive-03 ~/.ssh/id_ed25519
```

Pure contract/catalog tests:

```bash
PYTHONPATH=src pytest -q tests/test_stage_m.py
```
