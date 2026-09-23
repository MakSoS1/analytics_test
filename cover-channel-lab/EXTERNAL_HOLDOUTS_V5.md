# CoverLab V5 external holdouts

This document describes the external evidence required to promote a synthetic
CoverLab model from a **core candidate** to a **research candidate**.

The external corpus is challenge-only. It must never be merged into the
canonical synthetic training split.

## Safety and topology

Use a dedicated lab VLAN / VM network with RFC1918 addresses. During agent
execution, route only between the test client and the local framework/listener.
Do not use production credentials, production endpoints, public redirectors,
real user data, credential collection, shell execution, injection, pivoting,
port forwarding, BOFs, file theft, screenshots, keylogging, or other
post-exploitation actions.

The allowed framework lifecycle is:

- registration
- idle
- poll
- synthetic task
- synthetic result
- sleep
- reconnect

The capture registration code rejects public source addresses and marks every
framework record as challenge-only / training-ineligible.

## Framework bootstrap

On the isolated self-hosted runner:

```bash
export COVERLAB_ISOLATED_LAB=1
cd cover-channel-lab

# One tool:
bash scripts/bootstrap_framework_tools_v5.sh mythic /opt/coverlab/tools
bash scripts/bootstrap_framework_tools_v5.sh adaptix /opt/coverlab/tools
bash scripts/bootstrap_framework_tools_v5.sh sliver /opt/coverlab/tools

# Or all three:
bash scripts/bootstrap_framework_tools_v5.sh all /opt/coverlab/tools
```

The bootstrap uses only the official upstream projects:

- Mythic: `https://github.com/its-a-feature/Mythic`
- Mythic HTTPX: `https://github.com/MythicC2Profiles/httpx`
- Mythic WebSocket: `https://github.com/MythicC2Profiles/websocket`
- Mythic Apollo: `https://github.com/MythicAgents/Apollo`
- Mythic Athena: `https://github.com/MythicAgents/Athena`
- AdaptixC2: `https://github.com/Adaptix-Framework/AdaptixC2`
- Sliver: `https://github.com/BishopFox/sliver`

Mythic is bootstrapped with HTTPX/WebSocket profiles plus Apollo/Athena.
Adaptix is built with the official server/extenders Docker targets. Sliver is
installed using the official installer. Payload/agent generation is
intentionally not automated by CoverLab: use a pre-approved lab-only agent and
restrict it to the lifecycle above.

The bootstrap writes exact tool provenance to
`/opt/coverlab/tools/coverlab-tool-versions.env`. Source that file before
capture and select the matching version variable.

The four accepted framework labels are:

- `sliver`
- `adaptix`
- `mythic_httpx`
- `mythic_websocket`

## Capturing a framework session

Create a driver script that starts an already-approved lab agent, keeps it
alive for the desired check-in/poll/sleep interval, optionally performs a
harmless synthetic/no-op task and result, and then exits.

Capture and register it in one command:

```bash
export PYTHONPATH="$PWD/src"
export COVERLAB_FRAMEWORK_LIFECYCLE="registration,idle,poll,synthetic_task,synthetic_result,sleep,reconnect"

export COVERLAB_ISOLATED_LAB=1
source /opt/coverlab/tools/coverlab-tool-versions.env
export COVERLAB_FRAMEWORK_TOOL_VERSION="$COVERLAB_MYTHIC_TOOL_VERSION"

bash scripts/capture_isolated_framework_v5.sh \
  mythic_httpx \
  cc-mythic \
  v-mythic \
  10.77.0.21 \
  https \
  fw-mythic-httpx-0001 \
  /opt/coverlab/evidence \
  -- /opt/coverlab/drivers/run_mythic_httpx_lab_agent.sh
```

Repeat with independent captures for all four framework labels. The wrapper
records capture timestamps, hashes the PCAP, copies it into the evidence
directory and appends a strict `framework_holdout.jsonl` record.

To validate the raw framework evidence:

```bash
PYTHONPATH=src python -m coverlab.external_evidence_status_v3 \
  --framework-root /opt/coverlab/evidence/framework \
  --ech-root /opt/coverlab/evidence/ech \
  --environment-root /opt/coverlab/evidence/environment \
  --long-timing-root /opt/coverlab/evidence/long-timing \
  --office-root /opt/coverlab/evidence/office \
  --out-dir /tmp/coverlab-evidence-status
```

## Wire-real ECH pairs

ECH evidence is pair-based: the same benign/suspicious behavior should be
captured with ECH disabled and enabled. ECH itself is never an attack label.

Required modes:

- `grease`
- `accepted_h2`
- `accepted_h3`
- `rejected`
- `shared_frontend_benign`
- `shared_frontend_suspicious`

The target must be a lab endpoint and the client source address must be
private/loopback.

Example wrapper:

```bash
export COVERLAB_ISOLATED_LAB=1

bash scripts/capture_isolated_ech_v5.sh \
  cc-ech \
  v-ech \
  10.77.0.31 \
  h3 \
  ech-pair-001-on \
  ech-pair-001 \
  accepted_h3 \
  true \
  /opt/coverlab/evidence \
  -- bash "$PWD/scripts/run_local_ech_curl_v5.sh" https://ech-lab.test/ true h3
```

Create the corresponding paired capture with ECH disabled and the same
`pair-id`. The V5 scorer writes `model_score` and `decision_threshold`
back into the copied run manifest. Acceptance checks recall/FPR plus the mean
absolute score delta between paired ECH-on/off observations.

## Environment diversity

Register real captures produced by different client/server/network domains:

```bash
PYTHONPATH=src python -m coverlab.evidence_register_v4 \
  --root /opt/coverlab/evidence environment \
  --pcap /captures/winhttp-nginx-nat-01.pcap \
  --capture-id winhttp-nginx-nat-01 \
  --session-count 500 \
  --client-stack windows_winhttp_schannel \
  --server-stack nginx \
  --network-evidence nat
```

In addition to registered PCAP provenance, strict research promotion requires
`/opt/coverlab/evidence/environment/session_features.parquet` from the same
sensor/preprocessing pipeline used by B3. It must contain `capture_id` and
`label_binary` for each session. Each required client/server/network domain
must contain both benign and suspicious rows; V5 computes per-domain
precision/recall/FPR and rejects missing or single-class cells.

The existing validator requires coverage for:

Clients:
`windows_winhttp_schannel`, `dotnet_httpclient_schannel`,
`edge_schannel`, `firefox`, `java_httpclient`, `rust_reqwest`,
`chromium`.

Servers:
`nginx`, `envoy`, `caddy`, `apache`, `haproxy`, `iis`.

Network evidence:
`nat`, `forward_proxy`, `tls_inspection`, `tls_bypass`,
`partial_capture`, `capture_loss`, `connection_migration`.

## Real 20/60 minute timing evidence

Hosted Actions already covers 5/30/120/300 second timing profiles. The
1200/3600 second evidence is intentionally collected on a self-hosted lab
without timestamp acceleration.

Each interval needs at least one benign and one suspicious capture.

```bash
PYTHONPATH=src python -m coverlab.evidence_register_v4 \
  --root /opt/coverlab/evidence long-timing \
  --pcap /captures/timing-1200-benign.pcap \
  --campaign-id timing-1200-benign-01 \
  --interval-seconds 1200 \
  --event-count 5 \
  --label-binary 0 \
  --protocol https \
  --source-ip 10.77.0.41 \
  --started-at 2026-09-22T10:00:00Z \
  --ended-at 2026-09-22T11:40:00Z
```

For 3600 seconds the validator requires at least four events per campaign.

## Real office benign FPR

Do not force an office mirror into the synthetic campaign format. Export the
same B3-compatible session feature table from the office preprocessing
pipeline as:

```
/opt/coverlab/evidence/office/session_features.parquet
```

Score it with:

```bash
PYTHONPATH=src python -m coverlab.score_office_background_v5 \
  --features /opt/coverlab/evidence/office/session_features.parquet \
  --model /path/to/model-bundle/models/B3-opaque.joblib \
  --out /opt/coverlab/evidence/office/office_b3_report.json
```

The strict research promotion requires office FPR <= the same model acceptance
limit (default: 50 false positives per 1,000,000 benign sessions).

## Process external framework/ECH PCAPs

Framework:

```bash
bash scripts/process_external_framework_v5.sh \
  /opt/coverlab/evidence/framework \
  /tmp/coverlab-framework-features

PYTHONPATH=src python -m coverlab.score_framework_holdout_v5 \
  --evidence-root /opt/coverlab/evidence/framework \
  --features-root /tmp/coverlab-framework-features \
  --model /path/to/model-bundle/models/B3-opaque.joblib \
  --out /opt/coverlab/evidence/framework/framework_model_metrics.json
```

ECH:

```bash
bash scripts/process_external_ech_v5.sh \
  /opt/coverlab/evidence/ech \
  /tmp/coverlab-ech-features

PYTHONPATH=src python -m coverlab.score_ech_holdout_v5 \
  --evidence-root /opt/coverlab/evidence/ech \
  --features-root /tmp/coverlab-ech-features \
  --model /path/to/model-bundle/models/B3-opaque.joblib \
  --out-manifest /opt/coverlab/evidence/ech/ech_holdout.jsonl
```

Both processors run the captured traffic through the same offline Suricata,
Zeek and Gold feature pipeline as the synthetic corpus.

## GitHub workflows

### Complete synthetic/recovery run

Run:

`Cover Channel Complete V5`

with:

- `run_full=true`
- `source_release=gh-31385273929-a1` (or another validated release)
- `require_external_evidence=false` while building the new model

The workflow reuses validated HF resume shards. The old timeout-prone
`K-benign-07` is deterministically divided into `K-benign-07a` and
`K-benign-07b` without changing the original campaign IDs. Together the two
halves still contribute exactly the original 6000 campaigns, and Stage K still
contains exactly 60000 benign campaigns.

The workflow then runs:

1. Stage A parser validation
2. core isolated/sequence/challenge/trusted/future shards
3. 60k matched benign Stage K
4. hosted long timing
5. 30 frozen mixed captures
6. B1/B2/B3 + packet-only TCN + fusion training
7. frozen mixed evaluation
8. exactly 500 post-baseline adversarial sessions
9. external evidence scoring when available
10. core and strict research acceptance

### External holdout run on the lab runner

Run:

`Cover Channel External Holdouts V5`

on a self-hosted runner carrying labels:

`self-hosted, linux, coverlab`

Inputs:

- `model_run_id`: completed V5 model run
- `evidence_root`: normally `/opt/coverlab/evidence`

The workflow downloads the frozen B3 model from that run, processes framework
and ECH PCAPs, scores office benign features, validates environment/long-timing
coverage and uploads a complete external-evidence artifact.

### Strict research promotion

After **Cover Channel Complete V5** and **Cover Channel External Holdouts V5**
have both completed, run **Cover Channel Research Promotion V5** with:

- `model_run_id`: the Complete V5 run that produced the frozen model;
- `external_run_id`: the External Holdouts V5 run that scored evidence against that same model.

The promotion workflow downloads the frozen model/mixed reports, the original
core acceptance, and the external-evidence artifact, then recomputes strict
acceptance with both `--require-nine-point-evidence` and
`--require-office-evidence`. No PCAP needs to be committed to Git.

## Promotion semantics

`core_model_candidate=true` means the generated corpus, trained models,
unseen synthetic checks and frozen mixed evaluation passed the internal
acceptance policy.

`research_model_candidate=true` additionally requires:

- all nine existing research evidence points;
- real Mythic/Adaptix/Sliver holdout metrics;
- wire-real ECH paired metrics;
- client/server/network environment diversity;
- external 1200/3600 second timing;
- real office benign FPR evidence.

Missing evidence is reported as missing. It is never silently replaced with a
synthetic fixture.
