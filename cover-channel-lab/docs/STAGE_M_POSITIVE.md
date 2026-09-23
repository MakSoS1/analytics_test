# Stage M — positive-only implementation-diversity corpus

Stage M extends the retained V5 corpus without regenerating it. Its purpose is to make the positive class vary by implementation, network conditions, event count, timing, payload style, and directionality so a detector cannot succeed by learning one Python/TLS/server fingerprint.

## Scope and safety

Stage M models network shapes only. Every hostname is a local `.test` alias, every service terminates inside the isolated `10.20.0.0/24` lab, client namespaces have no default route, the DNS resolver forwards only to the fixed in-lab authoritative server, and the duplex TCP fixture never accepts a destination or opens an onward connection. No malware, command execution, persistence, credential access, external C2, unrestricted proxy, or Internet dependency is present.

Stage M is **positive-only**. It does not create synthetic legitimate/office negatives. Office traffic is intentionally a later population used for FPR/precision evaluation.

## Corpus contract

The deterministic contract contains **4,750 campaigns**:

- 2,950 core campaigns matching the A1–A10 coverage plan;
- 1,200 implementation-diversity campaigns;
- 600 explicit implementation-holdout campaigns (`training_eligible=false`).

Families:

| Family | Campaigns | Shape |
|---|---:|---|
| M-HTTPS-BEACON | 680 | HTTPS beacon, interval/jitter, asymmetric bursts |
| M-HTTPS-FRONT | 630 | same shape through local shared-front aliases |
| M-HTTPS-LOWENT | 240 | short code/GUID/fixed-hex payloads |
| M-HTTPS-FRAG | 240 | 2–6 character fragments over request series |
| M-HTTP-443 | 260 | plaintext HTTP on 443 and 80 |
| M-DNS-BEACON | 530 | low-QPS A/AAAA/TXT, UDP/TCP, direct/resolver |
| M-DNS-BULK | 360 | unique-subdomain burst with NXDOMAIN profiles |
| M-DOH | 250 | DNS wire messages over local DoH GET/POST |
| M-DEAD-DROP | 280 | local shared-service lookup, then separate HTTPS |
| M-WSS-LONG | 480 | long-lived WSS with sparse/burst traffic |
| M-TUNNEL | 430 | bounded local duplex TCP, no forwarding |
| M-FALLBACK | 270 | HTTPS→DNS and DNS→HTTPS transitions |
| M-RMM-SHAPE | 100 | periodic poll followed by interactive burst |

## Independent implementations

HTTP/HTTPS campaigns rotate real clients already available in the lab: httpx H1/H2, curl, Go `net/http`, Node `fetch`, Java `HttpClient`, Rust `reqwest`, Python stdlib, and Chromium. They terminate on three independent local HTTP server implementations: Hypercorn/ASGI, Go `net/http`, and Node `http/https`.

DNS uses three client implementations (dnspython, `dig`, raw sockets) and two paths: direct local authoritative; or local recursive fixture → separate in-lab authoritative server. The recursive fixture has no system-resolver or Internet fallback.

WSS uses Python `websockets`, Java `HttpClient` WebSocket, and Chromium against the custom Python WebSocket server and Hypercorn ASGI WebSocket endpoint. The duplex TCP family uses Python, Go, and Java clients with fixed-length, 32-bit length-prefixed, and line framing. The server only exchanges bounded synthetic frames and cannot proxy.

## Variation axes

Campaigns deterministically vary netem (`clean`, `wan_20ms`, `wan_80ms`, `lossy_wifi`, `constrained`), nominal interval (30 s, 60 s, 5 min, 15 min, 60 min), jitter (0/10/30%), event count (3/5/10/20/50/100 where appropriate), payload style, traffic direction, keep-alive/reconnect, DNS A/AAAA/TXT + UDP/TCP + NXDOMAIN profiles, and fallback order.

Hosted generation uses accelerated waits while preserving nominal timing in the manifest. A separate self-hosted workflow exists for real 15/60-minute timing evidence. The manifest explicitly records `timing_fidelity` and `timing_acceleration`.

## Holdout design

Every campaign stores `holdout_groups` for implementation, client, server, network, timing and payload. The 600 `implementation_holdout` campaigns are `training_eligible=false`, so the existing split contract forces them to challenge. `stage_m_holdouts.json` retains all groups for leave-one-group-out evaluation later.

## Generated artifacts

Each shard keeps normal CoverLab Bronze PCAP/manifests, Silver Suricata/Zeek and Gold feature tables, plus `stage_m_coverage.json` and `stage_m_holdouts.json`. GitHub Actions retains safety copies for 90 days and the workflow publishes every successful shard to the private Hugging Face dataset when `HF_TOKEN` is configured.

## Running

Smoke:

```bash
COVERLAB_STAGE_M_SMOKE=1 COVERLAB_NETEM_PROFILE=clean \
  ./scripts/run_shard_ci.sh stage_m 0 1 /tmp/stage-m M-positive-smoke
```

One full matrix cell:

```bash
COVERLAB_NETEM_PROFILE=wan_80ms \
  ./scripts/run_shard_ci.sh stage_m 2 4 /tmp/stage-m M-positive-wan80-s2
```

Optional filters: `COVERLAB_STAGE_M_TIER=core|diversity|holdout|all`, `COVERLAB_STAGE_M_FAMILY`, `COVERLAB_STAGE_M_INTERVAL`, `COVERLAB_STAGE_M_LIMIT`, and `COVERLAB_STAGE_M_REAL_TIMING=1`.

The standard hosted workflow intentionally contains **no model-training and no benign-generation job**; it produces only the positive corpus and parser/feature layers.
