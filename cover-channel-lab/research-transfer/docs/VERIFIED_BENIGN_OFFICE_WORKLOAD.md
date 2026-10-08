# Verified benign office application-workload fixture

This module produces **real, semantically verified HTTPS conversations** from
disposable application actions. It complements protocol-level Cover Channel
controls; it is not a tool for morphing, camouflaging, or replaying attacks.

## Run locally

Requires Python 3.12 and OpenSSL. Packet capture is optional and additionally
requires Linux, `tcpdump`, and local capture permissions (`sudo -n tcpdump` for
non-root users). The fixture server binds **only to 127.0.0.1**. The TLS key and
certificate are generated inside an automatically destroyed temporary folder;
the client verifies the ephemeral peer certificate. No third-party domain,
credentials, or real employee data is accessed.

```bash
cd cover-channel-lab/research-transfer
PYTHONPATH=code python -m natural_traffic.office_workload \
  --out /tmp/verified-benign-office-20261008 \
  --sessions 3 --seed 20261008 --capture
```

Each independent client session completes these four application tasks:

1. List and read a disposable document.
2. Edit the document with optimistic revision checking, then read it back.
3. Upload and download a dummy file, verifying identical bytes and SHA-256.
4. Post and retrieve a synthetic collaboration message.

All eight underlying requests run over real, certificate-verified TLS, using
Python's standard HTTPS client. Requests are not replayed packet templates.
The result is an immutable PCAP plus `workload_receipt.json` with semantic
completion checks, source type, count evidence, and a capture quality status.
The PCAP is never rewritten or re-timed after capture. The public CI artifact
contains only the receipt and aggregated extractor diagnostics, not packet
payloads or the TLS private key.

The GitHub Actions job `verified-benign-office-workload` captures these HTTPS
tasks on Linux loopback with `tcpdump`, checks PCAP quality, and runs the
existing *production* office-session extractor. It refuses empty extraction,
changed capture hashes, and failed semantic tasks.

## Input contract for downstream defender experiments

`natural_traffic.defender_domain prepare` accepts:

| Input | Interpretation |
|---|---|
| `.pcap` | Immutable classic Ethernet capture; runs production extractor |
| `.parquet` | Previously extracted feature table |
| `.csv` | Previously extracted comma-separated feature table |
| `.tsv` | Previously extracted tab-separated feature table |
| `.jsonl` | Previously extracted one-feature-record-per-line JSON table |

Zeek/Suricata raw events are **not** silently equated to the full measured
office feature schema; they require an explicit, validated extractor. An
unknown format fails closed. The original source SHA-256 is checked before
and after ingestion, and source/group/label metadata never becomes model-X.
Original uploaded captures are not edited in order to resemble an office.

## Scientific interpretation

Passing this fixture's tests establishes application semantics, genuine TLS,
capture integrity, and compatibility with the production extractor. **It does
not establish the office naturalness of these sessions.** In particular, a
Python HTTPS fixture on a GitHub runner is not automatically a representative
Office/SharePoint/Chromium/Windows end-user task on the organization's network.

Before reporting naturalness, collect consented, independently annotated
application workloads from the target network, document the mirror/NAT/TLS
proxy location and client population, then evaluate frozen benign captures
against a previously unseen office day. The existing `naturalness_release_gate`
must remain fail-closed until these requirements and the C2ST/distribution
gates pass. The fixture never calibrates suspicious activity against an NDR.
