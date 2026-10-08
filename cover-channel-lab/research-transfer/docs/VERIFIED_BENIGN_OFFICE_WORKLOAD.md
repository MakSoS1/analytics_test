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
With `--capture`, the result is an immutable PCAP plus
`workload_receipt.json` with semantic completion checks, source type, count
evidence, and a capture quality status. Without `--capture`, the receipt records
application completion only.
The PCAP is never rewritten or re-timed after capture. The public CI artifact
contains only the receipt and aggregated extractor diagnostics, not packet
payloads or the TLS private key.

The updated CI also runs `natural_traffic.office_profile_audit` after verified
extraction, then `natural_traffic.benign_transfer_evaluation` using frozen
measured transport features. It publishes two additional **safe aggregate**
files: `office-profile-report.json` and `benign-transfer-report.json`. Three
sessions on one Python runner are explicitly treated as **one independent
capture group**; the generated-vs-office C2ST therefore reports
`insufficient_support`, not a fabricated naturalness pass. The office-vs-office
22/28 September comparison is only a previously inspected negative control,
not a new blinded validation set.
The [first verified new Actions run 37855273730](https://github.com/MakSoS1/analytics_test/actions/runs/37855273730)
confirmed exactly three physical TLS sessions, three wire handshakes and 12
application tasks with production extractor parity. It also exposed a missing
Sep 22 `tcp_handshake_rtt_ms` field: the comparable office negative-control
feature set now excludes that *unmeasured* RTT before modelling, instead of
inventing a zero value or treating absent coverage as evidence.
The final [green Actions run 37857455916](https://github.com/MakSoS1/analytics_test/actions/runs/37857455916)
confirmed 60 comparable transport features, a grouped office-vs-office
negative-control ROC-AUC of **0.52687** (ExtraTrees) / **0.58607** (HGB),
and explicit `insufficient_support` for the one-source benign-vs-office
comparison. Its uploaded benign artifact is precisely four aggregate JSON
files, without PCAP, TLS secrets or per-host data.

For the full module map and experiment results see
[current project status](CURRENT_PROJECT_STATUS.md),
[transfer results](OFFICE_BENIGN_AND_TECHNIQUE_TRANSFER_RESULTS.md), and
[research history](RESEARCH_CHANGELOG_2026.md).

The GitHub Actions job `verified-benign-office-workload` captures these HTTPS
tasks on Linux loopback with `tcpdump`. It waits for an explicit interface-ready
acknowledgement before connecting, completes the application workload, then
waits for all expected TCP handshakes to be written to the live capture. Only
then does it stop `tcpdump`, check PCAP quality, and run the existing
*production* office-session extractor. It refuses empty extraction,
changed capture hashes, incomplete observed TCP handshake coverage, a mismatch
between extracted sessions and the independently counted wire handshakes,
and failed semantic tasks. This compares session *starts* with extractor rows;
it is not a proof of every TLS application record being preserved.

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
office feature schema: the input must contain at least 12 recognized transport
columns with finite numeric values in 80% or more rows **per column**.
Passing this structural check alone does not authenticate feature provenance
or any claimed labels. Raw security events require an explicit, validated extractor. An
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
