# External evidence capture and registration

This directory is for **wire-real challenge evidence captured in an authorized isolated lab**. External evidence is never training data.

The repository deliberately separates capture from validation. CoverLab does not expose an unrestricted C2 launcher. Sliver, Adaptix and Mythic captures are accepted only after the lab operator has constrained the framework to the lifecycle below and captured the traffic at the NDR observation point.

## Framework holdout

Allowed lifecycle stages are:

- registration
- idle
- poll
- synthetic_task
- synthetic_result
- sleep
- reconnect

Credential collection, persistence, lateral movement, arbitrary shell execution and post-exploitation are outside this dataset.

Register a capture:

```bash
PYTHONPATH=src python -m coverlab.evidence_register_v4 \
  --root external-evidence framework \
  --pcap /captures/sliver-safe.pcap \
  --framework sliver \
  --campaign-id j-sliver-safe-001 \
  --protocol https \
  --lifecycle registration,idle,poll,synthetic_task,synthetic_result,sleep,reconnect \
  --tool-version 1.5.0 \
  --adapter-version coverlab-v5 \
  --source-ip 10.77.0.21 \
  --started-at 2026-09-22T10:00:00Z \
  --ended-at 2026-09-22T10:05:00Z
```

Use `adaptix`, `mythic_httpx` and `mythic_websocket` for the other framework families.

## ECH

ECH captures must be actual ECH traffic. A scenario label is not accepted as proof that ECH was present on the wire. Register paired ECH-on/off or accepted/rejected evidence with a shared `pair_id`.

```bash
PYTHONPATH=src python -m coverlab.evidence_register_v4 \
  --root external-evidence ech \
  --pcap /captures/ech-h3-benign.pcap \
  --capture-id ech-h3-benign-001 \
  --ech-mode accepted_h3 \
  --pair-id pair-001 \
  --label-binary 0 \
  --protocol h3 \
  --source-ip 10.77.0.31 \
  --started-at 2026-09-22T10:00:00Z \
  --ended-at 2026-09-22T10:00:10Z \
  --ech-enabled true
```

Required modes are `grease`, `accepted_h2`, `accepted_h3`, `rejected`, `shared_frontend_benign` and `shared_frontend_suspicious`.

## Environment diversity

Register captures from real client/server/network combinations:

```bash
PYTHONPATH=src python -m coverlab.evidence_register_v4 \
  --root external-evidence environment \
  --pcap /captures/windows-nat.pcap \
  --capture-id env-windows-nat-001 \
  --session-count 500 \
  --client-stack windows_winhttp_schannel \
  --network-evidence nat
```

The contract covers Windows/SChannel, Firefox, Chromium, Java, Rust; nginx/envoy/caddy/apache/haproxy/IIS; and NAT, forward proxy, TLS inspection/bypass, partial capture, capture loss and connection migration.

## Long timing

The hosted workflow generates real 5/30/120/300-second timing profiles. The 1200/3600-second evidence must come from a long-lived isolated lab and may not be accelerated. Register each benign/suspicious capture with concrete timing provenance:

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

Repeat for a suspicious 1200-second capture and for benign/suspicious 3600-second captures. The external-holdout workflow processes these PCAPs with the same parser/Gold pipeline and scores them with the frozen B3 model.

## Office background

Only privacy-scrubbed, benign-verified office captures are registered:

```bash
PYTHONPATH=src python -m coverlab.evidence_register_v4 \
  --root external-evidence office \
  --pcap /captures/office-hour.pcap \
  --capture-id office-2026-09-001 \
  --duration-seconds 3600 \
  --session-count 100000 \
  --privacy-scrubbed
```

For a frozen offline mixed holdout:

```bash
bash ./scripts/compose_office_holdout_v4.sh \
  /captures/office-hour.pcap \
  /captures/cover-channel.pcap \
  /captures/office-cover-mixed.pcap \
  900
```

This shifts the CoverLab capture onto the office timeline and merges the files offline; it does not replay traffic onto a live network.
