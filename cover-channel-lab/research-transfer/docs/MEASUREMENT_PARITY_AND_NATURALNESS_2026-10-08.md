# Measurement parity and naturalness status — 2026-10-08

This is a *diagnostic ledger*. It does not claim that covert traffic can
masquerade as legitimate office activity or that a production corpus is ready.
Only authorized, synthetic benign controls were generated.

## Verified measurement parity

- [Windows NIC capture and extractor](https://github.com/MakSoS1/analytics_test/actions/runs/37764484638):
  49 physical Ethernet frames, two oversized frames, 51 normalized virtual
  packet segments, and 51 packet entries in each full sequence array.
  Byte-identical PCAPNG-to-PCAP conversion; one TLS session of about 17.92 s.
  `packet_accounting.passed=true`. This is a single public-HTTPS Windows
  connection, **not** an independent office control population.
- The [production extractor](../code/lab_pipeline/extract_lab_features.py)
  intentionally expands oversized frames to segments of at most 1514 bytes
  using `split_coalesced_frames`. Therefore, `pcap_frames != pkt_count`
  is not automatically corruption. Audit physical and normalized counts
  separately, with sequence arrays matching `pkt_count`.
- [Additional office-day validation](https://github.com/MakSoS1/analytics_test/actions/runs/37764820582):
  all 8,002 released rows passed aggregate sequence-length accounting;
  `sequence_length_mismatches=0`,
  `sequence_vs_pkt_count_mismatches=0`, `empty_sequences=0`,
  `invalid_pkt_counts=0` on both days. Diagnostic comparison on 60
  measured numeric transport features yielded day-to-day AUC 0.56138.

## Naturalness still NOT PASSED

- [Last completed 64-control E2E](https://github.com/MakSoS1/analytics_test/actions/runs/37758961855):
  all 64 PCAP quality checks passed, but held-out office vs generated
  controls had nonlinear C2ST max AUC approximately **1.0**.
- Comparing the same controls with added day-22/day-28 office transport slices
  (destination TCP/443, segment `pkt_count >= 6`) yielded AUC
  **0.9998255 / 0.9997360** respectively.
- The difference is not only in flow timing. The measured classifier
  also exploits packet counts, sizes, TCP flags, flow-state semantics,
  TLS fingerprint distributions and payload/context characteristics.
- An AUC near 0.5 for **two genuine office-day slices** is a useful negative
  control, not evidence that the generator is indistinguishable from office.

## Scope and integrity constraints

- Day 22 TLS measurements are unobserved/null and must not be invented.
  Day 28 has some observed TLS features. These days were explored earlier
  and are not a pristine holdout.
- Office Parquet rows are anonymized and **not asserted to be ground-truth benign**.
  The release contains no raw office PCAP or decryption key.
- Capture point relative to NAT/TLS interception and client OS mixture
  remain unknown. A Windows GitHub runner is not a surrogate for an
  authenticated corporate workstation at the mirror point.
- Do not reconstruct or edit PCAP timestamps/bytes to pass statistical tests,
  reproduce real training rows, or optimize suspicious sessions directly to
  evade NDR classification.

## Next defensible verification gate

1. Compare compatible, observed client/protocol subpopulations with group-
   disjoint splits; report sample support for each slice before AUC.
2. Audit full TCP connection lifecycle, not merely inter-request intervals.
   Keep a separate distinction between physical packets, virtual segments,
   application requests, and sessions.
3. Check transport and TLS feature schema parity with the same extractor
   across genuine Windows/Linux benign test captures.
4. Reserve a newly collected, previously unseen office day for final external
   confirmation. Do **not** claim final naturalness on 22/23/28 September.
5. Until an appropriately powered, fully independent test passes, leave
   `naturalness_status=not_passed`, `training_eligible=false`, and
   `production_ready=false`.

No further office machine deployment is needed for these measurement steps.
Additional bulk copies of the same 22/28 September data would not close
the measurement and domain-equivalence gaps.
