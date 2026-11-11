# ExamClips long20 runtime evidence ledger

Final primary observation: 2026-11-11T23:19:50.919Z.

This is a public runtime and encrypted-artifact index for the 20 chosen lecture jobs. It is separate from the authenticated media and semantic review.

## Recorded result

- 20 unique primary cases, all terminal with every expected multipart artifact present.
- 17 harness-complete cases and 3 incomplete cases.
- 409 proposed topics; 406 MP4-save records; 2 failed exports; 1 topic not run.
- 151,548.346456 seconds of saved MP4 durations in aggregate; 21,705,371,482 bytes.
- 179 primary artifact parts; 42,581,263,542 encrypted outer ZIP bytes.
- 131,522.674 seconds summed case runtime. The observed chosen-case wall span was 2026-11-11T19:52:35.672Z through 2026-11-11T23:18:42Z.

Aggregate output duration is not a measure of source coverage. Saved EDL overlap, editorial order, gaps and the actual source/output frames require separate inspection. Success here is a harness completion state and is not a content-quality verdict. Public job logs do not print exact source bytes, duration and SHA256 for every case; those fields remain null rather than being inferred from ASR progress counters.

## Files

- runtime-ledger.json: exact chosen run/job map, all 406 per-clip public save records, all 179 artifact IDs, digests and expiry timestamps, progress observations and completion flags.
- case-summary.csv: one row for each of the 20 primary cases.
- mp4-downloads.csv: one row for each of the 406 logged MP4 saves.

The JSON also records 9 nonchosen scheduling or infrastructure jobs as excluded, and the separate successful native RUL01 probe. The native probe contributes zero primary lectures and is excluded from every primary total. Its actual MP4 visual review is separate.

Only public runtime metadata appears here. No private report content, account details, handoff credentials, signed URLs, decrypted source/project content or browser/payment screenshots are included. The encrypted transport digests identify files to authenticate; they do not substitute for a decrypted member inventory.
