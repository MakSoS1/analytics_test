# SDD ledger — plan: docs/superpowers/plans/2026-10-06-natural-office-traffic-generator-v2.md

Ruling: GitHub connector branch is the isolated workspace because this harness has no local checkout/worktree for the repository — all implementation is confined to natural-traffic-generator-v2-2026-10-06 — cost if wrong: local-only Superpowers workspace scripts cannot provide bookkeeping, so this tracked ledger is removed before finalization.

Pre-flight: Task 1 contracts/profiles/reference -> Task 2 consumes ReferenceDataset/RuntimeProfile/FrozenProfileManifest: signatures aligned in plan.
Pre-flight: Task 1 RuntimeProfile/GenerationContext -> Task 3 consumes profiles/contexts: signatures aligned in plan.
Pre-flight: Task 1 CaptureBundle -> Task 4 adapters produce CaptureBundle: signatures aligned in plan.
Pre-flight: Task 2 FrozenProfileManifest -> Task 5 composition consumes frozen manifest: aligned in plan.
Pre-flight: Tasks 1-5 -> Task 6 CLI/reporting consumes all public interfaces: aligned in plan.

Task 1: RED natural-traffic-tdd run 37490940621 failed because natural_traffic package did not exist.
Task 1: Ruling: feature contract is full declared feature schema, not numeric-only — committed dictionary includes categorical/sequence features and spec requires full features; Task 2 owns model encoding — cost if wrong: heterogeneous feature handling becomes Task 2 responsibility.
Task 1: regression RED run 37492011376 proved dns_label_entropy was incorrectly filtered by substring target-label logic.
Task 1: complete (commits 78962b0..b2b0465, tests: natural-traffic-tdd run 37492169863 → 10/10 pass).

Task 2: RED run 37492668648 failed only because natural_traffic.calibration/evaluation did not exist.
Task 2: GREEN run 37493371264 passed 21/21 natural tests.
Task 2: complete (commits b6091cf..53a397e, tests: natural-traffic-tdd run 37493772325 → natural 21/21 pass; full research-transfer 99/99 pass).

Task 3: RED capture/resource/integrity/capability tests committed.
Task 3: GREEN implementation added after RED run 37494499185 (missing natural_traffic.capture only).
Task 3: unit GREEN run 37499295791 passed natural and full research-transfer suite.
Task 3: Ruling: GitHub Actions workflow is configuration, validated by the existing integration test rather than a separate config unit test — cost if wrong: CI syntax/runtime failure blocks Task 3 and is fixed before continuing.
Task 3: Ruling: real-capture smoke run 37499500808 failed before capture because unittest target `code.tests...` resolved Python stdlib `code`; use unittest discovery against test_natural_capture.py — cost if wrong: smoke remains blocked, no production behavior is affected.
Task 3: Root cause from run 37499730457: tcpdump kernel filter received 30 packets but userspace captured 0 because cleanup terminated the sudo wrapper; capture process now owns a session/process-group and is stopped with SIGINT so tcpdump flushes its PCAP — cost if wrong: real smoke will still fail and Task 3 stays open.
Task 3: Diagnostic probe added after run 37499992284 repeated 0 userspace captures despite kernel filter hits; independent shell tcpdump probe will distinguish runner restriction from backend lifecycle — no production change.
Task 3: Independent runner probe in run 37500267650 captured and read loopback packets successfully. Root cause is short-lived libpcap TPACKET_V3 buffering: -U only flushes delivered packets; backend now requests --immediate-mode so short TLS sessions reach userspace before shutdown — cost if wrong: third capture attempt fails and capture backend architecture must be reconsidered.
Task 3: complete (commits 831e454..b67f9ac, tests: natural-traffic-tdd run 37500566115 → unit/full regression + real Linux TLS capture all pass).
Task 4: RED adapter tests committed; awaiting natural-traffic-tdd evidence.
Task 4: GREEN implementation added after RED run 37500995186 confirmed missing natural_traffic.adapters only.
Task 4: complete (commits db5bc1b..e02bd36, tests: natural-traffic-tdd run 37501336754 → natural/full regression + real Linux capture all pass).
Task 5: Ruling: public GitHub contains feature/Arkime Parquet but no raw office PCAP, so CI composition has a pseudonymized feature-table mode and a separate strict raw-office delegate; only the latter may claim endpoint collision checking against office packets — cost if wrong: public CI can validate feature/membership integrity but cannot prove packet-level office overlay without private raw inputs.
Task 5: RED composition/full-extraction tests committed.
