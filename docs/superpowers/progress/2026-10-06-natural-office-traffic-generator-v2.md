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

Task 2: RED tests committed for leakage, support, frozen manifests, C2ST, family distance and technique signal.
