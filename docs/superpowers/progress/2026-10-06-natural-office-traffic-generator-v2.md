# SDD ledger — plan: docs/superpowers/plans/2026-10-06-natural-office-traffic-generator-v2.md

Ruling: GitHub connector branch is the isolated workspace because this harness has no local checkout/worktree for the repository — all implementation is confined to natural-traffic-generator-v2-2026-10-06 — cost if wrong: local-only Superpowers workspace scripts cannot provide bookkeeping, so this tracked ledger is removed before finalization.

Pre-flight: Task 1 contracts/profiles/reference -> Task 2 consumes ReferenceDataset/RuntimeProfile/FrozenProfileManifest: signatures aligned in plan.
Pre-flight: Task 1 RuntimeProfile/GenerationContext -> Task 3 consumes profiles/contexts: signatures aligned in plan.
Pre-flight: Task 1 CaptureBundle -> Task 4 adapters produce CaptureBundle: signatures aligned in plan.
Pre-flight: Task 2 FrozenProfileManifest -> Task 5 composition consumes frozen manifest: aligned in plan.
Pre-flight: Tasks 1-5 -> Task 6 CLI/reporting consumes all public interfaces: aligned in plan.

Task 1: RED tests committed; awaiting GitHub Actions evidence.
Task 1: RED trigger commit after workflow registration.
Task 1: Ruling: feature contract is full declared feature schema, not numeric-only — committed dictionary includes categorical/sequence features and spec requires full features; Task 2 owns model encoding — cost if wrong: heterogeneous feature handling becomes Task 2 responsibility.
