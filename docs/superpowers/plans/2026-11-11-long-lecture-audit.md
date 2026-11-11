# Long Lecture Audit Implementation Plan

> **For agentic workers:** Native execution in this session, followed by independent review. Execution is authorized by the user’s existing request; no additional approval gate.

**Goal:** Produce a complete evidence-backed audit of 20 new full lectures, each at least two hours.
**Architecture:** Keep the existing live-browser harness and isolated Actions jobs. Extend duration budgets and bounded encrypted transfers; collect exact original media, project snapshots and every exported MP4. Analyze results locally without changing the app.
**Tech Stack:** Playwright/Chrome, Node 24, Python, FFmpeg, GitHub Actions.
**Spec:** docs/superpowers/plans/2026-11-11-long-lecture-audit-spec.md

## Global Constraints

- Only authorized production URL and existing isolated QA branch.
- Exactly 20 new unique full sources, actual duration >=7200 seconds; no truncation/concatenation.
- Keep app defaults and existing eligibility rules; no manual topic approval.
- Credentials stay encrypted in transit, absent from public artifacts.
- Preserve old audit and distinguish harness, source and site failures.

## Review Focus

- A two-hour source must not inherit the former 90-minute case budget.
- Duration metadata may disagree with actual media; validate actual duration before site upload.
- Evidence exceeding connector transfer limits must remain reconstructable and authenticated.
- A crashed/long-running browser must still yield progress and partial evidence.
- Initial titles and rendered titles can differ; save pre-export and final project states.

## Task 1: Long-source runtime and progress

Files: tools/examclips-audit/audit-context.mjs, audit-context.test.mjs, run.mjs, download-source.py, run-config.json, manifest.json, run-request.json, .github/workflows/examclips-live-audit.yml.

- [ ] Add and run failing tests for >=7200 second budgets and invalid actual-duration admission.
- [ ] Assign long cases 18000 seconds, jobs 340 minutes and audit step 305 minutes; allow 30 minutes source acquisition.
- [ ] Require actual min_duration_sec=7200, retain validated originals, checkpoint settings/progress, and capture title provenance immediately before each export.
- [ ] Run existing crypto/context tests and Python validation, then independent harness review.

## Task 2: Bounded encrypted evidence transfer

Files: tools/examclips-audit/split-evidence.py, test_split_evidence.py, package-evidence.mjs, workflow upload steps.

- [ ] Add and run failing real-file tests for exact reconstruction, boundary parts and tamper detection.
- [ ] Split only encrypted evidence into <=240 MiB parts, max20; include per-part and whole-ciphertext hashes and encryption metadata.
- [ ] Upload each part as its own artifact; authenticate whole reconstructed ciphertext before extraction.
- [ ] Run tests and a small complete package/decrypt integration before launch.

## Task 3: Execute and review

- [ ] Verify corpus duration/diversity and fresh published build; launch pilots then remaining cases.
- [ ] Deliver encrypted credentials to each run-bound ephemeral key; monitor and recover environment-only failures.
- [ ] Fully decode outputs; inspect bounded native frame/audio samples, every topic boundary and significant omissions against full source/reference.
- [ ] Write per-case report, priority defects, exact review scope and evidence links; save final deliverables durably.
