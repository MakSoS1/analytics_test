# ExamClips analysis recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resume inspection of the existing twenty long-lecture results in isolated authorized GitHub runners.

**Architecture:** Three private runner workspaces receive a bound encrypted Library materialization plan. They authenticate original artifacts and return bounded encrypted review assets to the corresponding reviewer. All case choices and private input boundaries are explicit.

**Tech Stack:** Node24, Python3, FFmpeg, existing evidence crypto and diagnostics, Forge1.4.3, noble-hashes2.4.0 and esbuild0.28.2.

**Spec:** docs/superpowers/specs/2026-11-11-examclips-analysis-recovery.md

## Global Constraints

- Repository MakSoS1/analytics_test; branch qa/examclips-audit-2026-11-11 only.
- Exactly20 primary cases; the native probe increments the corpus by0.
- No plaintext secrets or private review assets in public Git history or logs.
- RSA4096/OAEP-SHA256; AES256-GCM with12-byte IV and16-byte tag; independent HKDF labels.
- Complete, unmodified current Library helpers and transfer metadata.

## Review Focus

- Replayed or cross-lane request: reject before file access.
- Path traversal, links or duplicate ZIP members: reject extraction.
- Wrong original run or unauthenticated ciphertext: no plaintext review.
- Missing runtime entropy: prohibit RNG fallback; test explicit seed interoperability.
- Interrupted diagnostic or expired transfer: preserve evidence and record infrastructure status without a site-quality verdict.

## Task1: Bound protocol and encrypted bridge

**Files:** tools/examclips-recovery/protocol.mjs, test-protocol.mjs, bridge.mjs, client.mjs, test-client.mjs, build-client.mjs; .github/workflows/examclips-review-recovery.yml.

**Interfaces:** requireIdentity(env), validateRequest(value,lane,expected), targetFor(lane,key); runner descriptor and per-sequence authenticated replies.

- [ ] Test replay, path traversal, foreign cases and exactly20 primary identities.
- [ ] Implement validation and build the pinned browser bundle.
- [ ] Execute known-answer tests in a Node VM without crypto/Buffer/TextEncoder and then in functions V8.
- [ ] Complete public RSA-OAEP/AES-GCM interoperability before any private handoff.

## Task2: Authenticate and recover original evidence

**Files:** tools/examclips-recovery/ingest.mjs, zip_guard.py, test_zip_guard.py.

**Interfaces:** ingestCase({target,root,privateKey,gh,downloadArtifact}) returns a verified receipt and a contained evidence directory.

- [ ] Test traversal, duplicates, wrong case and oversized archive metadata.
- [ ] Verify outer ZIP digest, multipart hashes and independently specified original cryptographic context.
- [ ] Apply Library identity through its unchanged helper and verify recovery-key public fingerprint.
- [ ] Inspect the small supplementary failure first, then the primary cases, retaining truthful integrity receipts.

## Task3: Bounded media inspection and reporting

**Files:** tools/examclips-recovery/media.py and encrypted per-lane reply paths.

**Interfaces:** inventory, files, exact frame, start/status diagnostics; no arbitrary shell or external path access.

- [ ] Reuse the existing tested media helper with60-second output grids and bounded event sampling; preserve exact clocks and scope.
- [ ] Read all topic text, inspect actual rendered titles and source/output frames, and resolve significant cuts or framing risks.
- [ ] Review all20 primary cases, with failed exports and infrastructure interruptions distinguished.
- [ ] Produce the new Russian report with per-case evidence and explicit limitations.

## Execution ledger

Ruling: the local executor is unavailable, so existing isolated QA branch/API leases replace local worktree scripts. No main-branch or production mutation is authorized. Public code is reviewed and tested remotely before private input.

- Pure protocol regression checks: baseline failed with missing requireIdentity, implementation passed in V8; the same public test file will run in Node on Actions.
- Review finding: primary evidence includes selected-manifest.json at archive root. A real-layout regression has been added before the extraction allowance; the first public-only Actions test run is expected to expose this failure. No private handoff is permitted before correction.
- Review finding: mapped diagnostics must use each exact pre-export project. The initial existing-helper wrapper is not approved for mapped quality claims; it will be replaced before private inspection.
