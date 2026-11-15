# Isolated Stand45 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the original 45 real lectures through the documented local current-build app without contacting production authentication or billing.

**Architecture:** Reuse existing RSA/AES envelope helpers for a preparation handoff, encrypted shared CI bundle, and per-case unlock handoffs. Serve verified assets privately on loopback, adapt the existing normal-UI runner, and retain its encrypted outputs and bounded diagnostic review.

**Tech Stack:** Node 24, built-in crypto/http, Python stdlib ZIP validation, existing Playwright/Chrome and pinned FFmpeg.

**Spec:** STAND_DESIGN.md and root's explicit implementation/transport instructions.

## Global Constraints

- Local bundle only; no publication or dispatch before root review.
- No product source/asset patching; private compiled application stays out of public Git and plaintext artifacts/logs.
- Exact CI archive, source commit, case identity and asset hashes are required.
- `test_instance` scope in all results; production account state untouched.
- Preserve full ASR, all eligible default clips, source media and encryption recipient.

## Review Focus

- Wrong-origin requests fail before leaving the browser; localhost auth/billing cannot be fulfilled.
- Wrong-run/purpose/key payloads fail before bundle disclosure; errors never echo payloads or capability URLs.
- ZIP traversal/symlinks/unexpected app assets or digest mismatches prevent serving.
- COOP/CSP are retained and COEP is absent, matching the observed hosted single-thread WASM exposure. Both runtime gates require `crossOriginIsolated=false` and unavailable `SharedArrayBuffer`.
- The visible localhost OCR default stays `auto`; there is no manual override. Automatic slide OCR independently falls back to browser Tesseract after the unavailable local capability probe.
- Mandatory real ASR of a 25-second public-source diagnostic excerpt must produce an actual nonempty transcript and completed UI before any full-source matrix is released.
- Preparation and matrix cleanup run on failure; expired handoffs do not create false product results.

### Task 1: Transport and verified bundle

- [ ] Write failing tests for payload shape, purpose/identity binding, download origin guards and safe ZIP/assets.
- [ ] Implement stand configuration, handshake adapter, preparation encryption and case decryption with existing crypto primitives.
- [ ] Verify real fixture encryption and exact private CI archive extraction locally; no real-site requests.

### Task 2: Static instance and UI runner

- [ ] Write failing tests for loopback-only serving, forbidden auth/billing origins, correct isolation headers and secret-safe error text.
- [ ] Implement static server and browser request policy; adapt only run target/startup/provenance and preserve ordinary OCR defaults.
- [ ] Verify the bounded real-ASR gate on Actions before matrix release; local Chromium cannot start because its singleton socket is denied.

### Task 3: Workflow and handoff documentation

- [ ] Add preparation/matrix workflow, required environment names, private cleanup and encrypted artifact handling.
- [ ] Reuse the 18 Python helper tests and existing crypto tests; run focused transport, origin and ASR-completion checks.
- [ ] Deliver exact files, protocol/schema, local proof and remaining risks to root for review before dispatch.

## Runtime correction after the first attempt

Run 43760040493 is excluded from quality acceptance. Its RU03 reached model-download completion but timed out with no ASR progress or clips. The stand exposed SharedArrayBuffer through added COEP, whereas the successful live RU03 used single-thread WASM without SharedArrayBuffer. The replacement removes that harness difference and strengthens preparation from upload-only to actual ASR completion. The replacement Actions gate is authoritative; local helper tests alone do not establish recovery.
