# Isolated Stand45 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the original 45 real lectures through the documented local current-build app without contacting production authentication or billing.

**Architecture:** Reuse existing RSA/AES envelope helpers for a preparation handoff, encrypted shared CI bundle, and per-case unlock handoffs. Serve verified assets privately on loopback, adapt the existing normal-UI runner, and retain its encrypted outputs and bounded diagnostic review.

**Tech Stack:** Node 22, built-in crypto/http, Python stdlib ZIP validation, existing Playwright/Chrome and pinned FFmpeg.

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
- SharedArrayBuffer isolation headers and explicit Tesseract preserve the hosted engine path.
- Preparation and matrix cleanup run on failure; expired handoffs do not create false product results.

### Task 1: Transport and verified bundle

- [ ] Write failing tests for payload shape, purpose/identity binding, download origin guards and safe ZIP/assets.
- [ ] Implement stand configuration, handshake adapter, preparation encryption and case decryption with existing crypto primitives.
- [ ] Verify real fixture encryption and exact private CI archive extraction locally; no real-site requests.

### Task 2: Static instance and UI runner

- [ ] Write failing tests for loopback-only serving, forbidden auth/billing origins, correct isolation headers and secret-safe error text.
- [ ] Implement static server and browser request policy; adapt only run target/startup/provenance and explicit OCR UI selection.
- [ ] Verify a bounded local UI/media fixture with actual Chrome and existing full-decode helpers.

### Task 3: Workflow and handoff documentation

- [ ] Add preparation/matrix workflow, required environment names, private cleanup and encrypted artifact handling.
- [ ] Reuse validated 14 Python helper tests and existing crypto tests; run new focused safety tests.
- [ ] Deliver exact files, protocol/schema, local proof and remaining risks to root for review before dispatch.
