# Isolated current-code ExamClips audit

This retry branch selects seven reviewed terminal technical failures from the original 45 full lecture sources. The complete manifest is unchanged; `run-request.json` is the explicit seven-case subset. The active original workflow is not cancelled. See `RETRY_SCOPE.md` at the repository root for the exact delta and limitations. Every result is labelled `test_instance`. It does not establish a live-site authentication, billing, quota, or hosting pass.

The pinned private CI artifact is `examclips-dist` (14177000950), from app CI run 43751698466 at commit c8358a6df86ca0f77d859ebe8481a876b3e1abd5 / v1.3.20. `stand-config.json` records the archive size/SHA256, every served application asset's size/SHA256, and processing-source provenance. No private compiled app, source, artifact capability URL, or private key is included in this harness.

## Execution boundary

The only app target is `http://127.0.0.1:5173/app/`. The server verifies the pinned assets before listening, binds to loopback, serves declared files only, and retains COOP/CSP while omitting COEP to match the observed hosted static app. Both preparation and case startup require `crossOriginIsolated=false` and no `SharedArrayBuffer` exposure, preserving the hosted single-thread WASM selection without modifying application assets. It provides no authentication, billing, RapidOCR or local-LLM backend. The browser blocks production app/auth/billing requests, local auth/billing routes, unexpected origins, and write methods to public model origins. Blocked requests are audit-environment failures. No entitlement responses or app state are fabricated.

`run.mjs` uses a fresh browser profile for one complete source, automatic language, full ASR, standard 720×1280/15 FPS output and every default eligible clip. It preserves the original file-picker accommodation and encrypted evidence path. The manual OCR selector retains localhost's default `auto`; the hosted selector defaults to `tesseract`. Neither audit invokes manual scene analysis. Automatic slide OCR uses its own `auto` default and falls back to browser Tesseract when the static server returns 404 for `/api/local-ocr-capabilities`, as the production static server does.

## Bundle handoff contract

The workflow is restricted to `MakSoS1/analytics_test`, branch `qa/examclips-stand45-retry-2026-11-15`. Root publishes encrypted payloads after validating each fresh descriptor. The existing `crypto.mjs` primitive and envelope format are unchanged.

| Role | Runner command | Descriptor case and purpose | Exact plaintext payload fields |
|---|---|---|---|
| Preparation | `node tools/examclips-audit/stand-handoff.mjs prepare` | `bundle-prepare`, `stand-bundle-prepare` | `artifactUrl`, `bundleRecipientPublicKeyPem` |
| One source | `node tools/examclips-audit/stand-handoff.mjs unlock` | Source ID, `stand-bundle-unlock` | `bundlePrivateKeyPem` |

Descriptor and ciphertext paths are `.audit-handoff/<runId>/<caseId>/public.json` and `encrypted.json`. Each descriptor includes the exact repository, branch, run ID, run attempt, case ID, purpose, recipient fingerprint and a 14-minute lifetime. The handoff outputs `payload_path` and `private_dir` to `GITHUB_OUTPUT`; no plaintext payload is printed.

`stand-bundle.mjs prepare` consumes `AUDIT_HANDOFF_PAYLOAD`, verifies the pinned archive, safely extracts the declared app, and produces `AUDIT_ROOT/shared-encrypted-app/bundle.enc` plus `bundle-encryption.json`. The fresh per-run bundle RSA recipient is separate from the evidence recovery key. The archive capability is restricted to the approved artifact delivery hosts; redirects are individually checked.

The shared workflow artifact is `stand45-encrypted-app`. Case jobs download it to `STAND_ENCRYPTED_APP`, then `stand-bundle.mjs unlock` consumes their encrypted unlock payload, verifies ciphertext/provenance/AAD, decrypts to a private temporary ZIP, and extracts `AUDIT_ROOT/site`. Payload and temporary plaintext ZIP files are removed. The shared bundle's AAD uses purpose `stand-bundle` and case ID `bundle-prepare`.

A rerun attempt cannot decrypt a previous attempt's bundle. Retries require a fresh workflow run, fresh preparation and a fresh bundle recipient key. Do not weaken the context binding or overwrite an older shared artifact.

## Preparation fixture and diagnostics

Before the selected retry matrix starts, the preparation job downloads the ordinary full public RU03 source through the existing source downloader and checks its SHA-256 against the verified successful live source (`f7628bb149c68d1563664067b213c7653993aa76ef1739fe8a91890c0525d422`). It extracts seconds 20–45 solely for this diagnostic gate. A fresh official Chrome persistent context uses the same launch helper and normal options as the full case. The normal UI imports that 25-second excerpt, retains auto/full/standard defaults and starts real ASR. Passing requires an observed processing phase, a completed results phase with idle controls, and nonempty generated SRT with valid source times. Model-download completion or UI startup alone cannot pass. No transcript/project is imported and no ASR or entitlement state is injected.

ASR has a ten-minute deadline; the entire gate step has 18 minutes, and preparation has 45 minutes to include the 14-minute handoff, tool installation, source acquisition and final encrypted diagnostics. Failure prevents the full source matrix from starting. The excerpt, its provenance and hashes, actual generated SRT, bounded progress/console events, and a screenshot are encrypted preparation diagnostics only. The complete downloaded smoke source stays private and is removed. All 45 quality cases still use their complete original sources; the smoke is explicitly excluded from case totals.

The bounded report and any failure screenshot go only to `AUDIT_OUT/bundle-prepare`. The existing evidence packager encrypts that directory to the normal recovery recipient and uploads `examclips-stand45-preparation-<runId>-<attempt>`. Private application assets, payloads, profiles and archives stay under `AUDIT_ROOT` and are excluded. A failed fixture prevents the source matrix from starting.

Source evidence is uploaded as encrypted compact review artifacts and split full artifacts prefixed `examclips-stand45-review-` and `examclips-stand45-encrypted-`. The full review helper uses the actual exported MP4s and exact saved EDLs. Its job deadline reserves 15 minutes before the six-hour Actions ceiling for final encryption and uploads.

## Local verification

Run from the repository root after FFmpeg and FFprobe are available:

```bash
node --test tools/examclips-audit/*.test.mjs
python3 -S -m unittest discover -s tools/examclips-audit -p 'test_*.py'
```

The preparation workflow installs the pinned Playwright version, verifies/provisions the same pinned FFmpeg build when necessary, and runs these gates before handoff. Local Chromium in the authoring workspace failed before page startup with a denied singleton socket; the actual browser fixture is therefore a required Actions preparation gate. No local browser pass is claimed.

Remote model weight contents are not independently hashed by this harness. Unpinned upstream model changes, the unauthenticated CI build flags, runner/browser environment, and production-network differences remain explicit limitations. Processing/rendering source files and lockfile provenance are recorded, but byte identity of the entire production main bundle is not claimed.
