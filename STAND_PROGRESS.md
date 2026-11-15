# SDD ledger — plan: STAND_PLAN.md

Ruling: Root explicitly selected the runner transport design and authorized local implementation in this standalone overlay. Root owns review, branch creation, publication and dispatch. No git worktree/commit is created in the shared repository.

Ruling: Root accepted a fresh RSA-4096 bundle-recipient keypair instead of a raw AES payload so existing crypto.mjs sealFile/openFile remain unchanged. The crypto primitive and envelope version are reused.

Pre-flight: Preparation produces bundle.enc + bundle-encryption.json using the stand-bundle context with caseId bundle-prepare; case transport consumes exactly that context plus its separately authenticated stand-bundle-unlock payload.
Pre-flight: Verified extraction produces site/app and an instance provenance record; the static server and UI runner consume those exact paths and target http://127.0.0.1:5173/app/.

Task 1: in progress; documentation, private CI archive digest, source lineage and asset inventory verified.

Task 1 complete: reused existing crypto, strict role-specific handoff, pinned artifact transport, safe allowlisted extraction, and actual private CI extraction verified locally. Payloads and capability URLs are never logged.
Task 2 complete: verified loopback static server, production/backend origin blocking, download-only external model policy, fresh-profile normal-UI case adapter, and truthful test-instance provenance. OCR default is retained after source tracing showed that automatic slide OCR independently probes the unavailable local capability and falls back to Tesseract in both static builds.
Task 3 complete locally: isolated branch workflow, all 45 cases (RU03 first, then descending source duration), mandatory preparation UI fixture, encrypted preparation diagnostics, existing compact/full evidence packaging, and cleanup. Root owns review and all remote changes.

Local validation: 21 Node tests and 18 Python tests passed before the final method guard; the new external-model-method regression was observed failing before the fix and passing afterwards. Final full-suite results are recorded in the handoff. All JavaScript, generated workflow shell blocks, embedded Python, and YAML structure parsed. Actual 18-asset extraction succeeded. Local Chromium could not launch because singleton socket() was denied with EPERM; no local browser UI pass is claimed. The workflow's preparation fixture is mandatory before matrix release.

Review fixes: external model hosts permit only GET/HEAD/OPTIONS; preparation UI failure report and bounded screenshot are encrypted from AUDIT_OUT only; fresh-run retry contract is explicit. Existing retest-review.py reads AUDIT_JOB_STARTED_UNIX and reserves 15 minutes before the six-hour job ceiling for packaging/uploads. Preparation ceiling is 30 minutes to cover handoff, tools, fixture and diagnostics.
