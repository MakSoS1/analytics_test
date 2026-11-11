# Authorized live ExamClips audit

This harness exercises the real production application at https://examclips.dpdns.org/app/ through official Playwright Chrome on a GitHub Actions Ubuntu VM. Authentication, entitlement checks, complete-source ASR, model downloads, topic planning, camera analysis and MP4 encoding all use the unchanged live site. The harness does not install a modified production build, seed authentication, supply a transcript, approve candidate topics, alter topic durations or replace a renderer.

The only authorized repository is MakSoS1/analytics_test and the only workflow branch is qa/examclips-audit-2026-11-11. The workflow triggers only when its workflow file or tools/examclips-audit/run-request.json changes on that branch. Helper edits and handoff commits do not trigger another run. A preparation job validates the requested IDs against the complete manifest, then launches one isolated matrix job per case, with at most ten running concurrently and fail-fast disabled.

## Selecting sources and budgets

manifest.json contains the public source corpus. Each case has a stable ID, title, reference language, expected complete duration and source URL. RUTUBE cases additionally specify their 32-character video ID and may limit downloaded source resolution with max_height. Direct and HLS sources are supported. The source is downloaded completely and checked with ffprobe. A validated RUTUBE original is also copied to its case evidence as original-source.mp4 for exact offline comparison when local public-source access is unavailable. That copy is included only inside the encrypted artifact. Copy failures are recorded as warnings, and incomplete copies are removed. Other originals stay outside the evidence directory and are deleted after their case.

run-request.json selects one to 25 distinct case IDs. Changing that request is the intentional launch or targeted-retry mechanism. The matrix supplies exactly one AUDIT_CASE_ID to each VM. A source longer than 30 minutes receives a 5,400-second case budget; other sources receive 2,700 seconds. The budget includes download, analysis, background analysis and exports. Each job has a 110-minute overall timeout, its own fresh browser profile, its own handoff and its own encrypted artifact. A completed case uploads immediately without waiting for the other cases. Browser profiles are excluded from artifacts; validated RUTUBE originals follow the encrypted-only evidence policy above.

The manifest language is reference metadata only. The browser preserves the site's automatic language setting and full-ASR setting and records what it observes. Source resolution limits apply to downloading the source; MP4 export remains at the site's standard 720 by 1280, 15 fps setting.

Every automatically proposed exportable clip is processed in sequence. Candidate topics or topics that the application requires a person to review remain unapproved and receive an explicit not_run reason. A timeout or memory failure does not turn a representative clip into a successful whole-case result. Each clip records downloaded, failed or not_run status, timing and a reason where applicable.

## Per-case encrypted authentication handoff

Each case job generates a fresh RSA-4096 key pair. It stores the private PEM in a temporary directory whose name includes the run ID, attempt and case ID, and publishes only a descriptor at .audit-handoff/RUN_ID/CASE_ID/public.json on the authorized branch. The descriptor contains the public key, SHA-256 fingerprint, repository, branch, workflow run ID, attempt, case ID, creation time and a 14-minute expiry. The job polls .audit-handoff/RUN_ID/CASE_ID/encrypted.json. A credential envelope for another case is rejected even within the same workflow run.

The operator retrieves public.json and invokes the local encryption utility with a private credentials JSON file and a local ciphertext destination:

    node tools/examclips-audit/encrypt-handoff.mjs public.json credentials.json encrypted.json

credentials.json must be a mode-0600-or-stricter local file containing email and password strings. It must never be committed, attached to an issue, written to an Actions variable or uploaded. Only the generated encrypted.json is committed to the exact handoff path for that run. The public descriptor and encrypted envelope do not authorize a different repository, branch, run or attempt.

The envelope uses a random AES-256-GCM key, a 12-byte nonce and RSA-OAEP with SHA-256 to wrap the AES key. The algorithm, key fingerprint and exact context are authenticated as additional data. The runner checks that context before decrypting, masks the two credential fields, writes the short-lived login file with mode 0600 and deletes the private PEM. The browser harness deletes the login file immediately after reading it. No authentication profile, storage state, trace, HAR, login screenshot or response body becomes an artifact. The final cleanup removes runner-private media and profile directories.

Public-key publication allows up to eight attempts, with refetching and bounded backoff on GitHub content-update conflicts between matrix jobs. Retries retain only the ephemeral key for that exact case and attempt. There is no shared persistent runner key.

## Native file-picker accommodation

The source is supplied through the application's existing hidden file input with Playwright setInputFiles. This avoids the desktop-only upload picker without changing the upload event handler.

When disable_native_save_pickers is true, the browser exposes showSaveFilePicker and showDirectoryPicker as unavailable before loading the app. The site's existing fallback then renders each complete MP4 into memory and downloads it. This accommodation is recorded in run.json and every result.json. The actual renderer still runs. Long clips may exhaust browser memory; this is reported as a failure or incomplete case, never as a completed export. Batch directory export is not used.

## Evidence and completion criteria

Each case saves source metadata, observed settings, progress records, browser errors, the project JSON exported from the UI, an SRT exported from the UI, microtopic titles and full source-segment EDL, screenshots with account controls masked, and actual downloaded MP4 files. Successful exports are probed for both audio and video, expected standard dimensions and full EDL duration. Up to three representative frames are extracted from each output for inspection.

A case is complete only when every proposed clip was downloaded successfully, the observed ASR loop reached the final window, the transcript reaches the final tenth of the source, SRT was downloaded and no recorded case error remains. Transcript-end checks can flag legitimate trailing silence and therefore need human interpretation. A results-phase screen alone is insufficient evidence of complete ASR.

The run records site-build.json before processing, after the case and at the end. It also records Playwright, Node and actual Chrome versions, viewport, OS/image, CPU model and count, and total system memory. Total memory is not a peak-memory measurement. Unexpected initial build or a changed deployment prevents an unqualified run success. Optional local OCR/review API 404s are marked as expected because those local services are absent on the live site. Source acquisition failures are classified as audit_environment/environment_failed and do not establish a site-quality failure. Safe completion-check booleans and processing-start status are written to the final case log as well as encrypted evidence.

## Encrypted artifacts

evidence-recipient.pub.pem is the operator's public recipient key; its private counterpart must remain outside this repository and outside the runner. Before launching, retain that private key in durable private storage independent of the transient executor. Losing it makes the encrypted artifacts unrecoverable. The packaging step scans the evidence directory, rejects symlinks and authentication/profile/trace-like paths, and permits only JSON, JSONL, SRT, PNG, MP4 and text outputs. The only retained full originals are validated RUTUBE original-source.mp4 files, encrypted with all other case evidence. Browser profiles and authentication material stay outside that directory.

Each case's evidence ZIP is encrypted with a fresh AES-256-GCM key wrapped by RSA-OAEP-SHA256 using the recipient public key. Only evidence.enc and encryption.json are uploaded in an artifact named with the run ID, attempt and case ID. The plaintext ZIP is removed. There is no plaintext fallback, and GitHub artifact retention is 30 days. The encrypted context binds the archive to its repository, branch, run ID, attempt and case ID. Each VM retains only one case's evidence, bounding disk growth independently of the full corpus.

After downloading and unpacking the GitHub artifact container, the operator can authenticate and decrypt the evidence locally:

    node tools/examclips-audit/decrypt-evidence.mjs evidence.enc encryption.json evidence-recipient.private.pem evidence.zip

The decryptor removes a partial plaintext output if authentication fails. Review the authenticated run and per-case reports before treating downloaded files as complete results.

## Local checks and runtime limits

The crypto tests exercise long credential payloads, run/attempt binding, tamper rejection and streaming file encryption, including cleanup of failed decryptions:

    node --test tools/examclips-audit/crypto.test.mjs tools/examclips-audit/audit-context.test.mjs

The workflow additionally verifies that the configured recipient file parses as a public key. Tests cover distinct paths for all 25 cases, invalid run requests, case-bound credentials and evidence, and full-source budget selection. These checks establish the transport contract; they do not establish that production ASR or MP4 export succeeds. The completed TED pilot supplies initial model and render timing evidence. Each VM analyzes one complete source and exports its proposed clips sequentially; no representative-only result is treated as a full pass.

The workflow's GitHub token is supplied only to the public-key handoff step. Checkout does not persist credentials. The token has repository contents write permission so that the handoff can publish on the isolated audit branch; the script enforces the exact authorized repository and branch. The harness does not modify the application's source or deploy a production build.
