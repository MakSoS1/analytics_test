# Authorized live ExamClips audit

This harness exercises the real production application at https://examclips.dpdns.org/app/ through official Playwright Chrome on a GitHub Actions Ubuntu VM. Authentication, entitlement checks, complete-source ASR, model downloads, topic planning, camera analysis and MP4 encoding all use the unchanged live site. The harness does not install a modified production build, seed authentication, supply a transcript, approve candidate topics, alter topic durations or replace a renderer.

The only authorized repository is MakSoS1/analytics_test and the only workflow branch is qa/examclips-audit-2026-11-11. The workflow triggers when its own workflow file or files under tools/examclips-audit change on that branch. Commits under .audit-handoff do not match those paths and do not trigger another run. There is no matrix: each workflow run has its own ephemeral authentication key. Distinct runs can process different case selections.

## Selecting sources and budgets

manifest.json contains the public source corpus. Each case has a stable ID, title, reference language, expected complete duration and source URL. RUTUBE cases additionally specify their 32-character video ID and may limit downloaded source resolution with max_height. Direct and HLS sources are supported. The source is downloaded completely and checked with ffprobe. The original media is kept outside the evidence directory and is removed after its case.

run-config.json selects one to six case IDs for sequential execution in a single browser profile. The default pilot budget is 2,700 seconds per complete case, including download, analysis, background analysis and exports. A case may be configured for up to 5,400 seconds; selected budgets must total at most 270 minutes. The profile and downloaded models are reused within one run. They are not uploaded as artifacts.

The manifest language is reference metadata only. The browser preserves the site's automatic language setting and full-ASR setting and records what it observes. Source resolution limits apply to downloading the source; MP4 export remains at the site's standard 720 by 1280, 15 fps setting.

Every automatically proposed exportable clip is processed in sequence. Candidate topics or topics that the application requires a person to review remain unapproved and receive an explicit not_run reason. A timeout or memory failure does not turn a representative clip into a successful whole-case result. Each clip records downloaded, failed or not_run status, timing and a reason where applicable.

## One-run encrypted authentication handoff

The runner generates a fresh RSA-4096 key pair. It stores the private PEM in its private temporary directory and publishes only a descriptor at .audit-handoff/RUN_ID/public.json on the authorized branch. The descriptor contains the public key, SHA-256 fingerprint, repository, branch, workflow run ID, attempt, creation time and a 14-minute expiry. The runner then polls .audit-handoff/RUN_ID/encrypted.json.

The operator retrieves public.json and invokes the local encryption utility with a private credentials JSON file and a local ciphertext destination:

    node tools/examclips-audit/encrypt-handoff.mjs public.json credentials.json encrypted.json

credentials.json must be a mode-0600-or-stricter local file containing email and password strings. It must never be committed, attached to an issue, written to an Actions variable or uploaded. Only the generated encrypted.json is committed to the exact handoff path for that run. The public descriptor and encrypted envelope do not authorize a different repository, branch, run or attempt.

The envelope uses a random AES-256-GCM key, a 12-byte nonce and RSA-OAEP with SHA-256 to wrap the AES key. The algorithm, key fingerprint and exact context are authenticated as additional data. The runner checks that context before decrypting, masks the two credential fields, writes the short-lived login file with mode 0600 and deletes the private PEM. The browser harness deletes the login file immediately after reading it. No authentication profile, storage state, trace, HAR, login screenshot or response body becomes an artifact. The final cleanup removes runner-private media and profile directories.

The public-key publication retries a conflicting GitHub content update once after refetching. That retry reuses only the ephemeral key for the same run. There is no shared persistent runner key.

## Native file-picker accommodation

The source is supplied through the application's existing hidden file input with Playwright setInputFiles. This avoids the desktop-only upload picker without changing the upload event handler.

When disable_native_save_pickers is true, the browser exposes showSaveFilePicker and showDirectoryPicker as unavailable before loading the app. The site's existing fallback then renders each complete MP4 into memory and downloads it. This accommodation is recorded in run.json and every result.json. The actual renderer still runs. Long clips may exhaust browser memory; this is reported as a failure or incomplete case, never as a completed export. Batch directory export is not used.

## Evidence and completion criteria

Each case saves source metadata, observed settings, progress records, browser errors, the project JSON exported from the UI, an SRT exported from the UI, microtopic titles and full source-segment EDL, screenshots with account controls masked, and actual downloaded MP4 files. Successful exports are probed for both audio and video, expected standard dimensions and full EDL duration. Up to three representative frames are extracted from each output for inspection.

A case is complete only when every proposed clip was downloaded successfully, the observed ASR loop reached the final window, the transcript reaches the final tenth of the source, SRT was downloaded and no recorded case error remains. Transcript-end checks can flag legitimate trailing silence and therefore need human interpretation. A results-phase screen alone is insufficient evidence of complete ASR.

The run records site-build.json before processing, after every case and at the end. It also records Playwright, Node and browser versions. Unexpected initial build or a changed deployment prevents an unqualified run success. Optional local OCR/review API 404s are marked as expected because those local services are absent on the live site.

## Encrypted artifacts

evidence-recipient.pub.pem is the operator's public recipient key; its private counterpart must remain outside this repository and outside the runner. The packaging step scans the evidence directory, rejects symlinks and authentication/profile/trace-like paths, and permits only JSON, JSONL, SRT, PNG, MP4 and text outputs. Original lectures and browser profiles are outside that directory.

The evidence ZIP is encrypted with a fresh AES-256-GCM key wrapped by RSA-OAEP-SHA256 using the recipient public key. Only evidence.enc and encryption.json are uploaded. The plaintext ZIP is removed. There is no plaintext fallback, and GitHub artifact retention is three days. The encrypted context binds the archive to its repository, branch, run ID and attempt.

After downloading and unpacking the GitHub artifact container, the operator can authenticate and decrypt the evidence locally:

    node tools/examclips-audit/decrypt-evidence.mjs evidence.enc encryption.json evidence-recipient.private.pem evidence.zip

The decryptor removes a partial plaintext output if authentication fails. Review the authenticated run and per-case reports before treating downloaded files as complete results.

## Local checks and runtime limits

The crypto tests exercise long credential payloads, run/attempt binding, tamper rejection and streaming file encryption, including cleanup of failed decryptions:

    node --test tools/examclips-audit/crypto.test.mjs

The workflow additionally verifies that the configured recipient file parses as a public key. These checks establish the transport contract; they do not establish that production ASR or MP4 export succeeds. The first live source is a pilot for actual model download, processing and rendering throughput. Increase parallel workflow runs only after reviewing that evidence. Each VM always analyzes one source at a time and exports one clip at a time.

The workflow's GitHub token is supplied only to the public-key handoff step. Checkout does not persist credentials. The token has repository contents write permission so that the handoff can publish on the isolated audit branch; the script enforces the exact authorized repository and branch. The harness does not modify the application's source or deploy a production build.
