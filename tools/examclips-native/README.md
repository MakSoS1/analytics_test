# Supplementary native export probe

This isolated harness reuses an authenticated long-lecture project and exports **one existing retained clip per selected project** through the genuine Chrome/Linux save dialog. It does not run ASR again or add a lecture to the twenty-case corpus. The prepared `run-request.json` is disabled; no workflow has been published or dispatched by this preparation.

## What is exercised

The source must still be a complete 7,200–10,800 second file within the app's 2,000,000,000-byte limit. The selected existing clip must retain at least 300 seconds across its EDL segments, which selects the deployed app's native single-file streaming branch. The app imports the original saved JSON, relinks exact source bytes with their recorded name/mtime, and performs its ordinary Export action. Native `showSaveFilePicker`, `FileSystemFileHandle` and `createWritable` remain untouched.

The X11 helper observes a new Chrome save dialog, verifies its relationship to the existing Chrome window, captures private technical evidence, focuses that window, and enters a new owned pathname using ordinary keyboard input. It refuses an unrelated/ambiguous dialog or an existing output file. A closed dialog alone is insufficient: the runner also requires the app's direct-to-disk completion status, unchanged native API, no MP4 download event, a finalized file, matching EDL duration/frame count, and full video/audio decode.

Every `run.json` and `result.json` is marked:

```json
{
  "auditKind": "native_export_probe",
  "supplementary": true,
  "corpusCountIncrement": 0
}
```

Actual MP4 title/visual/audio/semantic quality still requires viewing/listening and comparison with the authenticated original. Project titles are provenance. Automated decode and timing checks do not issue a quality verdict.

## Publication boundary

The only public preparation files are `.github/workflows/examclips-native-stream.yml` and this `tools/examclips-native` directory, excluding local `node_modules`, caches and test output. `evidence-recipient.pub.pem` is a public encryption key. There are no real credentials, project snapshots, source payloads, private recovery keys or signed download URLs in these files.

After review, the orchestrator can select one or two actual completed cases and enable `run-request.json`. Its exact initial content is deliberately safe:

```json
{
  "version": 1,
  "request_id": "native-stream-prepared-disabled",
  "enabled": false,
  "case_ids": []
}
```

The workflow watches only its own YAML and native request path on `qa/examclips-audit-2026-11-11`. Native handoff commits do not trigger another probe. The existing twenty-case workflow, source request and runner files are not modified. A later selected matrix runs sequentially, at most two projects.

## Encrypted input handoff

Each runner creates a fresh RSA key and publishes its public descriptor under `.audit-native-handoff`, nested by its actual run ID and source case. It waits up to fourteen minutes for `encrypted.json` in the same directory. The descriptor names purpose `native-input` and binds repository, branch, run, attempt and case. The private key stays on that runner and is removed after handoff.

On the orchestrator's machine, create a mode-0600 JSON request with these fields:

| Field | Required value |
|---|---|
| `receipt_path` | Actual receipt from the successful authenticated primary evidence installation. |
| `project_path` | Actual authenticated saved project, preferably the selected clip's `project-before-export.json`. It must be in that case's inventory. |
| `selected_clip_id` | Unique existing clip ID in that exact snapshot, with retained EDL duration ≥300 seconds. Candidate or review-gated clips are rejected. |
| `source_url` | Direct public HTTPS URL expected to reproduce the exact authenticated source bytes. This narrow follow-up does not remux an HLS source. |
| `credentials_file` | Existing mode-0600 real-site login JSON, read locally and encrypted without printing its contents. |
| `state_path` | Optional current orchestrator state file; defaults to `/workspace/shared/examclips-long-audit/state.json`. |

Save the actual runner public descriptor as `public-descriptor.json`, the private request as `private-request.json`, and use this command from the prepared native tools directory:

```bash
node make-handoff.mjs public-descriptor.json private-request.json encrypted.json
```

The builder checks authenticated receipt context, every selected project/source metadata hash, the original's exact SHA-256 and byte count, and the stable original app build. It reads `primary_case_runs` from current `state.json` before and after potentially long source hashing. A superseded run cannot be selected just because an old mapping was assumed. It binds the current state hash, selected run/attempt/case, receipt hash, project hash and primary artifact IDs into the encrypted provenance. Only that selected assignment is included, not the full orchestrator state.

The builder preserves the exact project JSON bytes. It gzip-compresses the bounded payload and encrypts both project and login using the existing AES-256-GCM/RSA-OAEP-SHA256 format. Envelopes are limited to 850,000 bytes so the repository Contents handoff remains bounded. The command creates its output exclusively and never overwrites an existing envelope. Publish only `encrypted.json` at the actual descriptor's handoff directory; do not publish the private request or plaintext input.

The receiver validates context and authentication before writing separate private login and project-input files. It emits only run/case identifiers. These inputs are outside evidence and are cleaned at job end. The credential file is also removed immediately after the login attempt.

## Source and project restoration

The runner downloads the full direct source over HTTPS and requires the original SHA-256 and byte count. It probes both video/audio tracks and full duration. A remux or a changed public file fails, even if it looks similar.

The app's relink predicate compares filename, size and `lastModified`, so the runner stages a separate copy under `project.source.name`. It restores the original millisecond timestamp using an integer-nanosecond filesystem operation; epoch-sized floating-point timestamp rounding is avoided. The browser's actual `File` name, size and lastModified are checked after the ordinary file control consumes that real path. No existing authenticated source path or hardlink is modified.

The project is loaded through the app's `project-file` input and the source through its `video-file` input. No app project state is injected. The restored saved snapshot must retain the selected title/EDL/render settings, transcript and source identity. The script never clicks ASR, topic recalculation, review approval or payment controls. Legitimate background camera work can occur under the unchanged app; a changed selected project is reported as a mismatch rather than silently accepted.

The exact app commit must match the primary run before the native probe, and remain unchanged through export. A version change is a separate observation, not an equivalent-storage comparison.

## Runtime and evidence

The prepared workflow uses Ubuntu 24.04's official Chrome, Node 24, pinned Playwright 1.65.0 with lockfile, Xvfb, Openbox, xdotool, X11 utilities and FFmpeg. Playwright 1.65.0 was checked against its publisher's npm registry metadata during preparation; the actual installed/browser/runner versions should be retained with the run. The workflow provisions ordinary missing UI/media packages using Ubuntu's package manager.

The browser has a two-hour bounded probe budget, with a five-second resource/status observer. Source acquisition, handoff and packaging have separate step limits. Low disk/memory, missing native UI, a RAM-path status, an app error, changed input, truncated file or decode failure produces a failed supplementary result. These conditions do not become an app-quality verdict automatically.

Before receiving any real credentials/project, the same future runner performs a genuine native-picker preflight using a synthetic 2.4-second MP4 served on its loopback interface. It calls the real `showSaveFilePicker`/`createWritable`, operates the OS dialog through the same helper, and requires exact saved bytes plus full media decode. That fixture is labeled separately and is neither an ExamClips renderer test nor a corpus lecture. It uses a separate browser profile and origin, so it does not pregrant the app permission. A failed preflight prevents the real handoff/login.

The encrypted evidence includes the native MP4, input and pre/post-export project provenance, source hashes/metadata, final media facts, progress/resource snapshots and private technical UI evidence. The complete source is referenced in its already authenticated primary archive rather than copied into the native artifact again. Choose an existing moderately sized ≥300-second clip for the first check; this confirms the storage branch but is not a multi-gigabyte stress test. Packaging refuses insufficient disk rather than silently omitting the actual MP4.

**`technical-ui/` is private technical evidence. Do not place its browser/dialog/account images into final Library deliverables.** Public-safe report visuals should be native decoded MP4 frames paired with the verified original; actual title statements must come from those frames. No authentication/payment screen is intentionally captured by the browser script.

## Compatible multipart consumption

Evidence retains the same `purpose: evidence` repository/branch/run/attempt/case context, recipient public key, 240 MiB part size and up-to-twenty-part transport as the verified long-artifact consumer. Artifact names use the existing `examclips-long-encrypted` pattern, with the **new native run ID**. Supplementary identity is explicit in authenticated run/result contents.

Consume a completed native case into its own root, outside the twenty-case watcher:

```bash
python /workspace/shared/examclips-long-audit/consume_long_artifacts.py native-artifact-request.json --output-root /workspace/shared/examclips-long-audit/native-followup/runs --reserve-gib 8
```

`native-artifact-request.json` uses the already documented private multipart request schema and the actual native artifacts' signed tool responses. It is created only after those artifacts exist. The existing consumer authenticates the envelope and every inventory hash. The native packager additionally requires each `saved_native` result to match its actual MP4 size and SHA-256 before encryption. The parent must inspect those media facts rather than treating the primary helper's historical `downloaded` counter as a native export count. Do not install native receipts in the primary `runs` directory or include them in the twenty-lecture aggregation.

## Local checks and remaining boundary

Run the complete native helper suite with:

```bash
npm --prefix /workspace/scratch/fbf4561cfc7e/ci_native/tools/examclips-native test
```

The suite includes real RSA/AES-GCM transport, wrong-context/tamper/expansion limits, exact source byte/mtime preservation, current assignment validation, project/EDL restoration guards, wrong-storage-path rejection, safe native-window selection, actual tiny MP4 full decoding/truncation, disabled matrix selection and encrypted package round-trip/secret exclusion. A second real MP4 fixture has 38 frames across EDL-like nonuniform timestamps, including a 1 ms transition. Decoder output explicitly uses passthrough with the demux time base, avoiding null-output CFR retiming. Workflow YAML and embedded Python are separately parsed during preparation.

The local executor denied creation of Unix-domain sockets, so its attempted Xvfb fixture could not start; this was a platform capability restriction before any browser/picker or app contact. The actual genuine UI preflight therefore remains a required gate on the later authorized Ubuntu runner. Do not describe local parser/media/crypto tests as a successful native save-picker execution.

These checks do not replace the later real app import and native export of the selected completed lecture project. No real source case, login or project handoff is included in the prepared branch contents.
