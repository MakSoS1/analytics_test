# Review evidence for the current-build rerun

`retest-review.py` reads actual `clip-*.mp4` files, the UI-exported projects, `result.json`, and `original-source.mp4`. It does not modify those inputs or interpret any saved camera-track schema.

The default Actions invocation is `python3 tools/examclips-audit/retest-review.py --deadline-seconds 1980`. `AUDIT_OUT` selects the evidence directory and `AUDIT_CASE_ID` selects its case subdirectory. For local use, pass `--evidence` and `--case` explicitly. `--targets` selects the combined regression manifest; its default is `tools/examclips-audit/regression-targets.json`.

The target manifest has a `cases` array. Each case has `id`, `visual_points` (`id`, `source_seconds`, `reason`) and `semantic_ranges` (`id`, `start`, `end`, `reason`). A case without targets still receives full decode, uniform samples and cut/scene samples; its summary says `target_case_present: false`.

## Exact provenance

- Prefer the unique recorded clip ID in `clip-NNN-project-before-export.json`.
- Fall back to the recorded result EDL, then project snapshots by unique clip ID. Never bind to an arbitrary project-array position.
- Keep reordered and repeated source spans. Record alternative EDLs and whether they disagree.
- Map the **actual decoded output timestamp** through the selected EDL before requesting its source comparison.
- Record integer PTS, time base, normalized time, source SHA256 and clip SHA256.
- An original regression point absent from an EDL is `absent_from_edl`; no unrelated frame is substituted.

## Decode and bounded samples

Each actual MP4 gets one full video/audio decode through the existing diagnostic `decode_and_sample` helper. Samples include first, middle, last, every60seconds, each mapped regression target and its ±0.07second neighborhood, and up to30 evenly distributed EDL cuts with the same neighborhood. The output request ceiling is512; any omitted request is explicit.

The same full-decode pass computes scene-screening scores. For the first three ranked peaks, the utility retrieves the previous/current/next actual decoded output PTS and captures those frames with short seeks. These are additional bounded video seeks, not additional full audio/video decode passes.

At most50 distinct mapped source times per clip are requested. Priority is regression targets, first/middle/last, scene peaks, EDL cuts, then uniform samples. Each omitted sample records the source-pair cap. The source-frame helper retains its actual timestamp and selection method.

Decode completion, warnings and integrity checks remain separate from quality judgments. Semantic-range coverage counts unique retained source seconds and repeated output seconds; `semantic_verdict` is always null. No full-video listening or semantic review is claimed.

## Deadlines and retained evidence

The main process runs each clip in a separate process group and terminates that group at the review deadline. It checkpoints case and clip reports so partial review remains inspectable. With less than15seconds available it records all remaining clips as unreviewed without hashing or probing the original. `AUDIT_JOB_STARTED_UNIX`, when present, further limits the review to leave15minutes before the six-hour job ceiling for encryption and uploads.

The review step is limited to35minutes and has `continue-on-error: true`. The original full-evidence packaging step remains `if: always()`. Its whitelist additionally accepts JPEG frames, decode logs and FFmpeg filter scripts inside authenticated encrypted evidence.

`package-review.mjs` creates a compressed ZIP of metadata, projects, transcripts, sampled frames and logs. It excludes **all MP4s**, `scene-frame-scores.jsonl` and `scene-metadata.log`. The raw media and full scene dumps remain in the existing full encrypted artifact.

Only `review.enc` and `review-encryption.json` are uploaded in the separate compact artifact. They use the same recipient public key as the full artifact, with an authenticated `artifactKind: compact-review` context. The plaintext ZIP and temporary file list are deleted. Authentication-like filenames, unexpected extensions and symlinks are rejected before packaging.

## Validation

The review path requires Python's standard library and the external FFmpeg/FFprobe executables. NumPy is imported only by the older optional waveform helpers, and Pillow only by the older contact-sheet helper; this utility calls neither. No pip installation is needed. The workflow prepares and verifies the media executables before running the Python tests, asserts both are on PATH, and runs tests with `python3 -S` so third-party site packages cannot silently satisfy a dependency. This validation step has a five-minute timeout and completes before the encrypted login handoff.

The included tests exercise exact pre-export binding despite reordered final projects; repeated source spans; missing targets; unique semantic-range coverage; explicit cut caps; actual full decoding and PTS-paired source frames from a real synthetic MP4; compact encryption/decryption; media/large-scene-dump exclusion; and refusal to archive credentials.

The complete local harness checks passed:12Node tests and12Python tests. The zero-deadline regression passes with PATH empty, proving that no media executable is required to record its omissions. A separate CLI integration also confirmed that a zero review deadline records the limitation while the full encrypted package can still be produced in a fresh run artifact directory.
