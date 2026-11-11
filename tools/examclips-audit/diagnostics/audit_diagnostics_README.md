# Offline ExamClips export evidence

`audit_diagnostics.py` inspects the actual exported MP4 files in one case directory. It reads `result.json`, prefers `project-final.json` over `project.json` when choosing a saved camera track, and retains differences between saved edit lists. It does not change any input file or application code.

The schema was checked against application commit `5f14760735796fc58e330b3819944da1ab1865a3`. The helper was rebuilt after the executor reset. Its current validation is recorded in `audit_diagnostics_validation.json`; previous-executor results must not be mistaken for this reconstruction's results.

## Invocation

Display the complete command interface:

```bash
python /workspace/shared/examclips-audit/audit_diagnostics.py --help
```

The first positional argument is an actual case directory containing `clip-001.mp4` and any further exports. `--source` accepts the complete local original. If that argument is omitted, `original-source.mp4` inside the case directory is used when present. `--audio-check` adds bounded audio comparisons, and `--interval` accepts a uniform frame-sampling interval from 10 to 15 seconds (default 12.5).

This reproducible command exercises the already-created technical fixture, not the production site:

```bash
python /workspace/shared/examclips-audit/audit_diagnostics.py /workspace/shared/examclips-audit/helper_validation_fixture --audio-check
```

## Evidence produced

- `diagnostics/diagnostics.json`: case summary, original-file hash and metadata, missing claimed downloads, unexported rows, and links to each clip's evidence.
- `diagnostics/clip-001/diagnostics.json`: streams, duration, exact EDL, input bindings, full-decode result, camera measurements, every requested/actual sampled timestamp, source-frame matches, contact-sheet index, and optional audio evidence.
- `diagnostics/clip-001/frames/full-decode.log`: the complete FFmpeg decode log. Every video and audio stream is decoded to null. JPEG sampling is a separate output from the same full pass.
- `diagnostics/clip-001/frames/scene-frame-scores.jsonl`: raw difference and scene metrics for every decoded output frame, with exact PTS and timeline position. These are screening measurements, not quality scores.
- `diagnostics/clip-001/contact-sheet-001.jpg` and further pages: actual decoded output frames paired with selected original frames. Labels show the output timestamp, the EDL source target, and the actual source-frame timestamp.
- `diagnostics/source-frames/`: cached original JPEGs and their actual source PTS records.
- `diagnostics/clip-001/audio/`: optional early/middle/late exported audio and original search-window WAVs. Short or repeated windows can yield fewer than three distinct comparisons; each retained window is recorded.

Paths inside each clip's report are relative to that clip's diagnostics directory. Paths in the case summary are relative to `diagnostics/`.

Sampled export and original JPEGs preserve their native decoded pixel dimensions for text-legibility review. The contact sheets use smaller display thumbnails; judge fine text from the individual JPEGs.

## Exact time mapping

EDL pieces are retained in their saved order, including repetitions and backwards jumps. A piece occupies a half-open output interval. At an exact cut timestamp the next piece applies. Output time maps to `source_start + output_time - output_start`. Rational numbers preserve the original decimal JSON values and FFprobe time bases; fields ending in `_exact` are fractions or integers encoded as strings.

Frame sampling uses integer PTS thresholds. A balanced expression tree avoids FFmpeg parser-depth limits for hundreds of sample requests. Requested and actual decoded timestamps are separate fields, so a request between frames cannot be mistaken for an exact sampled frame. The file-format clock origin and stream time base are also retained. Source comparisons select the first frame at or after the mapped target; they do not claim to reproduce the browser's source-frame selection exactly.

Every EDL boundary receives before/at/after probes. All saved instantaneous camera keys and text/presenter interval boundaries inside the EDL receive probes. Smooth-movement events are optional and capped at 64 by evenly spaced event selection; all raw events and the omitted count remain in JSON. Uniform samples continue across the entire exported clip regardless of that optional cap.

## Camera interpretation

Camera schemas 2–9 are supported. Text-protection intervals take precedence. Positive-duration keys interpolate centers and geometric rectangle size; `pan` uses linear time and other motion labels use the saved cubic easing rule. Zero-duration keys are instantaneous regardless of their motion label. Raw center and inverse-size deltas are measurements, not confirmed visual defects.

The app can compute a per-clip camera during export without saving it as the lecture camera. Therefore the helper deliberately sets `confirmed_renderer_track` to false for the saved track. Compositor fit modes can also change the visible result. Contact sheets and actual video review are needed to judge cropping, readability and movement.

## Actual-output transition screening

An extra branch of the same full-decode pass scales the actual export to 160 pixels wide, converts it to grayscale, and records FFmpeg `scdet` mean absolute frame difference and scene score on every frame. The original-resolution JPEG branch is separate. This does not require a second full decode.

`scene_screening.candidates` ranks nonzero local peaks from either metric, separated by at least 0.5 seconds, up to 64 candidates per clip. Each includes actual output PTS and, when the EDL is available, a mapped original-source time. The complete frame measurements remain in JSONL, including events not selected for ranking. FFmpeg's default scene marker threshold is retained as raw metadata; it is not a defect threshold and does not control the peak-based candidate list.

Source cuts, slide changes, captions, speaker movement, crop movement and compression can all change these metrics. Review short frame sequences around the actual event and compare the mapped original before attributing a transition to the app. A nonzero or large score alone never establishes camera jitter or bad motion.

## Audio interpretation

The optional comparison extracts mono 16 kHz windows wholly inside individual EDL pieces and searches roughly one second around the expected original-source position using normalized FFT cross-correlation. It records the best offset, signed correlation, alternative peak, nominal correlation, sample counts and RMS values. A positive offset means that the exported waveform matches a later source position than the EDL predicts.

Silent or constant windows are inconclusive. Weak or repetitive speech, music, and processing differences can make a numerical peak ambiguous. There is no universal pass threshold and no automatic audio/video synchronization verdict. This procedure is not full-video listening or speech recognition.

## Validation and exit status

Sixteen focused checks cover EDL order, repeated intervals, decimal cut boundaries, camera interpolation and overrides, rejected camera versions, cross-correlation offset sign, silence, the exact 0.8-second frame regression, actual-output transition screening, 212/600-request plans, and initialization-failure classification. A synthetic cut at exactly 0.6 seconds is detected from all twelve input frames even when only one JPEG is requested. The full CLI was additionally run with paired synthetic media and bounded audio comparisons. A truncated MP4 still reported a duration in FFprobe but failed full decoding and caused exit status 1.

The first real EN07 export exposed a parser-depth limit in the initial flat selection expression. That attempt failed before any decoding and is retained as a helper issue. After the balanced-tree fix, the same real export completed full decoding with 212 sample requests and 6,820 per-frame screening records. That is technical verification of the diagnostic on a real export, not a visual-quality verdict.

Exit status 0 means the requested diagnostic completed without a detected decode/input-binding failure; it is not a quality score. Exit status 1 reports a failed export decode, a diagnostic error, or an export claimed as downloaded whose file is missing. Exit status 2 indicates invalid invocation or case/source input. A case with no actual export files receives an explicit `no_actual_export_files` report. Filter-initialization failures, timeouts and terminated diagnostic processes have `full_decode.ok` set to null with an explicit status; they do not establish media corruption. Completed failed decodes have `ok: false` and retain their logs for interpretation.

No actual ExamClips export was used in the helper's technical fixtures. Production observations must cite the separate real-case evidence.
