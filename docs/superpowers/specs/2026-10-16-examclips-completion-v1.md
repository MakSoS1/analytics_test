# ExamClips v0.4 — local-first micro-lessons: system specification
Date: 2026-10-16. Branch: feat/examclips-completion-20261016 (stacked on draft PR #61).

## 1. User outcome and privacy
Given an authorized 16:9 university lecture, propose individually understandable 9:16 learning clips of typically 60–180 seconds, with configurable maximum 300 seconds. Preserve *real live* lecturer footage and original source audio. Use readable on-device re-layout of the source board, preserving original diagram pixels and only reflowing verified OCR text. Do not send lecture media, stills, transcripts or annotations to cloud inference.

## 2. Process architecture
1. Read user-selected MP4/MOV/WebM using browser BlobSource and local decode. Source content is never uploaded.
2. ASR via `@huggingface/transformers` Whisper Tiny (default) or Base (optional): 30-second decoded mono PCM windows, on-device WebGPU where available, fallback to WASM; only model weights are downloaded on first use.
3. Persist processed 30-second windows and transcript to per-video, per-language, per-model IndexedDB checkpoint. Fingerprint only the first/last 64 KiB of the local file via SHA-256, never upload it. Resume from skipped windows after interruption; provide explicit cache deletion and JSON/SRT export.
4. Optional *whole-lecture* visual scan samples thumbnail frames every ~8 seconds and finds candidate slide boundaries; these are weak priors, not definitive topic splits. The actual educational visual objects are recovered from high-confidence OCR and source pixels.
5. Global microtopic segmentation (dynamic programming) prioritizes actual ASR boundaries, pauses, finished sentences, discourse transitions, lexical change and optional nearby slide change. No fixed 15-second slicing. Clip candidates stay marked `needs-review`.
6. Optional locally installed Ollama/Qwen review: browser UI talks to same-origin Vite loopback server, which forwards **only one selected microtopic transcript and 75-second textual context** to 127.0.0.1:11434. No video, audio or images are forwarded. No models installed by this feature. The model returns a literal-evidence-supported, nonbinding judgement of intro/explanation/conclusion; deltas are bounded to ±45 seconds and require explicit confirmation. Fake quotes invalidate approval.
7. User reviews each candidate, listens to preceding speech, adjusts start/end and marks intro/explanation/result checked. Any later change clears approval. Unreviewed MP4 uses suffix `_DRAFT`.
8. Per-clip scene compositor uses offscreen/HTML Canvas, actual source diagrams, reflowable OCR text, motion-estimated webcam/adjustable presets, frame-deterministic transitions and captions. Export H.264/AAC with browser WebCodecs+Mediabunny, WASM AAC fallback.
9. Video sizes: quick 720×1280 at 15 FPS or high-quality 1080×1920 at 30 FPS; the high-quality path must be benchmarked on user hardware before promising real-time performance.
10. Batch export: directory picker creates each MP4 sequentially, with original audio, directly into a user-selected folder. Do not accumulate 20+ MP4 blobs in memory. If unsupported, single-clip export still works.

## 3. Browser/data contracts
- Local project JSON schema=1 includes source filename/duration, `chunks`, `clips`, `sceneCuts`, per-clip `scene`, `status`, `approvedAt`, optional `llmReview`. Source videos remain separate.
- `clip.status` = `needs-review` by default; `approved` only after explicit user's review. `llmReview` is never authoritative.
- Model response contract: verdict=complete|needs-context|unfinished|uncertain, confidence [0,1], literal evidence quotes checked against actual text, bounded start/end deltas. Invalid evidence yields uncertain.
- All storage is user-local. Note that a mutable remotely served web application is not a cryptographic privacy guarantee; use the localhost production build when strict privacy is required.

## 4. Security
Vite frontend and its optional production-preview bridge bind to 127.0.0.1 by default. Bridge rejects non-loopback connections, cross-origin requests and excessive JSON, and only connects to Ollama at local loopback. Nothing here installs models or runs arbitrary user-supplied commands. The native app is optional; no cloud rendering infrastructure exists.

## 5. Verification already automated
- JS unit tests for source timestamp clips, 1–5min cut proposals, OCR geometry, slide changes, typography, captions, poster layout, webcam motion, literal-evidence verifier, resumable ASR checkpoint and human-reference F1 metrics.
- Headless Chrome fixture SRT→H.264/AAC MP4 including full decode in FFmpeg and 1080×1920/30 fps.
- Chrome fixture with static teaching board + moving lecturer confirms non-frozen lecturer **in output MP4**.
- Browser OCR smoke with synthetic two-column Docker slide, Whisper Tiny/Whisper Base model download+WASM test.
- Browser IndexedDB save/restore/delete checkpoint smoke and local-only mocked Ollama bridge smoke.
- Chrome multiple-clip local directory batch export and visual screenshot quality gates.
- No private real lecture uploaded into public Actions.

## 6. Honest acceptance gaps
The actual uploaded 59m50s Docker MP4 is available in the private ChatGPT file runtime but was **not found on Windows self-hosted runner** (checked selected folders). No ASR model weights are present in the isolated file runtime, which has no external network access. Therefore full real ASR, human/reference boundary review and full 1–5min pedagogical scoring **cannot be certified in this environment**. A 120-second source-faithful video with actual audio and moving lecturer was locally exported and fully decoded; it is an **unverified topic preview**, not a completed AI-certified micro-lesson. Human-annotated multi-lecturer labels are not available; training/distilling a specialized complete-lesson classifier would produce unsubstantiated metrics until such labels are collected. Optional existing local Qwen reviewer is the practical no-new-download path.

## 7. Release acceptance (requires real recordings)
- Transcribe full 60min local user copy with checkpoint recovery, record walltime and peak memory.
- Score proposed boundaries against human-marked start/end (±10 sec F1) on lecturer-disjoint validation sets.
- Manually grade self-containedness of at least 30 clips; report false cuts and missing context.
- Verify titles, diagrams and formulas on a frame sample from each exported clip.
- Check sound sync, lecturer motion and MP4 decode of 1–5min high-res output.
- Offline network trace: no outbound upload containing video, PCM, OCR or transcript.

Until these steps, describe output as reviewable MVP, not automatically guaranteed quality.
