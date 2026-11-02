> Исторический документ: описывает состояние на дату написания. Текущие инструкции — в [индексе документации](../../README.md).

# ExamClips Local MVP Implementation Plan
> For agentic workers: REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Browser-only end-to-end lecture → locally editable vertical MP4 clips, with optional local Whisper transcription.

**Architecture:** Vite, pure modules with explicit source/ASR/segmentation/composition/export boundaries; streaming media APIs; no backend for files. CI on ubuntu-latest, no self-host runner changes.

**Tech Stack:** Node 22; Vite 8; mediabunny 1.61.4; @huggingface/transformers 4.3.1; Canvas/WebCodecs.

**Spec:** docs/superpowers/specs/2026-10-15-examclips-browser-mvp-design.md

## Global constraints
- Never upload the user's input lecture to GitHub or remote ML.
- Keep original `analytics_test` files unchanged; commit only `examclips-local/`, its docs and its CI file.
- Default conservative layout preserves all source pixels.
- Clearly disclose downloads and browser codec incompatibility; never synthesize transcripts or quality scores.
- Model inference works with bounded audio chunks (<=30 s).

## Review focus
1. File with no audio track: manual clip still usable; ASR errors clearly.
2. Captions outside clip and overlapping timestamps: never leak to previous/next.
3. Browser WebCodecs unavailable: error with no empty success artifact.
4. Reopening project with a different-length video: reject imported edits.
5. Export cancelled midway: do not download incomplete result.

## Tasks
### Task 1: Source and UI
**Files:** `examclips-local/index.html`, `src/main.js`, `src/styles.css`, `src/media.js`.
- [x] Build local-only video input, metadata and canvas preview.
- [x] Check input size and handle cleanup of Blob URLs.
- [ ] Manually verify on Chrome/Edge/Firefox with sample file; log failures.

### Task 2: Transcription and semantic baseline
**Files:** `src/asr.js`, `src/segments.js`, `tests/segments.test.mjs`.
- [x] Add lazy on-device Whisper model download and chunk decoding.
- [x] Implement deterministic candidate boundaries and editable SRT.
- [x] Add Node tests for invalid ranges, SRT and coverage.
- [ ] Evaluate a multilingual model and later learned segmentation on annotated lectures.

### Task 3: Media export
**Files:** `src/composition.js`, `src/render.js`.
- [x] Add fit/focus/crop templates with legible subtitles.
- [x] Add AVC/AAC MP4 rendering and audio timeline trimming.
- [ ] Verify browser real-time output file via ffprobe, audio/video sync and playable codecs.
- [ ] Measure performance; choose 1080x1920 and 30fps only after baseline.

### Task 4: Integration validation
**Files:** `.github/workflows/examclips-local-mvp.yml`.
- [x] CI setup on ubuntu-latest for tests and build.
- [ ] Review actual CI logs, fix failing installs/builds.
- [ ] Browser end-to-end smoke with fixture video.
- [ ] Privacy Network audit and device compatibility.

### Task 5: Later research track (separate branch)
- [ ] Prepare legally usable lecture dataset with independent lecturers/courses.
- [ ] Compare pause+slide / E5 / EmbeddingGemma / student model.
- [ ] Train small boundary+quality ranker on available RTX 5060 Ti only if baseline insufficient.
- [ ] Add OCR, slide detection, speaker detection and verified 1080p export.
- [ ] Verify enterprise-offline downloadable app without CDN execution.
