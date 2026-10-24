> Исторический документ: описывает состояние на дату написания. Текущие инструкции — в [индексе документации](../../README.md).

# Hybrid Reconstruction Implementation Plan
> For agentic workers: REQUIRED SUB-SKILL: Use superpowers:executing-plans or superpowers:subagent-driven-development with per-task tests.

**Goal:** Produce TikTok-style vertical educational composition from component source crops, speaker and OCR-informed timed attention.

**Architecture:** Add pure scene-model, optional Tesseract.js OCR on representative local video frame, integrate canvas scene director in existing local editor, export with existing media encoder, test in Chrome CI.

**Tech Stack:** Vite 8, Mediabunny, WebCodecs, Tesseract.js 6, Node 22, Playwright core.

**Spec:** docs/superpowers/specs/2026-10-15-examclips-hybrid-reconstruction-design.md

## Global constraints
- Never upload lecture video to GitHub or AI APIs.
- Do not invent formula content when OCR uncertain: retain original pixel crop.
- Webcam region initially preset: user must be able to adjust later; no claim of accurate auto face detection.
- No GPU model downloads to user's Windows PC; this implementation uses GitHub VM.
- Keep previous fit/crop functionality as optional fallback.

## Review focus
1. OCR absent or Tesseract model offline: source-based panels still playable.
2. Screenshot with two columns: no full landscape letterboxing in hybrid.
3. Source dimensions 1600×900, scene coordinates remain in bounds.
4. Semantic match unavailable: temporal fallback rotates active visual blocks.
5. H264 browser export with sound: no corrupt clip or timestamp drift.

## Tasks
### 1. Scene contracts, source-safe regions and director
- [x] Build `src/scene-model.js` geometry, OCR flattening, transcript keyword match, ordered beats.
- [x] Build tests `tests/scene-model.test.mjs` including missing-OCR fallback.

### 2. Scene extraction
- [x] Add `src/scene-analysis.js` with optional local Tesseract.js and lazy language download.
- [x] Detect coarse slide transitions by frame difference and produce per-slide OCR chapters.\n- [ ] Improve temporal localization and understand vector diagrams after independent accuracy evaluation.

### 3. Vertical compositor
- [x] Replace default horizontal fit composition with per-beat original-pixel crop recomposition.
- [x] Add independent webcam pixel layer, safe subtitle handling and source title crop.
- [x] Add basic camera corner presets and hide control.\n- [ ] Add drag-to-select freeform camera region and richer layout solver.

### 4. Integrate browser editor and export
- [x] Per-clip `scene` schema, selector for hybrid, Analyze Board action.
- [x] Update real-time preview and export to invoke shared compositor with elapsed time.
- [ ] Full Docker lecture OCR/transcript acceptance; only synthetic Chrome smoke before then.

### 5. Quality validation and future iterations
- [ ] Compare cropping/preservation with expert-reviewed slide-region scores.
- [ ] Face segmenter and motion track on-device; detect transition frames; vector reconstruct only verified elements.
- [ ] Stable 1080p/30fps benchmark and persistent browser caching.
