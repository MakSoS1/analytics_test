# ExamClips v0.7 — fullscreen timeline as primary app (2026-10-16)

## User-approved design direction
"Нет, таймлайн должен быть на весь экран и это должна быть основа сайта вообще после загрузки видео, а остальные штуки это просто отдельные вкладки. На таймлайне не должно быть загрузить кнопки и выбор там минута или 15 сек, это должно быть сразу на первом экране с загрузкой."

This supersedes the former v0.6 layout which displayed source timeline underneath a persistent sidebar and editing controls.

## Information architecture
**Page 1: Upload / setup**, one centered flow:
- Private video picker (MP4, MOV, WebM).
- Duration preset: 1–3 min (up to 5), 1–2 min, or short 15–45 sec.
- Local speech-recognition language, Tiny/Base model, optional 5/15 min sample.
- Primary action: Process lecture. Secondary: import local SRT.
- Media never uploaded to server; public model assets downloaded on initial use.

**Page 2: Measured progress**:
- Preparation → transcription → boundaries → composition.
- Actual progress only when measured, otherwise indeterminate.
- Cancel and resume existing ASR checkpoint.

**Page 3: Editor, default TIMELINE tab (full width)**:
- No file-upload button, no duration choice and no repeated sidebar.
- Workbench spans available browser width.
- Two video monitors: original 16:9 and composed 9:16.
- Large single synchronized source ruler, locally decoded filmstrip and color-coded clips: blue kept, gray discarded. Scrub source, select clips, drag trim handles, reclaim skipped intervals, confirm re-segmentation, recompose selected scene.
- Existing approved status invalidates on boundary changes, along with stale scene and LLM evidence.

**Separate tabs**:
- Montage: source-grounded scene/board OCR options, presenter placement, per-clip review and start/end.
- Subtitles: text and SRT export. Floating timed TikTok-style captions are applied to MP4 rendering as before.
- Tests: local transcript-term recognition quiz and JSON.
- Export: H264/AAC single/batch MP4 quality, project JSON import/export.
- Tabs live in top navigation and are actually mutually exclusive DOM panes, not anchor scroll targets. Existing DOM nodes moved instead of duplicated.

## Browser compatibility and privacy
- Browser-only hosting: existing media decoder, optional WASM/WebGPU Whisper and Tesseract.js, WebCodecs exports supported by desktop Chromium.
- Preview and export use same canvas compositor; enlarged live lecturer and progressive word captions.
- Local Py/PP-OCR and Ollama are optional installed desktop integrations, not available through remote static GitHub Pages.
- A model network download at first use is not the same as uploading video; nevertheless verify network policy if source is confidential.
- Strictly offline first-use packaging is not provided.

## Acceptance
- Initial file and duration controls visible on landing page, processing action disabled until a valid file is supplied.
- File loaded: same upload setup page remains; duration is chosen before processing.
- SRT/ASR completed: default tab is `timeline`, with source video and 9:16 preview on top and used/skipped track across >=84% viewport width; duration/file upload controls are not visible.
- Manual clip trim creates a real gray gap and correctly recomputes source coverage.
- Other editor tools are visible only under their tab; tests verify navigation and exports.
- CI independently validates H264+AAC standard/full-HD, live moving lecturer, karaoke caption pixel differences, local OCR fallback, local batch download and mobile viewport.
- Real multi-hour pedagogical segmentation still needs on-device user trial and human evaluation; unit/browser success does not establish video content quality.

## Repo
Branch `feat/examclips-timeline-primary-20261016` on top of `feat/examclips-workflow-timeline-captions-20261016`. GitHub Pages static bundle updates to compiled `gh-pages` branch. The owner must first enable GitHub Pages in repository Settings for a public URL; creating assets alone does not activate it.
