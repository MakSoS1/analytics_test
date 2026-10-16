# ExamClips MVP acceptance audit — 2026-10-16

Basis: the 9-page presentation "examclips(1).pdf" provided in conversation. In particular, page 1 mock dashboard, page 3 5-step scenario, page 4 emphasis on preserving board, formula, code, graph and diagram; pages 1/3/5 analytics and test/LMS claims.

## Interface design
Inspired by the pitch's crisp white + strong blue vocabulary, compact navigation, rounded lightweight cards and 5-step processing schematic, but implemented as a new original responsive frontend rather than reusing inaccessible screenshot pixels.
Sections: local file picker, 4-step journey, reviewable clips, actual local per-project metrics, vertical preview and editing, contextual OCR and source-preserving slides, transcript and quiz. Hide less-used controls in disclosed expandable sections, accessible native inputs and aria status.

## Feature matrix: MUST NOT imply unavailable features exist

| Presentation feature | Working MVP status | Verified / limits |
| --- | --- | --- |
| Choose upload/video source (P1/P3) | **Implemented locally** | File picker/drag and drop; original file stays on visitor's device. No cloud storage/auth |
| 20–30 minute total processing (P1/P3/P4) | **NOT validated target** | Depends on lecture, hardware, decoding, model and network downloads. Don't show an ETA without benchmark |
| Speech to timed transcript (P3/P8) | **Implemented, optional** | Whisper Tiny/Base in browser WebGPU/WASM, resumable IndexedDB 30s; SRT import/edits/export. Word-level accuracy not guaranteed |
| Semantic fragmenting / keywords (P3/P4) | **Heuristic implemented** | 60–300s chunk candidates from pauses, punctuation, topic cues and optional slide changes; an optional localhost-only Ollama can suggest edits; review needed |
| 20–40 1–3min clips (P3) | **Variable output, not quota** | Actual count depends on content duration and detected topic segmentation. Can be up to 5 minutes |
| Automatic vertical 9:16 with board/formula/code/screens (P1/P3/P4) | **Implemented for reviewable source-faithful crops** | Client Canvas compositor; OCR Tesseract.js browser; on installed localhost Python optional RapidOCR. Preserves original graphics, not guaranteed semantically correct redrawing |
| Moving lecturer and original sound (P1/P3) | **Implemented** | Browser Chrome CI checks MP4 frame motion and AAC audio. Needs real-world QA per recording |
| Export H264/AAC | **Implemented** | 720×1280/15 or 1080×1920/30, both demonstrated by deterministic Chrome fixture in CI |
| Clip review and local draft / approval | **Implemented** | Boundary/context playback, user approval; edits reset approval; _DRAFT names for unverified clips |
| Mini-tests "per fragment" (P1/P3/P5) | **MVP extractive only** | Generates up to 5 questions from exact local transcript terms, with distractors and browser grading; exports quiz JSON. These test vocabulary recall, NOT conceptual understanding or educational validity |
| Analytics: number of topics, total minutes, reviewed (P1/P3) | **Implemented on project** | Actual local calculations; no invented viewer counts |
| Analytics: views, retention, average watch and test pass after publishing (P1/P3) | **NOT implemented** | Requires distribution-channel tracking and privacy model; slide dashboards are product vision, not actual MVP |
| Projects/library/uploads (P1/P3) | **Partial** | Project JSON import/export; no server account/project storage or multi-tenant library |
| LMS export/API (P5/P8) | **NOT implemented** | External platform contracts/auth and server integration are outside browser-only MVP |
| Online user accounts, team, SaaS billing (P5/P7) | **NOT implemented** | Purely local editor has no auth, payments or subscription |
| Public web preview without uploads | **Static deployment ready** | GitHub Pages workflow; model assets downloaded on first use, local-only Ollama/PP-OCR buttons unavailable on hosted static origin. Site activation depends on GitHub Pages setting |
| Strictly offline first launch | **NOT implemented** | Public model weights, npm packages or static bundle must be obtained at least once; thereafter processing can remain local if cached |

## Browser privacy claims

- The static GitHub Pages host serves JS/CSS. Original video and microphone PCM are read via browser APIs; the editor does not upload them to application servers.
- Browser OCR uses WASM; on a hosted static site the RapidOCR and Ollama localhost bridge are absent/disabled explicitly.
- Private model/transcript cache stored in browser IndexedDB; user can clear saved ASR checkpoint.
- Third-party model CDNs serve public weights on initial use. Can't promise no outgoing traffic or no IP disclosure; original video is not sent.
- For a sensitive lecture prefer a downloaded localhost build, inspect traffic and ensure WebGPU/WASM dependencies were cached.
- On mobile older devices, hour-long video can exceed memory or no WebCodecs encoder support. Chrome desktop is validated, other browsers/device budgets need acceptance testing.

## What "MVP completed" means here
A **local-first demonstrable editor** covering source video → (Whisper or SRT) transcript → microtopic proposals → visual OCR-aware 9:16 editor → review → MP4 and vocabulary quiz JSON, without backend video uploads. This is not the entire SaaS product shown in the accelerator presentation.

## Integration acceptance
- npm test checks lecture segmentation, quiz correctness, source-faithful scene parsing, OCR and security helpers.
- A genuine Chromium browser test opens synthetic source video and SRT, uses real DOM for journey/quiz, verifies five questions can be answered and downloaded, checks 390px phone layout for horizontal overflow and saves screenshots.
- Other tests assert H.264/AAC exported video, 1080p, moving lecturer, local-folder batch export, and OCR WASM fallback.
- No claims about performance or AI semantic generalization from synthetic tests.

## Next research milestones after MVP
1. Per-lecturer holdout corpus with annotated real clips, educational completion score, OCR CER/WER on Russian formulas and diagrams.
2. Conceptual multiple-choice tests using local LLM with citation/evidence verifier rather than cloze-only questions.
3. LMS/API integrations, auth, hosted analytics consent and privacy controls after deciding business scope.
4. Performance tests over 60/180 minutes on Windows RTX 5060 Ti and ordinary user laptops.
