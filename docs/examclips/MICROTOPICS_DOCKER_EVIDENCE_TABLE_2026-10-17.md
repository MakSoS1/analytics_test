# ExamClips — Microtopics catalogue and Docker lecture intro handling
Updated 2026-10-17

## User requirements

- Rename **Монтаж** to **Микротемы** both in header and editor.
- The Microtopics tab is a structured table of every proposed instructional microtopic, with concise source-backed name, original lecture source intervals, full transcript with source timecodes, evidence-based lesson screenplay and per-topic 9:16 video preview.
- Source-aligned transcript is always distinguishable from a newly authored screenplay. Current deterministic screenplay beats are extractive (source quotes and timestamps), not invented AI narration.
- Selecting a table row opens its draft for editing, 9:16 play shows the existing local compositor, and MP4 is encoded only upon export. Never pretend a raw 16:9 source is an exported short.
- Keep all substantive topics, preserve a continuous >20-minute worked example, do not enforce output quotas.
- Introductions (teacher biography, title slide, course agenda, microphone/housekeeping) are not independent instructional topics merely because Docker terminology is mentioned.
- Old autosaved projects retain their original edit state. Provide a clear re-analysis action to use the improved planner; warn before overwriting previously approved edits.

## Real media observed locally — no lecture upload

User-provided `HAHL2026_Lecture01_Docker.mp4` duration 3590.341 seconds, 1600×900, H264/AAC. Sampled original frames show:
- 00:08 opening title Highload High-Availability Systems Lecture 1;
- 00:30–01:00 **About me**, instructor biography;
- ~02:00 **Lecture 1 brief**, course agenda containing technical terms without explaining them;
- ~05:00 **Containers vs. Virtual Machines**, subject-specific explanation;
- ~10:00 **Docker Architecture & Image Model**;
- ~20:00 **Dockerfile: Production-Grade Images**;
- ~30:00 **Container Lifecycle & Health**;
- ~45:00 and ~58:00 **Docker Networking**.

These visual checkpoints verify that the earliest slides are poor clip candidates but do **not** constitute word-aligned ASR or full human segmentation labels. The raw lecture stays private and is never committed to GitHub or uploaded to CI.

## Implementation

- `src/lecture-semantics.js`: separate biographical and agenda language from explanations; propose short topic-specific labels grounded in literal phrases. No unsupported new technical facts.
- `src/complete-topics.js`: retain educational speech, trim administrative segments, and use topical lexical transitions in addition to explicit transitions. Do not split an active worked solution arbitrarily.
- `src/microtopic-catalog.js`: a secure textContent-rendered scrollable table; evidence-only scenario, exact ASR/SRT source timestamps, playable 9:16 output canvas and edit actions.
- `src/main.js`: rename tab, insert table and selected-clip canvas mirror. Add per-row Play/Edit and recalculate action for previously saved projects.
- `tests/lecture-semantics.test.mjs` and `scripts/microtopics-table-smoke.mjs`: cover source-anchored captions, Docker biography/agenda exclusion and source-time evidence.
- Privacy: original media and user transcript remain browser-local. Public web deployment uses the static bundle only. Local Ollama verification is not available in the static GitHub Pages build.

## Remaining quality limitations

- A source frame sampled at 05:00 proves the slide shows a comparison, but cannot prove exactly when pedagogical speech begins. No real-hour word-aligned ASR or human-annotated recall score was produced from the private upload in the CI.
- Topic-specific lexical rules improve Docker headings but cannot guarantee all subtopics in arbitrary English/Russian lectures. Such claims require human-labeled benchmark corpus, high-recall segmentation and validation of every source span.
- Finished MP4 playback is available after local export; the tab deliberately exposes a **real-time 9:16 preview** instead of inventing pre-rendered MP4 files.
