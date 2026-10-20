# ExamClips Atlas Interface Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for integration and delegate independent range, catalog and style tasks. Track verified outcomes in the progress document.

**Goal:** Publish the selected Atlas interface with real ExamClips functionality and readable typography.

**Architecture:** Native DOM/CSS port on the current engine. Keep a single media player and project state; retain IndexedDB and media processing modules. Add bounded transcript-based discovery and replace all prototype-only operations with working application actions.

**Tech Stack:** Existing JavaScript ES modules, Vite, MediaBunny, Transformers.js, Tesseract.js, IndexedDB and Playwright browser tests.

**Spec:** `docs/superpowers/specs/2026-10-20-examclips-atlas-design.md`.

## Global Constraints

- Same origin `/analytics_test/`, database/store names and backward-compatible project schema.
- No demo data, simulated progress, Lovable production dependencies or upload of private media.
- Preserve arbitrary ordered source segments and original absolute timestamps.
- No clip-count quota. AI suggestions and manual approval remain distinct.
- Selected-range discovery does not modify existing clips; content edits invalidate stale review/export state.

## Review Focus

- Existing project without a cached large source must remain recoverable without losing its edits.
- Rapid navigation during autosave or late background OCR must not overwrite another project's data.
- Noncontiguous EDL must remain noncontiguous through JSON, reload, playback and export.
- Empty/partial transcript and repeated range discovery must not create fake clips or duplicate source spans.
- Narrow screens, long Cyrillic titles, hidden controls and light/dark disabled states must remain usable.

### Task 1: Range discovery and project compatibility

**Files:** create `examclips-local/src/atlas-range.js`, `examclips-local/tests/atlas-range.test.mjs`; extend `src/project-library.js` and tests for optional persisted UI/settings.

**Interfaces:** `findRangeTopics(chunks, duration, {start,end,clips,chapters,sceneCuts})` returns draft candidates with absolute source segments; `manualRangeClip(start,end,duration)` returns a validated draft; `coverageSpans(clips,duration)` describes real included ranges/gaps without semantic completeness claims.

- [x] Write and run failing tests for bounds, source offsets, existing approved edits, duplicate spans and empty input.
- [x] Implement pure range operations through the existing planner and screenplay verifier.
- [x] Extend snapshots without changing old storage identity; verify old and extended snapshots.

### Task 2: Atlas catalog and evidence detail

**Files:** `examclips-local/src/microtopic-catalog.js`, `src/atlas-catalog.css`, browser regression assertions.

**Interfaces:** retain `renderMicrotopicCatalog` callbacks and add optional `onAccept`/`onReject`; add optional `onSeek` to `renderMicrotopicDetail`. All values come from real clips/chunks/thumbnails.

- [x] Verify current renderer and preservation risks against the design.
- [x] Port portrait cards, chapter headers, summaries/status and separate candidate group.
- [x] Port evidence panels with working timestamp navigation and complete transcript.
- [x] Verify keyboard accessibility and stable selectors for media regression tests.

### Task 3: Application shell and real interactions

**Files:** create `examclips-local/src/atlas-shell.js`, `src/atlas.css`; modify `src/main.js`, `index.html`; create `scripts/atlas-ui-smoke.mjs`.

**Interfaces:** DOM shell keeps original control IDs/player/canvases and accepts callbacks for navigation, file selection and state refresh. Range actions consume Task 1; card/evidence callbacks consume Task 2.

- [x] Add failing browser acceptance checks for library, import steps, grid, source comparison and preserved edits.
- [x] Mount Atlas library/wizard/progress/results/detail using original engine controls; add persistent theme and brighter secondary text.
- [x] Wire range candidates, manual drafts, keyboard navigation and explicit source/clip playback.
- [x] Preserve source attachment, autosave, SRT/JSON imports, composition, quizzes and exports; clear stale content validations.
- [x] Run browser acceptance, reload, source playback and media export checks; inspect desktop/mobile screenshots.

### Task 4: Review and publish

**Files:** deployment/CI workflow only where needed; migration verification report.

- [x] Run full unit suite and production build with `/analytics_test/` base.
- [x] Run relevant existing persistence/EDL/MP4 tests and the new UI regression.
- [x] Independent final code review; repair material regressions and rerun affected checks.
- [ ] Commit integration, publish through existing GitHub branch workflow with a non-forced update, monitor CI/Pages, and verify live deployed commit and interface.
