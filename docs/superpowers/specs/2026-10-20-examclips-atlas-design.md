# ExamClips Atlas interface migration

## User-approved brief

Replace the public ExamClips interface at `/analytics_test/` with the complete visual and navigation design selected in `MakSoS1/lecture-clip-atlas`, remove Lovable branding/integrations, and brighten small secondary text. Preserve the real media processing, local project library, source-linked lessons, editor and exports described in the supplied ExamClips Full Product Spec version 1.0 (18 October 2026).

## Inspected sources

- Working engine: `feat/examclips-library-zoom-storyboard-20261017`, commit `208d7285513044874af6453baf4fa1f610414e83`.
- Selected design: `lecture-clip-atlas` commit `3665f874111edb860b7b23e4741d6df8ade8889f`.
- The selected design is a three-screen React prototype with in-memory fixtures and simulated playback/search. Its visuals and interactions are the design source; real data and media come from ExamClips.

## Architecture

Port the Atlas visual hierarchy to the existing Vite application using native DOM components. Keep the existing media player, canvases, ASR/OCR/semantic modules, EDL operations and IndexedDB names. This avoids duplicating application state or adding the prototype's server runtime to a static Pages deployment.

The library uses real project cards and thumbnails. A three-step import wizard exposes source, ASR/SRT settings and confirmation. Real operation progress remains visible. Results open as a chapter-grouped portrait card grid with a selectable coverage strip. Clip detail shows the horizontal source next to the real 9:16 canvas, editable title, source timing, evidence, review status and previous/next navigation. Existing caption, quiz, composition and export tools remain directly accessible.

Selected-range topic discovery uses saved transcript cues and the existing planner, preserves absolute timestamps and all existing clips, and adds candidates for explicit acceptance. A manual selection can become a draft with checked bounds. It does not simulate ASR or silently recalculate the entire lecture. Source playback and assembled clip playback are distinct modes.

## Compatibility and scope

- Preserve database `examclips-project-library-v1`, stores `projects` and `sources`, and existing schema 1/2 JSON imports.
- Extend optional snapshot settings and navigation fields safely. Preserve EDL ordering, titles, transcripts, chapters, zoom and offsets on reload.
- No implicit reanalysis on opening an existing project. Warn before explicit global regeneration can replace manual edits. Invalidate approval/evidence/export state when content changes.
- No new maximum topic count, no fixed duration splitting, no claims of complete semantic coverage from time coverage.
- Local source media stays on-device. Do not copy demo lectures or Lovable monitoring into production.
- P2 model research and proof of complete semantic quality on the user's unavailable original audio are outside this UI migration.

## Verification

Run existing unit and media export regressions plus new range, navigation and persistence tests. Exercise import via SRT, real source and portrait playback, title/boundary/EDL edits, review, JSON round-trip, reload, return to library, candidate acceptance/rejection and MP4 export. Check desktop/mobile layouts, dark/light contrast and the production `/analytics_test/` base path. Publish only after build and relevant checks pass; verify deployed source commit and live page.
