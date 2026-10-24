> Исторический документ: описывает состояние на дату написания. Текущие инструкции — в [индексе документации](../../README.md).

# Progress for 2026-10-20-examclips-atlas-interface.md

- Source repositories and complete supplied product spec inspected. Working branch based on current published engine commit 208d728.
- Decision: port the selected Atlas DOM/CSS design onto the existing engine, keeping a single media player and existing IndexedDB. The source design's in-memory fixtures and server integration cannot preserve real projects.
- User already selected the design and requested complete integration and publication. Execution proceeds under that authorization.
- Baseline engine unit suite reported passing by independent auditor. Root verification and browser tests recorded below as performed.

## Implemented and verified

- Native Atlas shell, three-step import, real library cards, chapter portrait grid, separate candidate group, source/9:16 detail, local EDL controls, evidence and chronological navigation.
- Dark and light interface themes. Secondary text is brighter; tested desktop/tablet/mobile grid is 5/3/2 columns. No demo lectures, Lovable client or prototype backend dependencies are included.
- Existing IndexedDB identity/schema retained. Optional settings and detail/scroll state round-trip with the project. Projects can open without the large source attached; source mismatches and invalid JSON preserve existing edits.
- Transcript range discovery uses the existing planner/verifier, absolute cues and occupied EDL spans. Candidates are explicitly accepted; repeated searches do not duplicate them. Manual ranges must be at least 10 seconds.
- One original player serves source and clip views. Source playback passes through excluded time; clip playback follows ordered EDL. Resume retains the current part. Boundary/EDL/transcript/composition edits invalidate old review and finished MP4 state.
- The isolated renderer review and integration review found and repaired stale exported MP4 state and playback restart after pause. The dedicated editing/playback regression first reproduced both failures and now passes.
- Final independent review also covered repeated source intervals and background playback. Resume now retains the ordered EDL piece index, and the shared playback boundary guard runs on both animation frames and media time updates. Both regressions were reproduced before the fix and passed afterward; the reviewer confirmed the repairs.

## Verification evidence before publication

- `npm test`: 29 test files passed, zero failures. The new range and snapshot modules add 19 behavioral cases.
- `EXAMCLIPS_BASE=/analytics_test/ npm run build`: passed; output asset URLs contain `/analytics_test/assets/`. Existing large media/ML bundle warning remains informational.
- All three Atlas browser regressions passed in official Chrome: UI/wizard/persistence; metadata-only projects/ranges/JSON; playback continuation/edit invalidation.
- The full Atlas UI regression also passed against the production build served at `/analytics_test/`, including reload, original attachment, project persistence and mobile navigation.
- Real original and portrait canvas frames changed during playback (mean pixel changes 9.01 and 10.12). Actual MP4 export passed at 720×1280 and 1080×1920 with audio, duration 4.032 seconds.
- Existing MVP UI, library/8× zoom/reload/immediate exit, noncontiguous EDL, sparse lecture, evidence grid, long worked example and batch export smokes passed. The long synthetic worked example remained one 20:15 lesson; two noncontiguous intervals exported as a 2.837-second MP4 with H.264/AAC.
- `git diff --check`, JS syntax, CSS parsing and measured contrast passed. Mobile layout at 390px had no horizontal overflow.
- Both PR workflows retain prior gates and add the three Atlas regressions. Official Chrome is selected for H.264/AAC support.

These are deterministic fixtures and application integration checks, not an evaluation of the user's unavailable original Docker audio. Remaining ASR/OCR and semantic-quality limitations are unchanged by this interface migration.

## Publication route

Create a feature PR into `feat/examclips-library-zoom-storyboard-20261017`, wait for both CI workflows for the latest commit, then merge. Existing Ready-to-Publish rebuilds with the Pages base path; verify its run, the separate Pages deployment and the live `site-build.json.source_commit`. The unrelated `main` branch and the selected source design repository are not deployment targets.
