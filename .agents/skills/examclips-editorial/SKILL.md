---
name: examclips-editorial
description: Use when composing or reviewing source-faithful vertical lecture videos in the ExamClips branch of MakSoS1/analytics_test.
---
# ExamClips editorial reference

Read `apps/examclips/AGENTS.md` and `apps/examclips/docs/quality.md` first.
Work in the ExamClips source branch, not `main`. This is the lecture-clipping
site at examclips.dpdns.org, not forgeofeducation.ru.

## Current visual contract

- Default restrained dark canvas. Preserve original pixels for diagrams, code,
  formulas and uncertain OCR. Do not redraw uncertain technical information.
- One primary source region per moment, large enough to read on a phone.
  Change focus with the explanation. Do not alternate arbitrary blank regions.
- A centered opening title finishes at 1.6 seconds of continuous lesson time.
  Do not keep a permanent heading, badge, counter or decorative frame.
- Presenter spans the content width below captions, with natural 16:9 geometry.
  Current 720x1280 geometry: main x18/y32/w684/h736, captions y776/h100,
  presenter x18/y884/w684/h384. Check `editorialGeometry()` before changing it.
- Keep captions separate from teaching material and presenter. Word reveals
  follow real timestamps when available; phrase-level SRT is an approximation.
- Animation is deterministic by frame/lesson time. Preview and MP4 use the same
  compositor. Title time must not restart at a noncontiguous EDL cut.

## Meaning and verification

Use original speech, evidence and sound. Keep setup, example and conclusion;
review boundaries on arbitrary subjects, not only Docker. Proposed lessons
remain reviewable. No fixed output count or maximum duration may truncate an
explanation. Full-lecture timing targets need measurements on the target device.

For visual changes, inspect rendered stills at the title, after the title,
a focus change and an EDL cut; check tiny text, clipping, duplicated source,
caption collision and camera distortion/motion. Check the final MP4 streams,
duration and audio synchronization. Synthetic tests do not certify teaching
quality. User media is not uploaded to public CI or cloud inference.

## Code map (repository-relative)

- `apps/examclips/src/editorial-motion.js`: geometry, title timing, palette.
- `apps/examclips/src/composition.js`: preview/export painting.
- `apps/examclips/src/scene-model.js`: source regions and scene timing.
- `apps/examclips/src/render.js`: browser MP4/audio export.
- `apps/examclips/tests/single-focus.test.mjs`: layout/title contract.
- `apps/examclips/scripts/single-focus-smoke.mjs`: browser rendering regression.
- `apps/examclips/scripts/editorial-visual-smoke.mjs`: rendered visual samples.
