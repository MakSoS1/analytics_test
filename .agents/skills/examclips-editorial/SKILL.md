---
name: examclips-editorial
description: Compose and review source-faithful vertical lecture shorts with mobile typography, purposeful motion and local rendering.
---
# ExamClips Editorial Motion Skill

Produce polished 9:16 education videos with a separate lecturer layer. Do not paste a miniature 16:9 slide into the portrait canvas.

Research:
- https://github.com/remotion-dev/skills (timing, visual QA, media, captions, measuring text)
- https://github.com/Liamrjohnston/remotion-motion-graphics-skill (clarity, purposeful choreography, real assets)
- https://github.com/gitethanwoo/video-editing (editorial analysis and render verification)

## Rules
1. Actual lesson imagery, titles, diagrams, facts and sound must come from user-selected input; do not fabricate technical data.
2. One primary visual idea per moment. Respect safe zones for captions and presenter. Reserve visually separate hero and bottom inset.
3. Fit measured text to width AND height. Headlines 34-57px; body 23-36px for 720x1280. Handle unbreakable terms and display at most one coherent thought per beat.
4. OCR is fallible. Reflow only high-confidence text; use original pixels for ambiguous formulas, topology diagrams and unknown layout.
5. Video animations are frame-time deterministic. Use 0.48s eased crossfades for meaningfully changed focus and restrained line reveal. Never use CSS transitions or arbitrary decorative shakes.
6. Treat captions separately from explanatory data. Page long captions into readable short cues without rewriting or fabricating words.
7. Presenter stays in a compact independent crop, with aspect-preserving cover, optional manual location and hide button.
8. Default warm white academic editorial style. Optional restrained dark background, single blue accent, zero neon or decorative gradients.
9. Same renderer powers live preview and final WebCodecs MP4. Private lecture data never goes to public CI or cloud inference.
10. QA on actual rendered stills: first/current beat, next beat, alternate theme. Check no clipping, duplicate text, tiny source images, presenter distortion, or caption collision. Run ffprobe on final video.
11. Do not claim artistic/pedagogical quality proven by synthetic tests. Test with an authorized real lecture and manual visual review.

## Code ownership
Editorial primitives: examclips-local/src/editorial-motion.js
Renderer: examclips-local/src/composition.js
Time/scene: examclips-local/src/scene-model.js
Browser export: examclips-local/src/render.js
Tests: examclips-local/tests/editorial-motion.test.mjs and scripts/editorial-visual-smoke.mjs
