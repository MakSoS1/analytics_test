# Working on the lecture-clipping site

Read [README.md](README.md), then [docs/architecture.md](docs/architecture.md).
Use [docs/deployment.md](docs/deployment.md) for publication and rollback.

## Identity and branches

This app belongs to `MakSoS1/analytics_test`, source branch
`feat/examclips-library-zoom-storyboard-20261017`, site `examclips.dpdns.org`.
PRs target that branch. `main` is another project; keep it unchanged.
This is not the separate `MakSoS1/examclips` / `forgeofeducation.ru` repository.

## Commands and code ownership

Run npm commands from `apps/examclips/`, with Node.js 22.12+ or 24 LTS.
Use `npm ci --ignore-scripts --no-audit --no-fund`, `npm test`, and
`EXAMCLIPS_BASE=./ npm run build`. Browser checks and prerequisites are in
[docs/development.md](docs/development.md).

- Current planner: `src/general-topics.js`; `main.js` imports it under the
  local alias `planCompleteTopics`. Do not mistake the alias for the legacy file.
- Sentence/word boundaries: `src/speech-boundaries.js`, `src/segments.js`.
- Layout: `src/composition.js`, `src/editorial-motion.js`, `src/scene-model.js`.
- Decode compatibility: `src/audio-compat.js`, `src/media.js`; export: `src/render.js`.
- App state and local project storage: `src/main.js`, `src/project-library.js`.

## Product invariants

- Keep source-grounded, reviewable microtopics. Preserve setup, example and
  conclusion. No hardcoded source identity, output count or duration quota in
  the default planner; do not activate legacy Docker reference guides by default.
- Preserve original speech, measured word timestamps and exclusive EDL source
  ownership. SRT phrase timing must not be presented as measured word timing.
- One readable primary source region at a time; opening-only title, restrained
  dark canvas, no permanent heading or decorative frames. Presenter spans the
  content width below captions. Read the repository editorial skill for visual work.
- Preview and export must share composition and use original source audio.
- User media and project contents stay local. Model downloads are public inbound
  dependencies. Optional Ollama/RapidOCR bridges bind to loopback and validate
  Origin, sizes and payload; these bridges do not exist on the static hosted site.
- Browser support must be tested through actual decode/export. Preserve the AAC
  fallback; `isConfigSupported()` alone is insufficient in YaBrowser.
- Do not claim universal pedagogical quality or a 30–40 minute average-PC
  benchmark from synthetic tests or native ASR measurements on an Apple M4.

## Change and verification discipline

Keep unrelated repository code/workflows out of app changes. Do not commit media,
outputs, weights, environments, caches, secrets, `dist/` or `node_modules/`.
Run the relevant unit/browser checks for the files changed, and ensure both
ExamClips PR checks pass before merging. After deployment check HTTPS, root
HTML/assets, the library/new-lecture flow and source commit in `site-build.json`.
Keep `public/CNAME` and publication paths intact. Documentation under
`docs/history/` records earlier states; current guides take precedence.
