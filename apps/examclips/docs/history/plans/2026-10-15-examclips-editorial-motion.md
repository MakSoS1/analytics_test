> Исторический документ: описывает состояние на дату написания. Текущие инструкции — в [индексе документации](../../README.md).

# ExamClips editorial finishing plan (2026-10-15)

User goal: real educational Shorts with accurate slide reconstruction, polished text, motion synchronized to lecture speech, a compact lecturer crop and no unnecessary empty space. Must stay local-first.

## Technology choice
Chosen: our Canvas/WebCodecs renderer, using published Remotion/motion-agent design rules. Native Remotion renderer and HyperFrames remain optional backend adapters, not mandatory downloads for users. Video/media remains on device.

## Work stages
1. [x] Identify official Remotion, editorial motion-graphics and general video QA agent skills.
2. [x] Implement a pure typography/easing/layout contract with automated boundary tests.
3. [x] Replace duplicated headers, overlapping OCR cards and wide presenter band with responsive warm editorial composition.
4. [x] Add preview/export caption parity and optional midnight style.
5. [x] Build actual-Chrome screenshots at two visual beats plus dark theme and validate a meaningful visual change.
6. [x] Verify latest implementation: 27/27 unit tests, production build, Chrome H264/AAC MP4, screenshot captures (GitHub run 38804509437).
7. [x] Manual local preview of Docker source: saw the two-line headline collide with divider in initial manual render; changed to a single correctly fitted title, regenerated A/B stills, full-decoded the 12-second H264+AAC local demo. Browser synthetic screenshot should also be reviewed visually from CI artifacts before launch.
8. [ ] Real lecture end-to-end quality: measure OCR fidelity, frame scene cuts, webcam position, visual readability, processing times and original audio sync.
9. [ ] Evaluate on lower-end devices; only add native desktop renderer if browser requirements fail on measured supported hardware.

## QA and privacy
Public GitHub Actions uses generated fixtures only; never upload private lecture frames or ASR text. Deliver explicit warnings for uncertain OCR and formulas. Quality and speed of real 59m Docker lecture remains unverified until real acceptance.

## Final latest-code integration evidence
GitHub Actions https://github.com/MakSoS1/analytics_test/actions/runs/38805605554 passed 27/27 unit tests, clean Vite production build, Chromium 720x1280/15 and 1080x1920/30 H264+AAC exported MP4, complete ffmpeg decode of HD output, and three real compositor screenshots with a 7.8% changed-pixel fraction between educational beats. This establishes reproducible encoding and visual motion on synthetic assets; it does not establish faithful full-course semantic directing on a user lecture.
