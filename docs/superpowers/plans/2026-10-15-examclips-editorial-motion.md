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
6. [ ] Verify latest commit: all unit tests, production build, Chrome MP4 with sound, screenshot captures.
7. [ ] Inspect the captured preview stills manually; rerender after removing any content collision.
8. [ ] Real lecture end-to-end quality: measure OCR fidelity, frame scene cuts, webcam position, visual readability, processing times and original audio sync.
9. [ ] Evaluate on lower-end devices; only add native desktop renderer if browser requirements fail on measured supported hardware.

## QA and privacy
Public GitHub Actions uses generated fixtures only; never upload private lecture frames or ASR text. Deliver explicit warnings for uncertain OCR and formulas. Quality and speed of real 59m Docker lecture remains unverified until real acceptance.
