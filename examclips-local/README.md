# ExamClips Hybrid Reconstruction (local-first)

This branch implements the requested **educational TikTok/Shorts composition**, not a 16:9 frame scaled into 9:16.

## One-time setup — Windows

Install Node.js 22+ from https://nodejs.org, clone branch `feat/examclips-hybrid-composer-20261015`, open `examclips-local`, then double-click `START_WINDOWS.cmd`. No video ever needs to be uploaded to any web service.

```powershell
git clone --branch feat/examclips-hybrid-composer-20261015 https://github.com/MakSoS1/analytics_test.git
cd analytics_test\examclips-local
npm install --no-audit --no-fund
npm run dev
```

Open http://localhost:5173. A first-time install downloads application dependencies, and running optional OCR/ASR downloads their model files. No NVIDIA CUDA drivers or dedicated GPU models required; modern Chrome/Edge preferred for WebCodecs export.

## User path

1. Choose local MP4. The preview starts in **AI-композиция**.
2. Optionally import SRT or run local Whisper ASR.
3. Choose a clip; click **Распознать доску (локальный OCR)**. Tesseract recognizes representative frames after locally detecting slide changes (at 8-second sampling intervals) and organizes source diagram/text regions into a vertical story, matching words from the transcript where possible.
4. The lecturer is located by temporal movement across locally decoded frames; if misdetected, change the webcam position in the editor.
5. Review each clip's content and the active region over time, adjust start/end and export an H.264+AAC MP4 locally.
6. Re-open a saved JSON project without repeating OCR if the same original video is selected.

## Distinguish implementation from research ambition

**Implemented:** OCR-assisted region discovery, original diagram crops, selected high-confidence OCR text as reflowable native text, timed panel attention, independent presenter layer, editable presets, browser render with audio, saves. CI includes synthetic slide OCR and browser MP4 tests.

**Not yet implemented or proven:** guaranteed detection of all fast slide transitions, semantic understanding of all diagrams, restoring arbitrary math into correct LaTeX, unsupervised understanding of full three-hour lectures, slide transition tracking, person background removal, guaranteed readable output without review, 1080×1920/30fps cross-platform performance, local small model training. OCR mistakes can alter reflowed words; verify before publishing.

A sample Docker lecture was inspected in conversation only, not uploaded to public GitHub or Actions. Project output stays local, although initial model downloads and JavaScript package installation access vendor hosts.

---
# ExamClips Local MVP (experimental)

A browser-only, privacy-first editor in a **separate folder of the existing analytics_test repository**. Nothing in cover-channel-lab is modified.

## Start

Use Node.js >= 22 and npm:

```bash
cd examclips-local
npm install
npm run dev
```

Open http://localhost:5173. For production build: `npm run build && npm run preview`. Tests: `npm test`.

## Flow

1. Select a local MP4/MOV/WebM video. Video remains in the browser.
2. Choose language, and transcribe the first 5/15 min or entire video using local Whisper. **First ASR use downloads model weights** from Hugging Face, so an internet connection is required once.
3. Alternatively import an existing SRT. This avoids model download entirely.
4. Review draft clips; edit start/end timestamps, title, fitting and focus.
5. Preview inside canvas; export a clip as vertical MP4 with original audio and burned-in subtitles (requires WebCodecs AVC/AAC encoders).
6. Save SRT and project JSON locally. Reopen JSON then select original video again.

## Known limitations and honest status

- First-version segmentation is a **deterministic timestamp / pause heuristic**, not a trained semantic-ranker. It must NOT be represented as a proven LLM or embedding-based method. 
- Visual layout uses user-controlled fit/focus/crop; it does **not** detect faces, OCR or LaTeX yet.
- Whisper timestamps may be coarse; human verification is required.
- Initial prototype uses **720×1280 at 15fps** to keep processing affordable; contract-ready 1080×1920 at normal framerate remains for benchmarking.
- MP4 export depends on browser H.264/AAC encoding support and could be unavailable; do not claim universal compatibility. Short clip first.
- BufferTarget stores the *exported clip*, not full source, in memory. Add StreamTarget to support hour-long exports.
- For confidentiality, video never leaves the device, but model/script downloads contact their hosting services. No analytics, no recording upload code. A website operator can update JS, so strong offline guarantees require packaged/reproducible builds.
- Current build is not a signed or audited desktop application. No performance claims, quality scores, or user-pilot results are asserted.

## Privacy check

Open DevTools → Network. After the model is cached, disable networking, reload an already cached application (or use localhost built assets), import SRT, and export a short clip. No request should contain input video bytes, PCM, transcripts or frame data. Record the network trace in testing.

## Sample lecture

`HAHL2026_Lecture01_Docker.mp4`: 59m50s, 1600×900, 25fps, H.264/AAC, 65.8 MB. This private user-provided file is **not** committed or uploaded to GitHub. Selected slides have a small lecturer image and dense content, so use **Preserve complete slide** first; automatic crop is unsafe.

## Next steps

See `docs/superpowers/specs/2026-10-15-examclips-browser-mvp-design.md` and `docs/superpowers/plans/2026-10-15-examclips-browser-mvp.md`.
