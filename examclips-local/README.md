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
