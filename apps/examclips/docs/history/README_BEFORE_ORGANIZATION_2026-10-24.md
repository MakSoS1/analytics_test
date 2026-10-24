> Исторический документ: описывает состояние на дату написания. Текущие инструкции — в [индексе документации](../README.md).

# ExamClips v0.11: general speech boundaries & single-focus vertical lessons

This branch is the current local-first ExamClips: transcribe a lecture locally, propose context-reviewable 1–5 minute lessons, recognize relevant slide/UI labels, synchronize scene focus with what the lecturer says, and export with original live presenter video/audio.

## Windows start

Install Node.js 22 or newer, clone tag v0.11.1 of https://github.com/MakSoS1/analytics_test and run examclips-local/START_WINDOWS.cmd. The editor opens at http://localhost:5173; first model use can download PUBLIC weights. Media is read from local files only.

## Browser audio compatibility

Before processing, the app tests actual audio decoding. If WebCodecs rejects AAC (including YaBrowser configurations that report support), audio is read locally through Web Audio in windows of at most 30 seconds. The same path supplies original audio for MP4 export. No full-lecture PCM buffer or extra decoder download is required.

## OCR options

- **Automatic (default):** If the isolated RapidOCR environment exists, prefer local RapidOCR; otherwise Tesseract.js in browser.
- **Tesseract.js:** No Python installation required. Browser WebAssembly runs locally. Fast enough for representative slide OCR, weakest on small software buttons on our synthetic test.
- **RapidOCR PP-OCRv6 small:** English/Latin software UI and engineering slides, CPU ONNX Runtime. Optional isolated local Python environment.
- **RapidOCR PP-OCRv5 mobile Cyrillic:** Russian/English slide text; same optional local environment.

To enable RapidOCR on Windows, double-click INSTALL_OCR_WINDOWS.cmd in examclips-local. This installs optional packages into a new .ocr-venv, **not into existing Whisper/PyTorch/CUDA/Ollama**. Public model weights are retrieved on first use and cached. Restart the local editor afterward.

The user-selected PNG goes only from the browser to a Vite server bound to 127.0.0.1, then through standard input of a fixed local Python script. It is not sent to a cloud OCR provider. The bridge checks local address, Origin, request size, PNG signature and image dimensions. If unavailable or failing, the editor falls back to Tesseract.js.

## Source-aware scene context

1. Sample lecture video around visual slide changes. Do not OCR every video frame.
2. Extract local OCR lines, coordinate bounding boxes and confidence.
3. Exclude recognized pixels in the presenter window, separate a top-right logo from the lesson title and identify layout groups: teaching prose, code, formulas, software UI tabs.
4. Determine which tab is highlighted only if measurable pixel colors support that claim. Unclear theme -> activeTab is null.
5. Compare actual OCR object names to words spoken in the locally obtained Whisper/SRT transcript and adjust visual region focus at those timecodes. This is a lexical heuristic, **not** verified comprehension of diagrams.
6. Preserve original pixels when a formula, topology, small font or OCR label cannot be faithfully reconstructed.
7. Export vertical H.264/AAC with actual video of the lecturer. Manual review of proposed microtopic starts/ends is still required.

## Evaluation evidence

- On six privately inspected Docker video frames (1600x900), Tesseract 5.5 took about 0.28–0.39s per image. It found 12/16 specifically chosen reference phrases (75%); this is *not* an overall OCR accuracy metric.
- An independent synthetic public three-slide test on GitHub-hosted Ubuntu compared exactly the same visual conditions. PP-OCRv6 small found 5/5 English UI phrases and 5/5 technical-slide phrases, while Cyrillic PP-OCRv5 mobile found 4/4 Russian phrases. Tesseract was weaker on synthetic buttons and compact English layout.
- These synthetic results DO NOT prove superiority of PaddleOCR on the real private Docker recording. For that we need PP-OCR predictions on the exact same private frames and human reference text.
- GitHub CI tests browser UI scene/tabs, Tesseract fallback, PP-OCR Python child process, origin protection, original MP4/audio export and presenter motion. All CI fixtures are generated synthetic assets, never the user's original lecture.

## Quality and security limits

Initial model downloads from third-party model hosts need Internet once. Strictly air-gapped distribution must include trusted cached public model files. Active tab colors are theme-dependent; incorrect labels are possible. Geometry and word matching do not replace a multimodal semantic director or quality-reviewed math reconstruction.

Node development: npm install --ignore-scripts --no-audit --no-fund; npm test; npm run build; npm run preview. Local playback/media files, Python .ocr-venv, caches and generated MP4 are Git-ignored.

See docs/superpowers for earlier architectural and microtopic plans and the new OCR evaluation note.

## Real Docker lecture workflow

See [the 2026-10-20 acceptance report](reports/REAL_DOCKER_ACCEPTANCE_2026-10-20.md) for the measured native Whisper workflow, exact reproduction commands, source-grounded boundaries and limitations. Source media and generated videos are distributed as release assets. The browser also accepts the resulting SRT or editable project JSON.

## General lecture workflow and single-focus video

See [the v0.11 acceptance notes](reports/GENERAL_SPEECH_AND_SINGLE_FOCUS_2026-10-20.md). The default app no longer uses the filename-specific Docker guide. Native ASR now retains measured word timestamps; import the editable project JSON to retain them (SRT carries phrase timing only). Title cards disappear after 1.6 seconds; the default dark composition shows one source region at a time.
