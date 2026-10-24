> Исторический документ: описывает состояние на дату написания. Текущие инструкции — в [индексе документации](../../README.md).

# OCR context implementation and test record (2026-10-16)
Branch: feat/examclips-ocr-context-20261016.

## Completed
- [x] Inspect and sample private Docker lecture without uploading it.
- [x] Benchmark Tesseract CLI on 6 full-size real frames with reference phrase inclusion and timings.
- [x] Cross-check official PaddleOCR/RapidOCR model language compatibility (v6 EN, v5 Cyrillic RU).
- [x] Run matched synthetic English UI, technical board and Russian slide comparison on GitHub-hosted CPU; publish raw results as workflow artifact.
- [x] Introduce independent .ocr-venv for optional PP-OCR (user action only); protect existing Whisper/PyTorch/Ollama.
- [x] Add a loopback-only PNG OCR bridge and fixed Python worker with no user-supplied shell.
- [x] Preserve browser Tesseract mode and automatic fallback.
- [x] Build source-grounded parser for titles, logo, speaker mask, UI tabs, active pixel state, code/formula hints.
- [x] Pair on-screen OCR labels with local speech chunks and annotate storyboard focus evidence.
- [x] Add Node unit and actual Chrome local bridge smoke tests, including Russian short-title regression.
- [x] Keep previous editorial output and audio/WebCodecs regression tests.
- [ ] Real-user Windows PP-OCR benchmark on *private* source lecture frames. BLOCKED until lecture is available on same device/runtime with model assets (private material must not be put on public GitHub).
- [ ] Full independently annotated CER/WER and semantic UI/diagram relation accuracy. BLOCKED pending labels.
- [ ] Fully offline binary + model package. Separate release engineering task, current local-first installation initially downloads dependencies.

## Validation
See actions workflows ExamClips OCR Models Comparison and ExamClips Local MVP CI. Synthetic unit/Chrome success checks actual models; no fake ML quality claims.
