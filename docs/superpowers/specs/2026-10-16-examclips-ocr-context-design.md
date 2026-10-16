# ExamClips scene-aware OCR selection (2026-10-16)

## Product problem
User has videos combining live webcam, educational slide/document, math/diagrams, and sometimes software UI. A classic OCR pass recognizes words but cannot reliably identify a title, selected tab, diagram relation or lecturer's active attention. Avoid retyping uncertain source pixels.

## Selected local architecture
1. Decode source locally; detect slide changes with cheap image differences (do NOT run OCR at video FPS).
2. For each representative frame, choose on-device OCR:
   - Default Auto: local isolated PP-OCR through localhost Python if user installed it, else Tesseract.js WASM.
   - Explicit Tesseract browser mode never depends on Python or another service.
   - RapidOCR maps EN -> PP-OCRv6 small, RU -> PP-OCRv5 Cyrillic mobile, ONNX CPU. No GPU or heavy downloads on user's existing Ollama/Whisper installation.
3. Normalize into OCR lines with source-space box and confidence 0–100, regardless of OCR provider.
4. Analyze only evidence in those lines: header, brand, text/code/formula, horizontal aligned UI tabs, pixel-highlighted active state if visual contrast is unambiguous. Exclude speaker crop from OCR context.
5. Align literal labels with local Whisper/SRT speech windows and shift current focus region when spoken terms match. This is lexical matching, not proven semantic scene understanding.
6. Preserve diagrams/unknown formulas and unrecognized information as original source pixels. Avoid generative redraw unless content verified.
7. Render through unchanged source-faithful editorial Canvas/WebCodecs compositor with moving instructor.

## Testable acceptance
- English synthetic UI screen with tabs Overview, EPDE, PySINDy: PP-OCRv6 recognizes all labels; spatial parser returns active Overview by measuring blue-tinted background; spoken mention PySINDy returns tab target.
- Russian synthetic slide: PP-OCRv5 mobile recognizes all 4 references; title parser keeps short "Как" token.
- English technical diagram card slide: PP-OCRv6 recognizes all 5 selected labels (Tesseract PSM6 only 1/5 on same synthetic case); original diagrams stay pixel source.
- Public CI: Python child backend consumes a bounded PNG on STDIN and returns line rectangles; Chrome calls /api/local-ocr on 127.0.0.1, foreign Origin rejected; OCR unavailable -> browser-only Tesseract.
- Production Vite preview uses identical loopback route as dev; no server-side public uploads.
- H264/AAC video/real moving lecturer from old CI must still pass without changes.

## Empirical evidence caveats
Private 59m50s Docker recording in current ChatGPT runtime, six 1600x900 representative frames. Tesseract 5.5.0 (Linux CPU) ~0.28–0.39s/frame. It fully matched 12/16 hand-recorded target phrases: exact string phrase coverage, NOT character accuracy. No transcript or original frame uploaded to public GitHub.
Synthetic test conducted on GitHub-hosted CPU with public generated slides:
- EN UI: Tesseract PSM6 4/5 vs PP-OCRv6 small 5/5.
- EN technical board: Tesseract PSM6 1/5 vs PP-OCRv6 small 5/5.
- RU instructional board: Tesseract PSM6 4/4 vs PP-OCRv5 Cyrillic mobile 4/4.
Runtimes and downloaded model weights differ; the results do not prove Paddle superiority on the private video. First-use downloads omitted from warm model inference comparisons. Full CER/WER and layout mAP require human-labeled reference frames and model evaluation on precisely the same real lecture.

## Security / privacy
- Browser OCR has no network data upload. It may fetch public OCR model assets once from published sources.
- RapidOCR is opt-in; INSTALL_OCR_WINDOWS.cmd creates examclips-local/.ocr-venv and installs packages only there. Models download on first use. Existing Python3.11 WhisperX and Ollama aren't modified.
- RapidOCR bridge accepts only loopback HTTP, rejects unrelated origin, limits payload/PNG size/dimensions, runs a fixed non-shell Python script, rejects parallel requests and limits execution time. Local image bytes are not stored as a file or transmitted to third-party inference.
- Git ignore excludes local videos, audio, ONNX models, isolated Python envs and generated result artifacts. Public CI assets are purely synthetic.

## Known limits and future work
- Selected-tab state depends on color, can be ambiguous in dark/hover themes; returns null rather than guessing.
- OCR sees text but not relationships between graph nodes. Need later real image/ASR multimodal benchmark for deeper layout semantics.
- Per-slide representative frame can miss animations occurring between visual change samples; need higher-rate region change tracking.
- For multi-language slide and Russian/English mixed lines, the RU model supports both but was only verified on a synthetic Russian board here.
- Strictly offline installers should bundle signed model archives in a future product packaging stage.
