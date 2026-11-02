> Исторический документ: описывает состояние на дату написания. Текущие инструкции — в [индексе документации](../../README.md).

# ExamClips microtopic-first pipeline and live presenter acceptance (2026-10-16)

## Product decision
**Do not create shorts by slicing every 15 seconds.** A deliverable video teaches *one independently understandable microtopic*. Prefer 60-180 seconds, with an opt-in tolerance to **300 seconds** if the explanation requires it. Preserve original speech and live instructor video; montage follows selected content rather than defining topic boundaries.

## Evidence and problem
The previous handcrafted 12-second Docker example was only an editorial animation demonstration. It did not explain a self-contained lesson, lacked a verified transcript, and the exported lecturer picture appeared frozen. Direct frame-level inspection proved the original lecturer moves; the specific Python prototype read raw FFmpeg stdout in a way that could return incomplete frame data, then substituted a static fallback. This was fixed in a local-only diagnostic, measuring motion of exported webcam frames: mean absolute grayscale difference increased from approximately 0 to over 5 per sampled half-second. The browser renderer separately decodes a source frame for each output timestamp and now has an end-to-end exported-webcam motion regression.

## Pipeline
1. Local source video and optional ASR: browser Whisper or user-supplied SRT. **No transcript = no claim of automatically completed microtopics.** An initial placeholder cannot be exported.
2. Candidate boundary scoring: natural ASR chunk boundaries, pauses, punctuation, explicit topic transitions, conclusion cues, lexical novelty, connected-sentence penalty.
3. Global segmentation: dynamic programming optimizes candidates over the covered transcript with soft target 165 seconds and hard maximum 300 seconds, minimum 60 seconds except a short remainder or deficient ASR (flagged as incomplete). A compact preset uses target 105 seconds, hard max 180.
4. Each topic gets an extractive title from actual recognized sentences and a low/medium tentative confidence marker, with specific review warnings when intro, ending or ASR coverage is uncertain. No artificial narration, fictional conclusions or generated formulas.
5. User can preview the first 15 seconds of preceding speech, extend start/end by 15 seconds, edit text and ranges, and re-run boundary suggestions. Editing title updates rendered scene title.
6. Each clip drives its own timeline: slide-change detection, OCR block analysis, original pixel diagrams, local warm editorial layout, instructor PiP and subtitles.
7. Export retains original audio and sequential decoded source frames. Automated browser regression uses a static presentation with a moving teacher video window and tests motion in **the exported video pixels**, not just the input.

## Quality rubric for future acceptance
A reviewable microtopic must (A) introduce terms and context; (B) explain one concept, operation or proof; (C) contain a conclusion or complete worked example; (D) show the relevant visual element at the corresponding narration time; (E) retain audible and visually moving instructor video; (F) be free of cut-off sentences.
The current heuristic **cannot certify** those pedagogical properties. Its output is marked needs-review. For autonomous acceptance, benchmark on manually annotated teacher-separated lectures and build an optional *fully local* semantic judge/reranker using a smaller model; compare with the heuristic and reject/correct uncertain boundaries.

## Acceptance tests
- No transcript: zero automatic topics; initial placeholder export disabled.
- 16-minute SRT: suggested clips are normally 60-300 seconds and cover only recognized speech, not arbitrary remainder of source file.
- If ASR covers 5 minutes of a 60-minute lecture, the UI warns that the remaining lecture has not been analyzed.
- Title extracted from actual meaningful sentence, not just 'now let's move on'.
- Exported browser MP4: sound included, source presenter visibly moves (numerical ROI pixel differences > 2.5), still lecture board remains source-faithful.
- Browser compatibility verified in GitHub-hosted Chrome with synthetic video; full real Docker lecture segmentation remains an acceptance experiment, not a passed test.

## Deployment and privacy
Local browser Vite/React-compatible front-end + Mediabunny/WebCodecs; no uploaded original files. Optional first-time WASM/ONNX model downloads. User's Windows self-hosted GPU runner, Ollama models and disk were not modified for this correction. No private original video attached to public GitHub Actions.

## Further development
1. Human-annotated transcripts and evaluation of exact semantic boundaries (tolerance ±10s), self-containedness ratings and topic coverage.
2. Separate semantic completeness verifier that reads a clip and surrounding transcript context; deployment through browser-local distilled ONNX encoder/ranker or optional installed local compute.
3. Extractive recap/title and preview confirmation of prerequisites; never invent lesson facts.
4. More accurate SRT word timing and synchronized emphasis, automatic presenter face/ROI tracking under slide motion.
5. On-device performance benchmark with 60-minute and 180-minute lectures before production acceptance.
