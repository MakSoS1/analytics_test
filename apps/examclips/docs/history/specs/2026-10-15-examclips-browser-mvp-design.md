> Исторический документ: описывает состояние на дату написания. Текущие инструкции — в [индексе документации](../../README.md).

# ExamClips browser-first MVP — design specification
Date: 2026-10-15. Status: implementation baseline (needs real-device browser acceptance). Scope: standalone `examclips-local/` folder on `analytics_test` feature branch.

## Goal and acceptance
Convert an *authorized* horizontal educational lecture to locally reviewed vertical clips, preserving audio and subtitles without uploading lecture frames, sound, transcripts or derivatives to remote services. Explicitly distinguish proven user-local computation from model downloads or server-delivered source code.

User can select existing local video, inspect metadata, run Whisper ASR in WebGPU/WASM, import SRT as offline alternative, review timestamp candidates, choose conservative fit or a user-focused crop, preview, export short MP4, download SRT and save project JSON.

## Non-goals
No cloud AI inference, billing, auth, collaboration, accurate scene classification, guaranteed performance on all hardware, presenter detection, latex regeneration, automatic semantic-quality scoring, full video upload, or native GPU worker in MVP. These are versioned future components.

## Project boundary
The video Blob is held in browser memory by reference. `mediabunny` uses BlobSource + VideoSampleSink and AudioBufferSink for sparse/streaming decode. `@huggingface/transformers` loads a small Whisper model on the end-user's GPU/WASM from Hugging Face on first use; model download is disclosed. No lecture content is posted anywhere.

- `src/media.js`: codecs, audio chunks, metadata, no eager whole-file audio decode.
- `src/asr.js`: Whisper inference, cancellable 30s chunks, timestamps; no API call to hosted inference.
- `src/segments.js`: deterministic boundaries, subtitles parsing/formatting, standalone tests. Semantic model is deferred.
- `src/composition.js`: pure canvas painting. Default preserves complete source frame; focus/crop require opt-in.
- `src/render.js`: self-contained AVC/AAC MP4 output from decoded video/audio samples with backpressure. Detect unsupported codecs and explain limits.
- `src/main.js`: page state, review, export, local JSON/SRT (no server).
- `tests/`: headless logic tests.
- CI hosted Linux: npm install/test/build; no video is uploaded to Actions.

## Data model
```json
{
  "schema": 1,
  "videoName": "local-source.mp4",
  "duration": 1234,
  "clips": [{"id":"clip-1","start":20,"end":96,"title":"Intro","layout":"fit","focusX":50}],
  "chunks": [{"start":20,"end":25,"text":"Example"}]
}
```
The video itself is NOT embedded in JSON. The user must explicitly select original local video on restoring a project. Unknown schema and incompatible durations reject restore.

## Compatibility/failure policy
No audio track -> local ASR disabled/error, still manual clip possible. Invalid timestamps rejected. ASR download failure remains visible and SRT import remains available. Unsupported VideoEncoder/AudioEncoder -> explicit error and preserved project. Encoder no output -> error rather than false success. Cancellation stops between decoded samples/inference chunks. Inputs >2 GB rejected for current scope. Full three-hour video can be selected but uninterrupted export or recognition is NOT benchmarked.

## MVP acceptance matrix
1. Static checks: Node 22, clean package build with no TypeScript errors, deterministic segmentation/unit tests.
2. Manual: import <=2 GB H264/AAC file; preview shows complete frame in fit mode.
3. Manual: SRT import/export roundtrip; edit title/range; save JSON; restore same video.
4. Manual: browser with working AVC/AAC encoders exports 10-30s MP4 with audio; verify via ffprobe.
5. Manual: first Whisper run downloads model; subsequent 30s window ASR locally, reload with offline model cache where available.
6. Privacy: inspect network requests; no POST containing audio/transcript/video. Record exact third-party requests; avoid 'zero network requests' claim because assets/models are downloaded.
7. Negative: invalid source, muted/no audio, offline first download, unsupported codec, large lecture, cancellation, memory pressure.

## Benchmarks to collect before broader release
Browser+version, CPU/GPU, WebGPU available, decoder/encoder support, 5/30/90-min ASR time, peak RAM, 45s MP4 export time+size, rendered visual legibility, subtitle WER, clip completeness scores, network audit. Pass contract-level 1080p/180min only AFTER objective tests.

## Integration isolation
This feature does not edit the existing ML/security repo. Use separate workflow and folder; keep self-hosted Windows runner untouched by default. Uploading sample lecture to public GitHub or GPU machine is forbidden without explicit transfer route approval.
