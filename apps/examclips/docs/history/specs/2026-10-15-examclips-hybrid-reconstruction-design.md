> Исторический документ: описывает состояние на дату написания. Текущие инструкции — в [индексе документации](../../README.md).

# ExamClips Hybrid Reconstruction — Architecture Spec
Date: 2026-10-15 · approved direction: automatic 9:16 educational scene editing, local-first.

## Product goal
Create independent educational shorts from lecture videos by **recomposing board objects** (title, visual diagram, text, lecturer) — NOT letterboxing an entire slide or blindly cropping the middle. Source lecture never uploaded from browser. Tested on a 59m50s 1600×900 Docker lecture whose speaker overlay sits at lower right and slides contain title, diagrams, text and code.

## Chosen architecture (v2)
1. Browser File/Blob video decode (Mediabunny).
2. On-device Tesseract.js OCR on representative video samples. OCR produces text and source-space rectangles, not rewritten mathematical truth.
3. Local scene-transition detector: sample thumbnail frames every 8 seconds, ignore the webcam strip, compare pixel differences and create separate scene chapters (max six per clip). OCR runs once per detected chapter. Local director maps OCR terms to ASR transcript windows and selects source regions for approximately 9-second beats; left/right split fallback when OCR is unavailable. All content uses ORIGINAL source pixels.
4. Independent lecturer video layer from a user-adjustable source crop (first preset assumes small webcam lower right). Experimental, not proven automatic face detection.
5. Canvas vertical video composer (720×1280), original audio via WebCodecs+WASM AAC. Default is hybrid. Legacy fit/crop supported only as explicit user choice.
6. Project JSON stores detected scene and timeline. No video/transcript uploaded to GitHub or servers.

## Semantics of automatic vs not automatic
Implemented: optional OCR + split-layout extraction + keyword correspondence to transcript and temporal focus; no need to send video to the cloud. Limitations: discrete 8-second scene-change sampling may miss rapid slide changes; lecturer region is only motion-estimated from several frames with a corner fallback; limited diagram understanding; no guarantee that every diagram/notation remains uncropped or OCR-reflowed correctly. DO NOT represent this as validated multimodal understanding, frame-accurate AI director or correct full reconstruction.

## Data contract
`clip.scene={version:2,title:string,panels:[{id,label,rect:{x,y,w,h},text}],beats:[{time,focus}],speaker:{x,y,w,h},method,source:{width,height}}`
Normalized source rectangles between 0 and 1. Beats use seconds from clip start; source clip timestamps remain absolute in transcript. Renderer accesses `clip.scene` per frame, never reconstructs OCR every frame.

## Privacy
User video and OCR input never transferred to server by application. First OCR/Whisper use downloads language/model assets from third parties; a hosted mutable page still needs a trust model. To deliver audited enterprise strict offline, bundle model assets with signed distributable/Tauri and audit outgoing requests.

## UX
New `AI-композиция` is default. `Распознать доску` button runs OCR. In V1 when OCR fails the player still shows left/right educational panels alternately. Speaker crop has automatic motion-based location at five preset regions and user-selectable corner presets; fine-grained freehand ROI adjustment remains for a later release. User can always switch to conservative legacy fit if detection is poor.

## Acceptance
- Node tests on OCR geometry, text matching, time beats, fallback, bad rect.
- GitHub hosted Chrome synthetic video SRT→hybrid MP4/AAC passes ffprobe and pixel-level image regression.
- No sample lecture in CI / repository.
- Sample Docker lecture frames can be processed locally without remote upload to assess clipping; report limitations honestly.
- Future: slide-change tracker; editable per-object boxes; small vision-language model local; OCR validation and formula fidelity metrics; speaker tracking; 1080x1920 output after benchmarks.

## Technology selection
Browser default: Canvas/WebCodecs/Mediabunny; Tesseract.js OCR (local WASM); Whisper tiny ONNX/WASM; no need for Remotion license or telemetry. Remotion for optional advanced React authoring, HyperFrames for optional desktop batch. HyperFrames requires Node/Chromium/FFmpeg; not pure browser and not installed on end-user device in this phase.
