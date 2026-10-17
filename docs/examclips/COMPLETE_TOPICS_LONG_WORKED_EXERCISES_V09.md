# ExamClips v0.9 — complete-topic discovery with long worked exercises

## Product requirement (2026-10-17)
- Never request a user-selected percentage of 'interesting' lecture footage.
- The objective is all substantively useful instructional content: definitions, explanations, examples, demonstrations, computations, conclusions.
- Omit obvious waiting, silence, microphone checks, breaks, purely organizational talk and empty repetitions, conservatively.
- A worked example or practical problem may last 20 minutes (or longer) and must remain one coherent portrait micro-lesson.
- A micro-lesson can comprise multiple nonadjacent source parts; content editing does not require forced contiguous timestamps.

## Changes in source code
1. `src/complete-topics.js` is the active planner called from `src/main.js`. It examines the complete ASR/SRT stream, keeps educational speech by default, removes obvious low-value filler, and preserves long tasks until an actual topic/problem transition.
2. No keepFraction, total coverage percentage cap, maxStories, fixed 15s, 3-minute, 5-minute or 10-minute limits are used by the active planner. Percentage displayed on the timeline is a diagnostic of time actually retained, not a target.
3. 1+ source parts per lesson (EDL) remain supported, with source-accurate captions, per-part storyboard/OCR and original audio.
4. `src/render.js` removes the artificial 601-second block; source frame timestamps are decoded in bounded ten-second batches to avoid allocating giant timestamp arrays.
5. Long single-video export (5+ minutes) uses browser File System Access save picker and mediabunny `StreamTarget` for disk-backed MP4, instead of holding the whole output in RAM. Batch exports use per-file streams as well.
6. For browsers lacking save-to-file streaming, a long clip may still use `BufferTarget` in memory. This is less safe on weak computers; Chrome/Edge are recommended for 20-minute exports.
7. The first-screen UI removes the share-of-content selector and duration preset; it explains automatic preservation of whole educational topics. Source timeline and Montage / Captions / Tests / Export tabs remain as before.
8. Optional localhost Ollama per-topic completeness review remains available in the Montage tab. The older experimental whole-lecture selective-story API is no longer linked to the user interface; it must not replace the new complete-content planner.

## Important empirical limitation
- The active planner is a conservative transcript-based boundary proposal, not a formally tested multilingual semantic understanding model. All auto-proposed clips are tagged `needs-review`.
- Recognized-speech timestamps detect some silent gaps but are not equivalent to verified waveform-level VAD. A false transcription or ambiguous teacher transition may be misclassified.
- Some lectures without explicit topic markers may produce a longer composite lesson requiring human separation; this is preferable to silently throwing away valid learning content.
- No genuine 20-minute high-quality 1080p export stress test has been performed on a consumer GPU. Structural 20-minute tests and real short direct-to-disk-streaming MP4 tests cover complementary aspects, not the full runtime envelope.

## Acceptance
- A one-hour source with >80% educational speech retains >80% (no cap); filler and microphone checks are removed.
- A 20-minute step-by-step practical exercise remains one microtopic despite repeated technical terms and long runtime, followed by a distinct next-topic video.
- A transcript with separated genuine explanations and organizational gaps keeps ALL educational explanations. It may exclude more than 50% if those gaps are genuinely empty.
- Blank / admin-only source produces no fabricated micro-lessons.
- Long-output streaming MP4 is independently FFmpeg-decodable, including H.264 video and AAC speech; batch files use indexed positional writes.
- Privacy remains local-first: lecture audio/video never uploaded to a server; first-use model downloads may require the network. Longer jobs may take substantial processing time.

GitHub branch `feat/examclips-complete-topics-longform-20261017` based on previous v0.8. No changes to main.