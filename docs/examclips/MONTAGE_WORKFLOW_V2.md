# ExamClips v0.6: progressive short-video composition, wizard and source timeline

## Product goal
Original 16:9 university lecture stays on the user's device. Convert it into reviewable 9:16 1–5-minute topic explanations, preserving actual board/formula/code pixels, original lecturer footage and speech. The user explicitly asked to avoid a fixed, empty subtitle rectangle, give more space to the webcam, and replace the overwhelming control wall with an upload-first editor.

## Short-form references: specific sources and implications
- CapCut's supported formats include **word-by-word synced**, **highlighted** and **dynamic** captions. Source: https://www.capcut.com/resource/types-of-captions
- OpusClip's 2026 promotional research on educational video reports frequent animated subtitles, but the percentages are *vendor claims* and not an independent controlled experiment. Source: https://www.opus.pro/research/best-caption-strategy-education-tutorials
- Educational screen walk-through examples from @sulansart described by Vyra emphasize readable phone zoom on concrete actions, presenting face on one side and the relevant screen action on the other. Source: https://www.usevyra.com/formats/app-walkthrough
- Numberbender vertical teaching studio demonstrates source-native 9:16 compositions rather than placing an unchanged 16:9 recording in a tall frame. Source: https://numberbender.com/studio-tutorial
- The lecture-short recommendation is to prioritize one complete concept and check it without the surrounding hour. Source: https://dalaillama.in/blog/turn-lecture-into-shorts

These are format references and product design cues; the user-provided example video did not accompany this particular request, so there is no claim of having inspected that specific file.

## Deliverables
1. **Onboarding wizard**: upload-only empty state; once media loads, configure Whisper Tiny/Base or bring a local SRT; processing uses a large active-step tracker; final editor appears only after candidate topics have been identified.
2. **Karaoke captions**: 2–4 on-screen words, progressively revealed and highlighted at their speech times. No permanent subtitle background rectangle; floating text uses dark outline and soft shadow for contrast. Video preview and actual MP4 export use the same deterministic caption timeline.
3. **Word alignment**: asks browser Whisper for `return_timestamps:'word'` where supported; packs word events into meaningful clauses with word arrays. If ONNX lacks word alignment, transparently falls back to segment timestamps and clearly indicates that intra-sentence word placements are interpolated. This improves realism, but word-level ASR stamps still need listening-based validation.
4. **Larger lecturer crop**: logical portrait composition enlarges moving PiP to 315×284 (was 255×204); material grows into the space previously reserved for subtitles; subtitle overlay floats near bottom of materials above presenter, without hiding the whole board behind a permanent card.
5. **Timeline**: public source filmstrip is generated ONLY from frames in the user's own browser and never uploaded. All source time is mapped to kept blue or discarded gray areas. Selecting a blue section selects the corresponding clip. Pointer handles adjust clip start/end; all manual changes invalidate old AI evidence, educational approval and prior scene crop. Scrubbing original track seeks source time. Clicking discarded time and + adds a new reviewable candidate. Re-segmenting from ASR requires confirmation; recompose selected clip runs local OCR scene analysis only.
6. **Progress**: separate large progress panel states prepare → transcribe → topics → montage, with real audio window progress or MP4 encoded frame progress. Unknown stage progress is intentionally indeterminate rather than invented. The cancel button calls the same local AbortController.
7. **Decluttered sidebar**: the relevant primary action is visible in each phase. In results mode advanced recognition settings are folded away but can be reopened; full advanced video and OCR controls remain under disclosure.
8. **Privacy**: no new backend upload. On GitHub Pages hosted static version local Whisper+Tesseract remain on user device; localhost bridge to optional Ollama/PP-OCR is unavailable as before. Third-party model weights still require first-use network download.

## Acceptance
- Pure tests: source clip union, skipped gaps, overlap-safe percent, source scrub clamp, approved status invalidation, karaoke word progress and true Whisper word timestamp usage, timestamp fallback.
- Browser: initial upload-only gate, configure step after private file, results gate after local SRT, seeking in timeline, creating a candidate from a gray gap, on-screen editing.
- Chrome Canvas: rendered bottom-area captions change between spoken phrases while pixels outside caption glyphs remain unchanged; no permanent caption rectangle.
- H.264/AAC standard and high export, confirmed moving enlarged lecturer and browser batch saving to local folder.
- Screenshots desktop / mobile / new source timeline and phone overflow check.

## Not claimed
- Automatic original-face background segmentation or clean alpha matting.
- Verified pedagogy and model generalization across professors/subjects.
- Certified correctness of diagrams, formulas or OCR-based replacement.
- LMS/social analytics/billing.
- Full photorealistic TikTok editing on any uploaded source video with no human QA.
- An accessible public Pages URL until the repository owner enables Settings → Pages → branch gh-pages.

## Next improvement after validation
After the user reattaches the example TikTok/Reels clip, compare its speaker bounding box size, typography, caption placement and transition rhythms at 0s/10s/30s/60s, then adjust style as evidence dictates.
