# ExamClips — Lecture library, persistent edit projects, script verification and zoomable timeline
Updated: 2026-10-17

## UX flow
1. On the upload/home screen show **previously processed lectures**, local file picker, analysis settings. Each history card shows filename, updated date, source duration and number of microtopics. Actions: Continue, Delete.
2. After local ASR/SRT analysis, show the fullscreen 16:9 source / 9:16 output editor and the central timeline. Header offers **← Все лекции**. Going back flushes any pending autosave and safely releases the old source file.
3. Timeline toolbar includes 1×–24× zoom, −/+ and Fit. The entire ruler, source filmstrip, source playhead, blue keep / gray reject pieces share the same horizontal scrollable canvas. Timecode trim conversion is still exact and independent of zoom. Zoom/scroll and the selected editor tab persist with the project.
4. Montage tab contains an evidence-only **screenplay**: source transcription quote, source time and role (question/introduction, explanation, takeaway). The system checks for actual instructional explanations and whether it found a conclusion. Uncertain candidates need manual review before full-lecture export. An explicitly user-approved clip may still be exported.
5. Docker/technical lecture intros like lecturer biography, course schedule, microphone checks are excluded before selecting topical clips. Heuristics may still err; mark proposed outlines for review. No model should invent lecture content or an unsupported result.
6. Keep all worthwhile teaching segments; a 20+ minute complete worked problem stays one clip and uses stream-to-disk output in browsers that support it. No ratio or fixed maximum instructional duration is imposed.

## Storage contract and limitations
- **Always try to save project metadata** into origin-scoped IndexedDB: original fingerprint (name, size, modified), duration, transcript, visual scene cuts, EDL with ordered source pieces, approvals, source-backed screenplay, selected clip, active tab and zoom/scroll. Autosave is debounced after edits and flushed when navigating back or tab becomes hidden.
- Store the selected project's ID in origin-scoped localStorage. A reload can automatically reopen small original files copied into a separate IndexedDB store (at most 64 MiB, only if estimated quota is sufficient).
- **Long user lectures are not copied** into app storage: reopening shows the project in the library and asks to reselect the identical original. On supporting browsers, the user can explicitly associate a FileSystemFileHandle via a native picker to resume with permission. File identity is verified before attaching saved timecodes to a source.
- This is not a server-side cloud backup, and browser storage can be cleared or evicted. Private mode and sites that block IndexedDB can disable persistence; the UI must show an error rather than pretend a save succeeded. Exporting a JSON backup remains possible.
- Original lectures are never sent to GitHub, the static hosting provider, or the model server. Public ASR/OCR model weights may be downloaded on first use.

## Verification
- Pure unit tests: Docker lecturer-intro exclusion, fully derived evidence-only screenplay, no invented topic, complete 20min exercise, project snapshot validation.
- Chrome: 4s source + imported SRT → edit title → zoom 8× → automatic local save → reload same origin → restore exact title/zoom → back to history → Continue original → editor reload without ASR re-run.
- Existing complete MP4 H264/AAC, enlarged lecturer motion, progressive captions, multi-source EDL and 1080p output regression should stay green.
- Docker-like synthetic 180s lecture: initial biography and scheduling (0–9s) must not appear in keep track; instructional segments later should remain, including very late content.
- Real subject/topic usefulness remains an **unvalidated** quality metric until human-labeled long-lecture testing. Caption word timing and formula reading also require visual/audio QA.

## Launch
Branch: feat/examclips-library-zoom-storyboard-20261017 (stacked on feat/examclips-complete-topics-longform-20261017). GitHub Pages remains a prepared static hosting target, but public activation is dependent on repository Pages settings. For local Windows use examclips-local/START_WINDOWS.cmd; prepared static CI build can be downloaded as a workflow artifact.
