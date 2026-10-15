# ExamClips completion implementation and release checklist
Date: 2026-10-16.

## Implemented and committed
- [x] 1–3min candidate segmentation, maximum 5min, no 15-second fixed cuts.
- [x] Source speech + visual slide-change combined as *soft* evidence for segmentation.
- [x] Independent local scene recomposition, preserved original diagrams and compact moving lecturer.
- [x] User review workflow with previous-context playback, ±15s manual extension, explicit approval, automatic invalidation on edits, unreviewed files labeled _DRAFT.
- [x] Optional same-computer Ollama/Qwen completeness check with validated literal speech evidence and zero automatic boundary changes.
- [x] Whisper Tiny + optional Whisper Base, 30s chunking, IndexedDB recovery and explicit deletion.
- [x] Browser output at 720×1280/15 or 1080×1920/30 with audio.
- [x] Directory-based sequential batch export of selected microtopics, not server upload.
- [x] Security loopback binding and mocked local Ollama integration tests.
- [x] Automatic F1 evaluation function for independent human-marked reference intervals.
- [x] Separate branch/PR and clean Actions validation against synthetic data.

## Real lecture work done privately, not in public GitHub
- [x] Verify source recording is 3590.34s, 1600×900, H264/AAC; video contains no subtitle stream.
- [x] Visual scan: 449 samples at 8s intervals, 23 possible slide changes, extracted slide headings locally with Tesseract.
- [x] Source-faithful 120s portrait preview of Containers vs. Virtual Machines with original audio and moving presenter, FFprobe and full decode.
- [ ] Complete Whisper ASR of actual hour-long lecture: BLOCKED because private source MP4 is in ChatGPT runtime but not on Windows runner, and the isolated runtime has no ASR model / model download network.
- [ ] Review independent audio-backed microtopic boundaries and render certified self-contained 1–3min episode: BLOCKED pending accurate full transcript and human acceptance.
- [ ] Train distilled specialist model and publish generalization metrics: BLOCKED pending teacher/course-disjoint human-labeled corpus and repeated experiments.

## Reproducible recommended real-world path
1. On local Windows (RTX 5060 Ti), check out this branch and launch START_WINDOWS.cmd. It installs application packages (scripts disabled), makes a local production build and serves http://localhost:5173.
2. Select private MP4 from local Downloads/Videos folder, which never leaves the device.
3. Select RU/EN and Tiny or Base; process full video. Every processed 30-second chunk is saved in IndexedDB and resumes if interrupted. Export SRT/JSON.
4. Optionally scan full video for slide changes; recalculate suggested microtopics (default ~1–3min, max 5min).
5. Select candidate; analyze slide with local OCR; review introductory context and ending with live moving lecturer.
6. Optionally run local Ollama/Qwen explanation-completeness review; read literal evidence and approve/correct suggested bounds.
7. Mark each independently understandable microtopic as approved; export all MP4 into selected folder. Unreviewed ones receive _DRAFT.
8. Record real reviewer ratings and reuse them as ground truth for future small learned boundary model.

## Risk management
Never copy private lecture into a public repository or log. No new models are installed on the Windows self-hosted machine by Github Actions; existing Ollama model intact. Whisper model weights downloaded only after user clicks browser ASR. The native trained ranker is intentionally not represented as completed without labels. Older draft branches remain unmerged.
