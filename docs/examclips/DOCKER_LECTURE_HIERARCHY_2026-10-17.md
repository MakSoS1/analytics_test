# Docker lecture as a hierarchy of chapters and completed microtopics

## Input studied

Private user upload `HAHL2026_Lecture01_Docker.mp4`, 1600×900, H.264/AAC,
3590.341 sec (~59:50). The original file stays outside the repository.
The analysis inspected sampled ORIGINAL frames every 90 seconds plus close-up
screenshots at 00:08, 00:30, 01:00, 02:00, 05:00, 10:00, 20:00, 30:00,
45:00 and 58:00. This is enough to verify visually the large chapter sequence,
but **not** to derive word-exact edit points or certify what was spoken.

### Chronological chapter guide (visually observed, approximate)

| Approx. time | Visual source topic | Editing decision |
|---|---|---|
| 00:00–03:48 | Lecture 1 title, **About me**, **Lecture 1 brief**, introductory analogy | Exclude as course introduction (for THIS exact video reference) |
| 03:48–08:10 | Containers vs Virtual Machines; infrastructure comparison | Separate “what is a container” from “how it differs from a VM” when supported by speech |
| 08:10–10:12 | Docker Architecture & Image Model, daemon, CLI, containerd | Architecture lesson |
| 10:12–12:50 | Image layers, stacking, caching | Images/layers lesson |
| 12:50–20:55 | Production-grade Dockerfile, builds, cache | Separate Dockerfile, caching and build optimizations as supported |
| 20:55–23:55 | Image safety and production build practices | Separate when speech supports a self-contained lesson |
| 23:55–30:50 | Container lifecycle, stop/kill, health, diagnostics | One or more coherent lessons; source-driven |
| 30:50–35:50 | Dockerfile practical examples | Distinct practical chapter; preserve full worked solution |
| 35:50–39:55 | Volumes, bind mounts, statelessness | Separate durable storage mechanisms when explained |
| 39:55–50:30 | Docker Networking, bridge/host/none/overlay | Several related but distinct network concepts |
| 50:30–54:00 | Resources and limits | Container resources lesson |
| 54:00–55:10 | Conclusion | Keep only if there is new informative speech, otherwise mark recap |
| 55:10–59:50 | Networking slide reused | Flag possible recap; do not drop meaningful new speech just due same slide |

The cut points are visual anchors in seconds, **not authoritative clip boundaries**.
Docker-specific anchors are enabled only for a video whose filename, frame
geometry AND duration match the inspected source. Other lectures use general
local OCR of changed slide headings instead of matching a filename.

## Algorithm (v1.1)

1. Full local Whisper/SRT speech data in source time; original video never uploaded.
2. Lecture chapter outline: known verified visual reference for this exact Docker
   upload, otherwise sampled-slide OCR (bounded to <=70 changed frames).
3. Strong rejection of lecture title, teacher bio, course brief, schedule, small
   introductions. A technological keyword in an agenda DOES NOT imply teaching.
4. Within each chronological chapter, identify sustained changes in explained
   concepts (Docker bridge != overlay, container definition != VM comparison),
   explicitly announced transitions and repeated lexical context shifts.
5. Do not clip an active step-by-step worked problem solely for duration reasons.
6. For each proposed lesson create a compact source-linked screenplay:
   definition, mechanism, concrete example, conclusion (only if spoken).
   Each claim exposes exact start/end and verbatim quote; if completion lacks
   evidence, show a warning and keep it unapproved.
7. Gallery shows genuine source frames, separate cards per microtopic grouped
   by chapter; clicking opens scenario, detailed original transcript, editable
   source cuts and live 9:16 preview. Non-contiguous pieces are played in order
   without accidentally playing removed lecture gaps.
8. Browser project autosave retains chapters and draft changes, guards against
   a background OCR scan replacing manual edits, and supports reanalysis.

## Explicit verification limits

- A complete 59:50 audio ASR and human-ground-truth segmentation **have not**
  been executed in this environment. There is no downloaded Whisper/ASR model
  and no internet model download. CI uses synthetic English/Russian transcripts
  aligned to the inspected chapter timeline; it cannot certify microtopic
  precision/recall on the real audio. Users can run full local Whisper in
  the browser (or import accurate full-length SRT) to validate exact cuts.
- The short scenario is currently a **source-backed extractive summary**, not
  an invented narration or LLM-certified semantic paraphrase. Quotes and
  captions are source-grounded. Optional local Ollama review remains available
  when launched locally; not on static GitHub Pages.
- Thirty minutes for complete 60-minute ASR+chapter indexing is a performance
  **target**, not a verified upper bound. Actual time depends on browser,
  WebGPU support, Whisper model and device. The app saves checkpoints so
  interrupted ASR can resume without recomputing completed 30s windows.
- Draft 9:16 rendering is live in the browser; a finished MP4 is produced when
  the user explicitly exports the clip (no pre-rendered hour of videos is
  claimed merely on selecting a lecture).

## Test suite

- `tests/docker-outline.test.mjs`: exact video identity, chronological intro
  exclusion, chapter-specific Docker subtitles, source-backed script, sparse
  speech refusal, and 20-minute worked solution preservation.
- `tests/lecture-semantics.test.mjs`: biography and technology-agenda rejection.
- `scripts/microtopics-table-smoke.mjs`: UI image gallery, card navigation,
  verified source quote links, original timecoded transcript, portrait player.
- Existing browser export, source timeline, save/reload, layout and audio tests.
