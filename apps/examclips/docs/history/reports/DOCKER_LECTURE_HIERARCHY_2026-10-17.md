> Исторический документ: описывает состояние на дату написания. Текущие инструкции — в [индексе документации](../../README.md).

# Docker lecture as a hierarchy of chapters and completed microtopics

## Input studied

Private user upload `HAHL2026_Lecture01_Docker.mp4`, 1600×900, H.264/AAC,
3590.341 sec (~59:50). The original file stays outside the repository.
The analysis inspected sampled ORIGINAL frames every 90 seconds plus close-up
screenshots at 00:08, 00:30, 01:00, 02:00, 05:00, 10:00, 20:00, 30:00,
45:00 and 58:00. This is enough to verify visually the large chapter sequence,
but **not** to derive word-exact edit points or certify what was spoken.

### Chronological chapter guide (rechecked against source OCR)

I decoded a 25-second sample grid from the actual 59m50s MP4 and ran
local Tesseract OCR against the original slide headings. The *observed
sample checkpoints* are 04:10 **Intro**, 04:35 **Containers vs. Virtual
Machines**, 09:10 **Docker Architecture & Image Model**, 13:20
**Dockerfile: Production-Grade Images**, 24:10 **Container Lifecycle &
Health**, 31:40–36:15 intermittent Dockerfile/Lifecycle examples,
36:40 **Storage — Volumes, Bind Mounts & Statelessness**, 40:00
**Docker Networking**, 50:25 **Resource Isolation & Limits**, 53:20
**Conclusion**, and 55:50 a **Docker Networking** slide again.

| Approx. time | Visually observed source chapter | Decision |
|---|---|---|
| 00:00–04:35 | Title, About me, Lecture 1 brief, Intro | Exclude the noninstructional introduction for THIS exact file |
| 04:35–09:10 | Containers vs. Virtual Machines | Separate definition of container from explicit comparison where speech supports both |
| 09:10–13:20 | Docker Architecture & Image Model | Separate Docker daemon/engine and image-layer explanation by ASR evidence |
| 13:20–24:10 | Dockerfile: Production-Grade Images | Keep distinct instructions, build caching, optimizations, concrete demonstrations |
| 24:10–31:40 | Container Lifecycle & Health | Lifecycle, SIGTERM/SIGKILL, health checks |
| 31:40–36:40 | Interleaved Dockerfile and Lifecycle slides | Verify spoken context, preserve full continuous practical exercises |
| 36:40–40:00 | Storage — Volumes, Bind Mounts & Statelessness | Separate durability and mounting mechanism explanations |
| 40:00–50:25 | Docker Networking | Different concepts: bridge, host, none, overlay |
| 50:25–53:20 | Resource Isolation & Limits | CPU/memory/cgroups |
| 53:20–55:50 | Conclusion | Only keep source-supported new learning; no redundant outro short |
| 55:50–59:50 | Docker Networking slide revisited | Flag potential repeat but use speech to decide whether useful |

The sampled images provide **slide category evidence only**: a slide may
stay on screen before or after the teacher discusses its subject. Word-exact
clip in/out points require a complete aligned transcript.

The cut points are visually verified chapter anchors, **not authoritative speech boundaries**.
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
  the user explicitly exports the clip. Small exports additionally open as a
  playable local MP4 in the selected microtopic; large disk-streamed exports
  can be reopened from disk.

## Test suite

- `tests/docker-outline.test.mjs`: exact video identity, chronological intro
  exclusion, chapter-specific Docker subtitles, source-backed script, sparse
  speech refusal, and 20-minute worked solution preservation.
- `tests/lecture-semantics.test.mjs`: biography and technology-agenda rejection.
- `scripts/microtopics-table-smoke.mjs`: UI image gallery, card navigation,
  verified source quote links, original timecoded transcript, portrait player.
- Existing browser export, source timeline, save/reload, layout and audio tests.
