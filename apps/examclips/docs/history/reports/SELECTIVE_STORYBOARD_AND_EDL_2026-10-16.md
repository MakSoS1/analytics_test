> Исторический документ: описывает состояние на дату написания. Текущие инструкции — в [индексе документации](../../README.md).

# ExamClips v0.8 — selective educational stories and nonlinear editing
Date: 2026-10-16. User-supplied references were reviewed privately, not committed.

## Two real reference videos
- Reference 1: 53.22 seconds, portrait 720×1280/30 FPS, H264/AAC, female lecturer alternate with source-native Docker, Kubernetes, CI/CD, load balancer, PostgreSQL, Prometheus/Grafana/Loki diagrams. Rapid visual speaker/subject switching and small direct-on-video captions.
- Reference 2: 100.97 seconds, portrait 720×1280/30 FPS, H264/AAC, male lecturer alternate with research paper screenshot, enlarged percentages, agent/harness blocks, tabular results and diagrams. On-video animated emphasis captions.
- Finished shorts cannot prove which timestamps their source authors discarded or whether the cuts are nonconsecutive. No automated full transcript for these reference files was claimed.

## Change in product objective
- BEFORE: ASR -> partition almost all lecture -> consecutive 1–3min short videos. User rejected forced use of irrelevant and silent portions.
- NOW: ASR/phrase timestamps -> semantically suggestive candidate windows -> rank explanations/example/result density and subtract repetitive, organizational and silent content -> select only the top useful minority (15/30/50% MAX source duration, not a target) -> optionally group topic-related distant excerpts -> human review -> nonlinear MP4.
- Zero suggested highlights is a valid outcome. No force-fill and no guarantee that 1hr produces any given number of short clips.

## Browser-only selection — evidence and limitations
- Implemented in src/selective-stories.js: language-aware token matching, simple inflection normalization, explanatory cues, pauses, technical specificity and organizational filler penalty. Candidate groups are automatically marked needs-review.
- Source speech time gaps > about 1.15 seconds within a candidate can become hard edit points; normal short breathing gaps remain. This depends on ASR/SRT timestamp quality, NOT actual verified sample-accurate VAD.
- Distant parts can be proposed for the same microtopic if literal subject terminology overlaps. This is a heuristic, not proven true semantic coherence, multilingual embedding or educational QA.
- Ranking scores are not calibrated probabilities and should not be sold as tested intellectual-interest predictions.

## Optional private local LLM second pass
- src/story-review.js + localhost-only Vite bridge to existing Ollama; no new models installed by the app.
- The model receives bounded candidate TRANSCRIPT TEXT only, precise source times, opaque candidate IDs and a strict output schema.
- Each selected part requires a contiguous literal quote proven to occur in its source text. Fabricated quotes/IDs, oversize requests or budgets are rejected; zero acceptable stories is allowed.
- Request requires explicit user consent, and returned stories remain needs-review. The path does not exist on static GitHub Pages; there the browser-only heuristic still works.
- A mocked local model contract test validates endpoint behavior, not real-model editorial reasoning quality.

## Source EDL and final MP4
- Each story contains an array of editable source pieces. The user can reorder, remove and append pieces from otherwise discarded lecture time.
- The source stays untouched. Selected pieces are decoded independently in playback order with uninterrupted destination presentation timestamps.
- Original AAC speech is decoded and trimmed for the same source slices, retimestamped without the source gaps; output uses H.264/AAC MP4.
- An optional per-piece OCR scene is generated only from that piece. Original scene pixels remain the fallback.
- Any trim, reorder or membership change invalidates approval, LLM evidence and source-based scene composition.
- Synthetic browser proof: sections 0.0–1.3 and 2.2–3.7 sec of 4 sec fixture, one exported MP4 ~2.84 sec with real H264 video and AAC audio, full FFmpeg decode. Run scripts/noncontiguous-edl-smoke.mjs.

## UI and privacy
- Fullscreen timeline remains primary: blue sparse kept segments vs gray source gaps, local frame contact strip, draggable handles, restored excerpts and a dedicated list for ordering source pieces.
- User controls desired minimum clip length and maximum editorial percentage before loading/transcribing, never on timeline.
- Model weights may require first-use public download; video and audio remain on visitor device. Ollama is localhost-only; no video remote upload.

## Acceptance limitations
- Synthetic tests and two already-edited reference shorts are NOT enough to certify real-lecture interestingness or self-containedness.
- Next benchmarks require full raw multi-subject lectures, lecturer-disjoint human labels of which moments should be used, selected-source ratio, precision/recall for useful spans, coherent multi-part narratives, video/source frame alignment, false cuts, and sample-accurate speech synchronization.
- No SaaS publishing metrics, billing, LMS, remote storage or automated concept understanding benchmark is claimed.

Branch: feat/examclips-selective-story-edl-20261016. Main remains untouched.