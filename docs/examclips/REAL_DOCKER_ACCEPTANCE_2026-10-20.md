# Real Docker lecture acceptance — 2026-10-20

This change targets `MakSoS1/analytics_test`, the app deployed at
https://maksos1.github.io/analytics_test/. The separate `MakSoS1/examclips`
repository and forgeofeducation.ru are unrelated to this deployment.

## Source and method

The user supplied HAHL2026_Lecture01_Docker.mp4: 3590.341 seconds,
1600×900, 25 fps, H.264/AAC, 65,786,991 bytes. No source copy existed in Git
history or GitHub releases at the time of this audit. The user requested
uploading it; source and rendered videos are release assets, not Git blobs.

Full local transcription used faster-whisper 1.2.1, small/int8, four CPU
threads, beam size 3, VAD, on Apple M4 with 16 GiB memory. Recognition took
272.1 seconds; model loading/download took 51.1 seconds; total script time
324.8 seconds. A base/int8 comparison took 116.9 seconds of recognition,
but technical terms were less reliable. Small also makes errors (e.g. none
can become known); these are original ASR results, not manually rewritten quotes.

The source-verified Docker guide is enabled only for this filename, duration
and dimensions. It is not a generic benchmark and does not establish accuracy
on arbitrary courses. Generic uploads retain the extractive semantic planner.

## Correctness changes

- Export captions use the correct source timestamp in every ten-second decode
  batch, including subsequent disjoint EDL sections.
- ASR line wraps are joined for planning; original transcript/evidence remains
  untouched. Nearby announced transitions can move approximate visual boundaries.
- Apply a verified guide to an entire chapter before lexical refinement;
  otherwise preliminary keyword splits can consume the next topic's setup.
- Keep the caching rule, bad Dockerfile, improved Dockerfile and result together.
- The healthcheck Dockerfile example remains in the lifecycle explanation;
  runtime restart policies are not incorrectly classified as image building.
- Separate host, none and overlay using spoken introductions. Distinguish
  absence of automatic DNS from evidence of a user-defined bridge.
- Preserve visual identities when merging short continuations, and preserve
  existing IDs when retiring redundant guide entries.
- Keep short substantive storage explanations; no fixed output count or maximum
  length is imposed. Recap and audience questions have explicit labels.
- No blind left/right alternation. A sparse source-pixel scan locates content;
  blank halves are excluded. Code, formulas and source imagery retain pixels.
- Two source regions stack vertically with an active primary view and context;
  captions and presenter have separate space. Paused previews stop repainting.

## Reproducing the local workflow

Install Python, FFmpeg, Tesseract (English data), Node 22+, and Chrome.
Use an isolated Python environment, then `pip install faster-whisper==1.2.1`.
Initial public model downloads require Internet; audio is processed locally.

From `examclips-local`:

```sh
python scripts/transcribe-private-lecture.py --video /path/HAHL2026_Lecture01_Docker.mp4 --out /path/results/asr --model small --language en --threads 4
npm ci --ignore-scripts --no-audit --no-fund
npm run dev
# In another terminal; set CHROME_PATH to the local Chrome executable if needed:
node scripts/render-real-lecture.mjs /path/HAHL2026_Lecture01_Docker.mp4 /path/results/asr/lecture-transcript.json /path/results/video all
node scripts/audit-real-lecture.mjs /path/results/asr/lecture-transcript.json /path/results/audit
```

The renderer uses the application's planner, scene model, composition and
WebCodecs exporter. This acceptance runner uses native Tesseract and a reviewed
presenter location for this source; the ordinary app uses browser/optional local
OCR and automatic presenter detection. `lecture-project.json` imports into the
existing editor and can be attached to the original local MP4. SRT can also be
imported directly. Native Whisper time is not a measurement of browser WASM ASR.

## Attention and learning

The practical choices are a specific title immediately, one explanatory
question, readable source material, speech-synchronised captions and meaningful
focus changes. Avoid fabricated claims, arbitrary crop alternation and forcing
an unfinished explanation into a duration quota.

YouTube's creator discussion recommends a strong first-second hook and compact
stories: https://blog.youtube/creator-and-artist-stories/youtube-shorts-deep-dive/
TikTok's 2025 SMB playbook recommends communicating value in the first 3–6
seconds: https://ads.tiktok.com/business/library/TikTok_SMB_Creative_Playbook_2025.pdf
These are creator/advertising recommendations, not controlled evidence that
retention or student learning will improve for this lecture. Such claims require
learner tests. Long complete explanations remain vertical lessons; they are not
all platform-length Shorts.

## Verification scope

157 deterministic tests and production build passed. Atlas UI/mobile/project/
playback checks, 720p/1080p exports and editorial visual checks passed locally.
The final real-source run produced 27 MP4 files (720×1280, AAC audio), totalling
3164.87 seconds, with no browser errors. Scene analysis took 32.28 seconds and
rendering 172.41 seconds; complete renderer elapsed time was 207.29 seconds.
Together with small/int8 recognition this is 479.4 seconds (7m59s), or 532.1
seconds (8m52s) including the measured first model setup. These are sequential
stage measurements on the M4, not a browser-only or average-PC benchmark.
All 27 outputs passed stream/duration checks. Visual inspection sampled frames;
it is not a claim that every second was watched. The intact caching explanation
lasts 378.7 seconds; source completeness takes priority over Shorts length.
All automatically proposed lessons retain review status. Keyword coverage and
synthetic tests do not certify pedagogical completeness or ASR accuracy.
Performance on an average Windows PC and browser-only full ASR remains unmeasured.
