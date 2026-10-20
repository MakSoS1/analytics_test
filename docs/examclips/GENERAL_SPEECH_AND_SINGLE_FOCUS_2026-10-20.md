# General sentence boundaries and single-focus composition

This release addresses the v0.10 review: a lesson could begin midway through a
sentence, and simultaneous source panels made the explanatory text too small.

## Default workflow

The app and real-video runner now use `planGeneralTopics`. They do not select
chapters or cuts by filename, dimensions, known Docker timings or a Docker topic
dictionary. The older reference modules remain for regression/comparison only.

- Preserve measured word arrays during normalization and local ASR checkpoints.
- Split at measured sentence ends, not interpolated character timings. When only
  SRT phrase timestamps exist, keep indivisible rows and join unfinished speech;
  do not impose the former 45-second joining limit.
- Combine explicit discourse transitions, sustained vocabulary changes and
  automatically read slide headings. Vocabulary alone is insufficient to split
  an explanation. A graph reference or return to an earlier slide can be a
  continuation, not a new lesson.
- Keep ordered states/steps and continuous examples together. Retain conclusions;
  there is no prescribed output count or maximum lesson duration.
- Title suggestions quote source speech or OCR headings. No topic-specific title
  dictionary is used in the default planner. ASR mistakes are not silently fixed.

For the supplied source, word-aligned small/int8 ASR took 299.3 seconds on CPU
(four threads, Apple M4 / 16 GB; total script time 301.7s with cached weights).
The multi-stage boundary is 1363.87 seconds, beginning with the complete spoken
announcement; the preceding security explanation ends at 1362.40 seconds.
The caching comparison is preserved from 892.04 to 1278.76 seconds. These are
observed outputs, not constants embedded in the algorithm.

## Visual behavior

One source region occupies the main area. No secondary thumbnail, permanent
heading, badge, panel counter or decorative frame is drawn. A title card appears
for 1.2 seconds and fades out over 0.4 seconds, using the continuous lesson clock
so it never restarts at an EDL cut. Source material and the presenter retain their
pixels; white slides are slightly dimmed. The surrounding canvas defaults to a
restrained dark background. Captions remain below the material, separate from
the presenter. Prose crops follow OCR bounds; code and uncertain imagery preserve
source evidence. Diagram edges receive padding rather than clipping text boxes.

## Verification and limitations

174 unit/regression tests and a production build passed locally. Browser tests
cover a single visible source region, opening-only titles (including disjoint
EDL segments), normal import/edit/save/mobile flows, and changing visual focus.
CI repeats these checks before publication. Full exports are inspected separately.

Cross-subject checks include constructed English and Russian biology, finance,
mathematics and architecture cases, plus actual timed public MIT transcripts:

- Calculus, Rate of Change:
  https://ocw.mit.edu/courses/18-01-single-variable-calculus-fall-2006/resources/lecture-1-derivatives/
- Biology, Photosynthesis:
  https://ocw.mit.edu/courses/7-01sc-fundamentals-of-biology-fall-2011/resources/photosynthesis/

The public transcripts are local validation inputs, not bundled course content.
This is an inexpensive local heuristic, not a claim of universal semantic
understanding. Without clear discourse, punctuation or slide headings it may
conservatively retain a longer lesson. Generated proposals stay reviewable;
synthetic tests and two external transcripts do not prove accuracy in every
language, course or teaching style. Browser-only ASR speed and average Windows
hardware have not been benchmarked. No cloud inference or new paid API is required.
