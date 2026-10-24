# Скрипты ExamClips

Запускайте из `apps/examclips/`. Эти файлы используют его `src/`, `public/`,
локальные fixtures и npm-зависимости. Fixture-генерация и полный браузерный прогон
описаны в корневом `.github/workflows/examclips-local-mvp.yml`.
Подготовка окружения: [development.md](../docs/development.md).

| Группа | Скрипты |
| --- | --- |
| UI, мастер и проекты | `atlas-ui-smoke.mjs`, `atlas-project-flows-smoke.mjs`, `atlas-editing-playback-smoke.mjs`, `mvp-ui-smoke.mjs`, `library-zoom-resume-smoke.mjs` |
| ASR и кэш | `asr-checkpoint-smoke.mjs`, `whisper-smoke.mjs`, `whisper-base-smoke.mjs` |
| Звук, экспорт и композиция | `audio-compat-smoke.mjs`, `browser-smoke.mjs`, `noncontiguous-edl-smoke.mjs`, `stream-edl-smoke.mjs`, `batch-export-smoke.mjs`, `presenter-motion-smoke.mjs`, `single-focus-smoke.mjs`, `karaoke-overlay-smoke.mjs`, `editorial-visual-smoke.mjs` |
| Микротемы и локальный review | `microtopics-table-smoke.mjs`, `long-worked-example-smoke.mjs`, `sparse-lecture-smoke.mjs`, `local-review-smoke.mjs` |
| OCR и optional Python worker | `ocr-browser-smoke.mjs`, `local-ocr-browser-smoke.mjs`, `ocr_model_benchmark.py`, `rapidocr_local.py` |
| Реальная лекция | `transcribe-private-lecture.py`, `render-real-lecture.mjs`, `audit-real-lecture.mjs` |

`rapidocr_local.py` — runtime worker локального моста; это не только тест.
`whisper-*.mjs` и OCR benchmark могут скачивать публичные веса и идти заметно
дольше обычных регрессий. Не запускайте полную расшифровку повторно для правки
README или путей, если unit/build/browser checks покрывают изменение.

Native ASR/renderer принимают пути к видео, транскрипту и результатам. Видео
не должны становиться Git blobs. Примеры команд — в development guide;
качество и границы измерений — в [quality.md](../docs/quality.md).
