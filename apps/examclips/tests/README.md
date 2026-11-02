# Проверки движка

`npm test` из `apps/examclips/` выполняет `node --test tests/*.test.mjs`.
Здесь детерминированные unit- и regression-тесты без пользовательских MP4.
Браузерные end-to-end сценарии находятся в [scripts/](../scripts/README.md).

- Речь и планирование: `general-speech`, `segments`, `complete-topics`,
  `lecture-*`, `docker-*`, `topic-editorial-guardrails`, `word-align`.
- Сцены и читаемость: `single-focus`, `scene-model`, `slide-*`, `speaker-motion`,
  `editorial-motion`, `lesson-screenplay`, `caption-flow`.
- Состояние/покрытие: `asr-checkpoint`, `project-library-snapshot`, `atlas-range`,
  `source-timeline`, `topic-evaluation`.
- Локальные инструменты: `local-ocr-bridge`, `completion-review`, `story-review`.

Docker-specific тесты сохраняют регрессии и сравнение старых методов. Они не
означают, что рабочий планировщик должен распознавать лекцию по имени файла.
ASR/OCR fidelity, фактический MP4 и педагогическую полноту нельзя удостоверить
одними unit-тестами: [quality.md](../docs/quality.md).
