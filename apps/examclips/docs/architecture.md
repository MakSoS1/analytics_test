# Архитектура и карта кода

ExamClips — статическое Vite SPA на JavaScript/CSS, без обязательного backend,
аккаунтов, Supabase или SSR. Публикуются только файлы `dist/`. Текущая интерфейсная
оболочка — Atlas. `src/main.js` связывает интерфейс, состояние и пайплайн;
`index.html` загружает его как entry point.

## Поток обработки

1. Пользователь выбирает локальное видео. `media.js` открывает контейнер через
   Mediabunny. `audio-compat.js` проверяет фактическое декодирование звука;
   для проблемного AAC доступен Web Audio/ADTS fallback порциями до 30 секунд.
2. `asr.js` получает аудио и выполняет Whisper через Transformers.js на устройстве.
   `asr-checkpoint.js` хранит прогресс. Альтернатива — импорт SRT или проект JSON.
3. `slide-cuts.js` и `slide-chapter-index.js` находят репрезентативные изменения
   изображения; OCR извлекает текст/геометрию. Это не покадровый OCR всей лекции.
4. `general-topics.js` группирует завершённые предложения и смены вопроса.
   `speech-boundaries.js` использует реальные word timestamps, если они есть;
   строка SRT остаётся неделимой. `topic-editorial-guardrails.js` убирает дубли
   и пересечения источника. `lesson-screenplay.js` добавляет структуру сцен.
5. Пользователь проверяет микротемы, границы, сцены и субтитры. Данные проекта
   сохраняются в IndexedDB через `project-library.js`.
6. `composition.js` рисует предпросмотр и экспорт. `render.js` собирает H.264/AAC
   MP4 из выбранных source/EDL-сегментов с исходным звуком.

## Где искать изменение

| Задача | Файлы в `src/` |
| --- | --- |
| Мастер, импорт/экспорт проекта, состояние редактора | `main.js` |
| Библиотека, интерфейс Atlas, каталог и выделение диапазона | `atlas-shell.js`, `atlas-panels.js`, `microtopic-catalog.js`, `atlas-range.js` |
| Стили интерфейса | `styles.css`, `atlas.css`, `atlas-catalog.css` |
| Текущий общий планировщик | `general-topics.js`, `speech-boundaries.js`, `topic-editorial-guardrails.js` |
| Нормализация речи, временные сегменты | `segments.js`, `word-align.js`, `selective-stories.js` |
| Whisper, тихое аудио, кэш распознавания | `asr.js`, `audio-utils.js`, `asr-checkpoint.js` |
| Контейнер, кадры, совместимость AAC | `media.js`, `audio-compat.js` |
| Слайды, OCR, визуальные области, вебка | `slide-cuts.js`, `slide-chapter-index.js`, `slide-context.js`, `scene-analysis.js`, `speaker-motion.js` |
| Сценарий, выбор областей и их геометрия | `lesson-screenplay.js`, `scene-model.js`, `editorial-motion.js` |
| Рисование видео и титров | `composition.js`, `caption-flow.js` |
| Экспорт, batch и streaming | `render.js` |
| Покрытие лекции, таймлайн, оценка по ручной разметке | `coverage-inspection.js`, `source-timeline.js`, `topic-evaluation.js` |
| Необязательная локальная LLM-проверка и тесты по лекции | `completion-review.js`, `story-review.js`, `quiz.js` |

`main.js` импортирует `planGeneralTopics` под именем `planCompleteTopics`.
Это **не** вызов старого `complete-topics.js`. Модули `lecture-outline.js`,
`lecture-semantics.js`, `semantic-subtopics.js`, `visual-subtopic-hints.js`,
`microtopics.js` и прежние планировщики сохранены для сравнений/регрессий и
вспомогательных задач. Не следует включать известные Docker-таймкоды в основной
путь только потому, что они есть в коде и тестах.

## Состояние и границы доверия

- Исходные MP4 читаются с устройства. IndexedDB хранит проекты и ASR checkpoints;
  localStorage — небольшие настройки/идентификатор последнего проекта.
- JSON проекта переносит разметку, речь и настройки; исходное видео нужно хранить
  отдельно и при необходимости повторно привязать. Записи зависят от origin.
- Пользовательская речь, OCR и импортированные документы — данные, а не команды.
  Автоматические предложения остаются проверяемыми пользователем.
- На GitHub Pages нет `/api/local-*`: optional Ollama/RapidOCR работают только при
  локальном Vite dev/preview. Реализация: `vite.config.js`, `local-ocr-bridge.js`,
  `scripts/rapidocr_local.py`. Транспорт ограничен loopback, проверяет Origin/размеры.
- Публичные модели скачиваются отдельно. Наличие сайта в сети не доказывает
  доступность хостинга весов или скорость распознавания.

Сценарии проверки: [development.md](development.md). Точные ограничения качества:
[quality.md](quality.md).
