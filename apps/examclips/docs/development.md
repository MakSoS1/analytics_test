# Разработка и проверки

Все команды ниже выполняются из `apps/examclips/`. Используйте исходную ветку
`feat/examclips-library-zoom-storyboard-20261017`, а не `main`.
Зависимости фиксируются `package-lock.json`.

## Основной запуск

Нужен Node.js 22.12+ или 24 LTS (CI использует Node 22).

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run dev
```

Сервер привязан к `127.0.0.1`; адрес напечатает Vite. Если 5173 занят,
Vite может выбрать другой порт. Некоторые acceptance-скрипты ожидают 5173:
освободите его или используйте `EXAMCLIPS_ORIGIN`, если скрипт поддерживает эту
переменную. Не открывайте production HTML через `file://`.

Windows: `START_WINDOWS.cmd` самостоятельно устанавливает JS-зависимости при
необходимости, собирает приложение и запускает preview на порту 5173.
Его относительные пути работают из нового каталога.

## Базовая проверка и сборка

```sh
npm test
EXAMCLIPS_BASE=./ npm run build
npm run preview
```

В PowerShell задайте `$env:EXAMCLIPS_BASE='./'` перед `npm run build`.
Сборка — `dist/`. `public/CNAME` должен попасть в `dist/CNAME` без изменений.
Режим dev содержит optional локальные мосты; hosted production их не содержит.

## Браузерные регрессии

Используются Chrome с H.264/AAC, FFmpeg и `playwright-core` из npm-зависимостей.
Если Chrome не найден, укажите `CHROME_PATH`; конкретные скрипты имеют разные
пути поиска, поэтому Linux CI — воспроизводимый полный прогон.
Основные сценарии и имена скриптов: [scripts/README.md](../scripts/README.md).

GitHub Actions:

| Workflow | Что проверяет |
| --- | --- |
| `examclips-local-mvp.yml` | Unit/build, UI и mobile, projects, AAC fallback, экспорт, сцены и browser OCR на синтетических fixture |
| `examclips-storage-qa.yml` | Автосохранение, возврат в библиотеку, reload и редактирование проектов |
| `examclips-gh-pages-branch.yml` | Unit/build и публикация только исходной ветки сайта |

Оба PR workflow запускаются на изменениях приложения. Их YAML находится в
корневой `.github/workflows/`, working directory — `apps/examclips/`.
Старые специализированные OCR/Whisper workflow с экспериментальными ветками
сохранены в [истории workflow](history/workflows); они не выполняются автоматически.

Не публикуйте пользовательские лекции в CI. Видео/аудио fixtures там создаются
FFmpeg. Прохождение синтетического теста не доказывает качество любой лекции.

## Необязательный RapidOCR

Для обычного браузера Python не нужен: работает Tesseract.js. На Windows
`INSTALL_OCR_WINDOWS.cmd` устанавливает RapidOCR/ONNX Runtime в `.ocr-venv/`
рядом с приложением. Для других систем можно создать отдельное Python-окружение
и указать путь к его Python через `EXAMCLIPS_OCR_PYTHON` перед запуском Vite.
Используемые семейства моделей и параметры установки — в этом CMD-файле и
`scripts/rapidocr_local.py`; не меняйте существующие окружения CUDA/PyTorch ради OCR.
Публичные веса могут скачиваться при первом обращении.

Локальная Ollama обнаруживается на `127.0.0.1:11434`, если уже установлена с
подходящей моделью. Для обычного пути она не обязательна, новые веса LLM приложение
само не устанавливает. Hosted версия использует браузерные возможности.

## Native ASR и реальная лекция

Это отдельный диагностический путь, а не измерение browser WASM ASR.
Нужны Python, FFmpeg; для render acceptance также Chrome и Tesseract с English.
В отдельном окружении установите `faster-whisper==1.2.1`.

```sh
python scripts/transcribe-private-lecture.py --video /path/lecture.mp4 --out /path/results/asr --model small --language auto --threads 4
# После запуска npm run dev на порту 5173, в другом терминале:
node scripts/render-real-lecture.mjs /path/lecture.mp4 /path/results/asr/lecture-transcript.json /path/results/video all
node scripts/audit-real-lecture.mjs /path/results/asr/lecture-transcript.json /path/results/audit
```

ASR пишет JSON с `rows` и measured `words`, SRT и метаданные времени/устройства.
Renderer использует планировщик и экспорт приложения, но его тестовая настройка
вебки ориентирована на проверенную Docker-лекцию. Для другой лекции проверяйте
геометрию, а не считайте acceptance runner универсальной настройкой камеры.
Укажите реальный путь к Chrome в `CHROME_PATH`, если требуется.

Сохраняйте результаты вне Git, например в игнорируемом `artifacts/`.
Исходники и веса не входят в deploy. Локальные мосты не нужно открывать в сеть.
