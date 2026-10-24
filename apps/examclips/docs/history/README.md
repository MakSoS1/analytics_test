# История ExamClips

Эти материалы объясняют развитие проекта и прежние результаты. Они **не заменяют**
[текущую документацию](../README.md). Нельзя применять старые ограничения,
таймкоды или композицию только потому, что они описаны в архиве.

| Каталог | Содержимое |
| --- | --- |
| [reports/](reports) | Отчёты о выпусках, проверках лекции, UI и композиции |
| [plans/](plans) | Планы прежних этапов разработки |
| [specs/](specs) | Прежние проектные решения |
| [workflows/](workflows) | Специализированные экспериментальные OCR/Whisper workflow; архив, автоматически не выполняется |
| [Прежний README приложения](README_BEFORE_ORGANIZATION_2026-10-24.md) | Снимок инструкции до группировки репозитория |

Порядок чтения для истории нарезки:

1. [Прежний прогон Docker v0.10](reports/REAL_DOCKER_ACCEPTANCE_2026-10-20.md):
   27 видео, Docker-specific guide и прежняя композиция.
2. [Общие границы и одна область v0.11](reports/GENERAL_SPEECH_AND_SINGLE_FOCUS_2026-10-20.md):
   предметно независимый default planner, word timestamps, один кадр и широкая вебка.
3. v0.11.1: фактическая проверка AAC и Web Audio fallback;
   актуальное описание в [troubleshooting.md](../troubleshooting.md).
4. [Подключение бесплатного домена](reports/CUSTOM_DOMAIN_2026-10-24.md):
   команды содержат прежний путь. Текущая публикация — [deployment.md](../deployment.md).

Старые пути: `examclips-local/` → `apps/examclips/`,
`docs/examclips/` → `apps/examclips/docs/history/reports/`,
`docs/superpowers/` → `apps/examclips/docs/history/{plans,specs}/`.
Для воспроизведения старого release checkout его тег: не смешивайте его paths,
сценарии и количество выходных роликов с текущим кодом.
