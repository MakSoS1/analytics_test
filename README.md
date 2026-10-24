# analytics_test — ветка ExamClips

> **Вы на ветке сайта нарезки лекций.** Основной проект репозитория находится
> в `main` и не связан с ExamClips. В `main` этот сайт не переносится.

**Сайт:** https://examclips.dpdns.org/  
**Исходная и публикационная ветка:** `feat/examclips-library-zoom-storyboard-20261017`  
**Код приложения:** [apps/examclips](apps/examclips/README.md)

Новый агент: начните с [AGENTS.md](AGENTS.md), затем прочитайте
[README приложения](apps/examclips/README.md) и
[карту кода](apps/examclips/docs/architecture.md).
При передаче проекта давайте ссылку именно
[на эту ветку](https://github.com/MakSoS1/analytics_test/tree/feat/examclips-library-zoom-storyboard-20261017/apps/examclips),
а не на корень репозитория, который по умолчанию открывает `main`.

## Запуск сайта нарезки

```sh
git clone --branch feat/examclips-library-zoom-storyboard-20261017 --single-branch https://github.com/MakSoS1/analytics_test.git
cd analytics_test/apps/examclips
npm ci --ignore-scripts --no-audit --no-fund
npm run dev
```

Нужен Node.js 22.12+ или 24 LTS. Точный адрес и порт напечатает Vite.
Для Windows доступен `apps/examclips/START_WINDOWS.cmd`.

## Карта этой ветки

| Каталог | Назначение |
| --- | --- |
| [apps/examclips](apps/examclips/README.md) | Самостоятельное Vite-приложение нарезки: код, тесты, скрипты и документация |
| [.github/workflows](.github/workflows) | Общие workflow репозитория; только три `examclips-*` относятся к текущему сайту |
| [.agents/skills/examclips-editorial](.agents/skills/examclips-editorial/SKILL.md) | Инструкции по композиции видео ExamClips |
| [docs/legacy/ANALYTICS_EXERCISES.md](docs/legacy/ANALYTICS_EXERCISES.md) | Прежний корневой README с заданиями по SQL/Python |
| `3.ipynb`, `4.ipynb`, `cover-channel-lab/`, `monitor/`, `*_probe_result/` | Другие материалы репозитория; не зависимости и не исходники ExamClips |

Приложение раньше лежало в `examclips-local/`, отчёты — в `docs/examclips/`,
планы — в `docs/superpowers/`. Всё, относящееся к нему, теперь собрано под
`apps/examclips/`; старые документы помечены как история.

Публикация остаётся на GitHub Pages через `gh-pages`.
Инструкции: [deployment.md](apps/examclips/docs/deployment.md).
Отдельный проект `MakSoS1/examclips` / `forgeofeducation.ru` к этому сайту
нарезки не относится.
