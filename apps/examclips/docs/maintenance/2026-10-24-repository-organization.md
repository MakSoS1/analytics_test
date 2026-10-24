# Реорганизация 24 октября 2026

## Область изменения

Пользователь выбрал отдельную ветку `analytics_test`, а не перенос в `main`
и не новый репозиторий. Ветка сайта и PR base остаётся
`feat/examclips-library-zoom-storyboard-20261017`. Домен `examclips.dpdns.org`
и GitHub Pages сохранены. Основной проект репозитория не переносился.

## Карта переноса

| Раньше | Теперь |
| --- | --- |
| `examclips-local/` | `apps/examclips/` |
| `docs/examclips/` | `apps/examclips/docs/history/reports/` |
| `docs/superpowers/plans/` | `apps/examclips/docs/history/plans/` |
| `docs/superpowers/specs/` | `apps/examclips/docs/history/specs/` |
| SQL/Python-текст корневого README | `docs/legacy/ANALYTICS_EXERCISES.md` |

Три текущих ExamClips workflow остаются в `.github/workflows/`,
их working directory, path filters и artifact paths обновлены. Четыре
специализированных workflow с прежними экспериментальными ветками перенесены
в `docs/history/workflows/`; их скрипты сохранены в приложении.

Корневые README/AGENTS маршрутизируют агента в приложение и правильную ветку.
Текущие инструкции собраны в [индексе документации](../README.md). Исторические
документы помечены. Editorial skill приведён в соответствие с тёмным фоном,
одной областью, титульником до 1,6 с и широкой вебкой.

## Проверки

- 113 существующих файлов приложения, кроме заменённого README и ignore rules,
  совпадают с Git blobs до переноса: код, скрипты, тесты и конфигурация не изменены.
- Исходный аналитический README сохранён побайтно, включая прежние пробелы.
- Все относительные Markdown-ссылки проверены отдельно от внешних URL.
- Три активных YAML разобраны парсером; старые пути отсутствуют в активных workflow.
- 176 unit-тестов и production build с `EXAMCLIPS_BASE=./` прошли из нового каталога.
- Сборка сохранила прежние имена/хеши JS/CSS/WASM и `CNAME`.

Результаты браузерного CI и live-публикации фиксируются в
[PR #75](https://github.com/MakSoS1/analytics_test/pull/75) и его Actions checks.
Дальнейшие проверки публикации: [deployment.md](../deployment.md).

Контрольный SHA `main` до реорганизации:
`35812dd0ea2a98203f0f270337d359b3c8bcac08`. Он не является базой кода этого сайта.
