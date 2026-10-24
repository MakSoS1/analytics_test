# Публикация, домен и откат

## Какая это публикация

- Репозиторий: `MakSoS1/analytics_test`.
- Ветка исходников и PR base: `feat/examclips-library-zoom-storyboard-20261017`.
- Основной `main` — другой проект, его не меняем.
- Путь приложения: `apps/examclips/`.
- URL: **https://examclips.dpdns.org/**.
- GitHub Pages: ветка `gh-pages`, корень `/`, статические файлы.
- `MakSoS1/examclips`, `forgeofeducation.ru`, Caddy/VM/Supabase не участвуют.

## Обычное обновление

1. Создайте `codex/*` от свежей исходной ветки сайта. Выполните нужные проверки.
2. Откройте PR **в исходную ветку сайта**, не в `main`. Дождитесь
   `browser-build` и `browser-storage`.
3. После merge `examclips-gh-pages-branch.yml` соберёт `apps/examclips/`, выполнит
   unit-тесты и опубликует `dist/` в `gh-pages` через `peaceiris/actions-gh-pages`.
4. Проверьте успешный Actions run и live-сайт по списку ниже.

Сборка использует `EXAMCLIPS_BASE=./`. Это сохраняет корректные пути ресурсов
для корня домена и прежнего `/analytics_test/`. `public/CNAME` копируется в
`dist/CNAME` при каждой публикации. Workflow проверяет его значение
`examclips.dpdns.org`; `.nojekyll` и `site-build.json` добавляются при deploy.
Не редактируйте `gh-pages` вместо исходников — следующий deploy перезапишет её.
Изменения только корневого README/AGENTS не обязаны заново собирать сайт.

## Проверки после публикации

```sh
gh pr checks PR_NUMBER --repo MakSoS1/analytics_test
gh run list --repo MakSoS1/analytics_test --workflow examclips-gh-pages-branch.yml --limit 3
gh api repos/MakSoS1/analytics_test/pages
curl -I http://examclips.dpdns.org/
curl -I https://examclips.dpdns.org/
curl -I https://maksos1.github.io/analytics_test/
curl -fsS https://examclips.dpdns.org/site-build.json
```

Ожидается: Pages `built`, `https_enforced=true`; HTTP и прежний URL
перенаправляют на новый HTTPS URL. У нового домена действительный сертификат;
корневая страница, JS/CSS, dynamic chunks и WASM доступны. В браузере откройте
библиотеку и мастер новой лекции, проверьте отсутствие ошибок загрузки.
`source_commit` в `site-build.json` должен совпасть с опубликованным исходным
коммитом. Не используйте `curl -k` или обход браузерных TLS-предупреждений.

## DNS и продление

DigitalPlat DNS: `dns1.digitalplat.org`, `dns2.digitalplat.org`.
Четыре A-записи `@`, TTL 300:

```
185.199.108.153
185.199.109.153
185.199.110.153
185.199.111.153
```

Это прямое подключение к GitHub Pages без HTTP-прокси Cloudflare. Сертификат
Let's Encrypt управляется GitHub; HTTPS enforcement должен оставаться включён.
[Официальная инструкция GitHub](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site).

Домен зарегистрирован бесплатно 24 октября 2026; в панели указан срок до
24 октября 2027. По условиям на момент подключения бесплатное продление доступно
в последние 120 дней перед истечением срока. Платные слоты, подписки и платное
досрочное продление для этой настройки не покупались. Перед продлением проверьте
актуальные условия регистратора.

## Откат

При регрессии приложения откатите проблемный merge в **исходной ветке сайта**
и дождитесь новой публикации, сохранив актуальные workflow, `CNAME` и пути.
Коммиты до реорганизации используют `examclips-local/`: не переносите выборочно
старый deploy YAML поверх новой структуры. Убедитесь, что URL/HTTPS/ресурсы
восстановились, до сообщения об успешном откате.

Если нужно полностью отказаться от домена, согласованно удалите его привязку
Pages и `public/CNAME` из исходников, уберите его GitHub A-записи у DNS-провайдера,
опубликуйте и проверьте прежний GitHub URL. Не оставляйте неподключённые к
репозиторию web-записи, ведущие на Pages.

Смена origin не переносит IndexedDB/localStorage: сначала сохраните проекты JSON
и оригинальные видео. На новом адресе импортируйте JSON и повторно привяжите видео.
