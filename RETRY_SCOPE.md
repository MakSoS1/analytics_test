# Отдельный повтор RU11 и EN10 после технических отказов инициализации

Пакет создан от просмотренного harness commit `704c2744716c420d2b8f84e41f07454116774147` на отдельной ветке `qa/examclips-stand45-retry-small-2026-11-15`. Действующие run43765971939 и observed retry43771796745 сохраняются. Новый запуск требует отдельной проверки и публикации; существующие workflow и account не изменяются.

## Точный объём

`run-request.json` выбирает только `ru11` и `en10`:

| ID | Длительность исходника, с | Байты | SHA-256 |
| --- | ---: | ---: | --- |
| RU11, «Адроны» | 850.325 | 51480024 | `2778840d1288ab7739ed08404efc0123290821c59f358be7e378824b769bfd35` |
| EN10 | 584.303946 | 80754525 | `0e74dbe57e4673ba3b45c51028a9c0742b0b7b0b33263eda866df7405f083693` |

В main job132989409058 (RU11) и job132994870595 (EN10) зарегистрированы Blob OOM и ASR Failed to fetch до любого экспорта. Эти технические отказы не дают оценки качества видео и не доказывают общую первопричину ошибки или нехватку RAM. Остальные активные случаи, включая EN07, не добавлены.

Сохраняется полный исходный manifest45. Приложение — private CI artifact14177000950, commit `c8358a6df86ca0f77d859ebe8481a876b3e1abd5`, SHA-256 архива `4463e4e2b9a3f57ce215610f974f2162189a4c421bab6947191dd61c1c726940`. Все18 asset hashes, сеть, loopback target, отсутствие COEP, автоматический язык, полный ASR, стандартный экспорт15fps/720 и все клипы сохраняются. Итог имеет тип `test_instance`; он не устанавливает live-site authentication/billing/hosting pass.

## Минимальное изменение

Меняются имя и точные ограничения новой ветки в workflow, ветка в AAD guard и соответствующих тестах, явный список двух случаев и эти scope docs. Существующий `prepare.mjs` читает список из `run-request.json`; нового workflow_dispatch или обходного механизма выбора нет. Код `run.mjs`, browser launch, network policy, source transport, review/package helpers, persistent ASR gate и observer неизменны. `needs: prepare` остаётся обязательным.

## Браузер и gate

Свежий persistent browser запускается тем же helper и четырьмя обычными флагами. Обязательная подготовка требует наблюдаемого real ASR, idle results UI и непустого созданного SRT для прежнего25-секундного диагностического фрагмента RU03. Фрагмент не заменяет полные RU11/EN10. Код bounded read-only resource observer и условного nonpersistent control сохраняется: control после ошибки не разрешает матрицу даже при успехе. Подробный существующий контракт — `OBSERVED_GATE_SCOPE.md`.

В observed run43771796745 обязательный persistent gate уже фактически прошёл, но новый запуск повторяет его самостоятельно. Gate success не гарантирует отсутствие редкой ошибки на последующей VM и не заменяет качество итоговых роликов. Никаких RAM flags, Blob/model overrides, удаления кэша или state injection нет.

## Источники и ключи

Оба источника скачиваются целиком по прежним открытым direct URL. TIB helper сохранён, но для этой пары не вызывается. После повтора сравниваются фактические SHA source/app, экспорты и доказательства.

Для новой ветки создаются отдельные prepare/unlock descriptors и operator directory `private/stand45-small`, новый одноразовый bundle RSA recipient и новый whole workflow attempt1. AAD сохраняет точное repository/branch/run/attempt/case/purpose; старые ветки и попытки отвергаются. Evidence recovery recipient не меняется. В публичный repo передаются только ciphertext; приватные product assets, keys и artifact capabilities в него не попадают. Shared bundle attempt1 не переиспользуется при attempt2 — нужен свежий whole workflow run.

`concurrency.group` включает ref и case ID, `cancel-in-progress: false`. Изменение не отменяет активные runs; подготовка ожидает обычной очереди VM. Нет production auth, billing, платежей или изменений доступа.
