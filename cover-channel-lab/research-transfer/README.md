# Офисный фон, общий импорт активностей и Arkime

Наработки исследования 2–6 октября 2026, перенесённые с Mac. Этот каталог добавлен рядом с исходным cover-channel-lab: его существующие сценарии и workflow не заменены.

**Естественность не подтверждена; production_ready=false.** Лабораторные вставки остаются различимы от офиса. Этот результат и ограничения диагностики сохранены; перенос не является подтверждением пригодности для production-обучения.

## Что включено

- `code/office_injection/`: общий activity.json, импорт scenario/control PCAP и evidence, перенос в сохранённый фон, integrity gates и ground truth. Идентификатор другой TCP/UDP техники не требует изменения реестра Cover Channels.
- `code/cover_runtime/`: закреплённые исходники main/Stage M, реестры механик, изолированные runtime adapters и проверки исполнения.
- `code/framework_runtime/`: ограниченный Adaptix adapter с фиксированными тестовыми заданиями и обычные браузерные контроли. Исходники внешних инструментов и их сборочные зависимости нужно получить отдельно.
- `code/lab_pipeline/` и baseline helpers: полная схема признаков, сшивка сессий, пакетные последовательности и Parquet. Исходная схема содержит 146 колонок; с ключами хранения — 155. Словарь выделяет 127 feature-колонок, а не 155 независимых ML-признаков.
- `code/arkime/` и wrappers: offline обработка, lifecycle patch, plugin, сохранение всех SPI полей, общий список PCAP и строгое сопоставление на тех же пакетах.
- `code/demo/`: аудит происхождения, мощности и сенсорного влияния, объяснение кластеров и 3D-визуализация.
- `notebooks/`: последняя аудированная версия с агрегированными выводами и каталогом механик; выводы, вложения и точечные данные удалены.
- `docs/`: контракт импорта других техник, запуск, ограничения и дальнейшие проверки.

## Начать

```bash
cd cover-channel-lab/research-transfer
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-tested.txt
export PYTHONPATH="$PWD/code"
.venv/bin/python -m unittest discover -s code/tests
.venv/bin/python -m office_injection.activity --help
.venv/bin/python code/prepare_arkime_inputs.py --help
```

[Natural Traffic Generator v2](docs/NATURAL_TRAFFIC_GENERATOR_V2.md), [общий импорт](docs/UNIVERSAL_IMPORT.md), [запуск и зависимости](docs/RUNNING.md), [следующие шаги](docs/NEXT_STEPS.md), [агрегированные результаты](RESULTS.md).

Исходные офисные Parquet, PCAP, payload sidecars, salt, приватные индексы, outputs ноутбука, site-specific live collectors, deployment scripts и архивы исходников внешних инструментов не публикуются. По отдельному поручению владельца добавлены [12 псевдонимизированных полных Parquet и зашифрованный словарь](datasets/office-cover-20261006/README.md). Приватный ключ остаётся только на Mac; закрытый исходный комплект передан отдельно. Типовой общий импорт поддерживает целые клиентские TCP/UDP обмены; replay adapter ограничен 35 секундами. Другим carrier/длительным захватам нужен отдельный проверяемый adapter. Linux нужен для capture/replay/native Arkime, Mac подходит для таблиц и Python tests.

`PUBLICATION_SCOPE.json` фиксирует исключения и placeholder replacement. `PUBLICATION_MANIFEST.json` содержит hashes опубликованных файлов. Исторические source pins ноутбука относятся к закрытым оригинальным отчётам; их данные не входят в GitHub. Чтобы выполнить ячейку чтения исходного 89-X экспорта, задайте TRAFFIC_RESEARCH_DATA на разрешённый локальный каталог. Он отличается от полного сопоставимого среза.

## Natural Traffic Generator v2

Новый пакет `code/natural_traffic/` отделяет real-stack generation, benign-only calibration, freeze/confirmation и technique-signal evaluation от исторического PCAP replay. Сценарии не используются для подбора naturalness-профиля; `passed_candidate` остаётся исследовательским статусом, `production_ready=false` до независимого production transfer.

## Дополнительные дни — 8 октября

[Два дополнительных офисных Parquet](datasets/office-additional-days-20261008/README.md): 8 000 отдельных TCP/web-сессий за 22 и 28 сентября, 8 002 строки, полный контракт 155 колонок и три идентификатора групп. Прилагаются контекст зеркала, отчёт о пропусках и зашифрованный словарь для прежнего ключа получателя. TLS-поля 22 сентября отсутствуют в сохранённом источнике; новые native Arkime-данные не включены. Дни ранее использовались в диагностике и не объявляются финальным holdout.
