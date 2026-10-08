# Изолированный Cover Channels runtime

Исходники `upstream/main` и `upstream/stage_m` закреплены Git blob-хешами и `source_lock.json`; внешние файлы не редактируются. Применяемые изменения хранятся в отдельных runtime adapters, их снимки и SHA входят в каждый run. Реальный запускаемый код выполняется только в отдельном контейнере на исследовательском `.18`.

`run_batch.py` запускает **один** собственный контейнер `--network=none`,2CPU/4GiB, собственные namespaces/veth. Offload отключается только внутри него. Capture проходит на клиентском v-dev после подтверждения готовности tcpdump. `captured` означает успех клиента и непустой PCAP; это ещё не допуск к датасету.

На стенде, из каталога runtime:

```bash
python3 run_batch.py --image cover-complete-wire:20261002 --registry registry.json --all --events 6 --mechanics --out ../core_new
python3 run_batch.py --image cover-complete-wire:20261002 --registry supplemental_registry.json --all --out ../source_new
python3 run_batch.py --image cover-complete-wire:20261002 --registry native_registry.json --all --timing native --mechanics --out ../native_new
```

`--entry` и `--profile` ограничивают явно заявленный scope. `cover_source.import_capture_run` проверяет фактические manifest/events, SHA, dispatch, wire membership и native sent-time intervals. Для subset требуется `requested_only=True`; итоговое покрытие сверяется с полным объединённым registry.

Registry описывает284 основных и938 дополнительных конфигурационных профилей; native registry добавляет10 профилей. Supplemental включает все5 A-transform repetitions, по одному представителю остальных конфигураций, C по60 событий/10 фаз. Это не регенерация всех объёмных повторов исходного корпуса. Дополнительные client labels показывают source configuration, не независимо проверенный effective stack.

Controls — ограниченные benign application fixtures; privacy/LOTS и source-benign profiles — hard negatives. Application decoder выполняет только ограниченные операции с инертными строками, tunnel forwarding допускает только фиксированный localhost echo endpoint. Криптографические события decoding не становятся сетевыми признаками X.

`native` подтверждается событиями и наблюдаемым временем, не параметром запуска. Старые короткие прогоны не пригодны для обучения времени. ECH acceptance, реальные framework holdouts, внешние среды, Windows stacks и1200/3600s evidence требуют собственных неизменяемых capture/adapter records; наличие adapter не означает покрытие.

Office mapping меняет логические ключи в **производной** копии; исходные captures сохраняются. Это синтетические позитивы в сохранённом фоне, не физически снятые офисные позитивы. Политика latest user HOLD запрещает Bronze/Jupyter/GitHub publication; `office_injection.publication_plan.prepare` формирует только проверяемый план объектов.
