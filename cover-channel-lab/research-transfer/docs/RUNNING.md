# Запуски и внешние зависимости

Все примеры выполняются из каталога `cover-channel-lab/research-transfer`. Это публичная копия кода; закрытые таблицы и source archives не включены. Используйте новые output directories; исходные данные и failed runs остаются. Скрипты не устанавливают службы автоматически и не публикуют данные.

## Проверка Python-кода

Python 3.12; использованные версии science libraries — в requirements-tested.txt.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-tested.txt
export PYTHONPATH="$PWD/code"
.venv/bin/python -m unittest discover -s code/tests
.venv/bin/python -m office_injection.activity --help
.venv/bin/python -m office_injection --help
.venv/bin/python code/prepare_arkime_inputs.py --help
```

`code/lab_pipeline` находится рядом с baseline helpers, поэтому репозиторий detector/workspace не требуется. Python tests не воспроизводят native Linux capture/DPI и не заменяют его отдельной проверки.

## Cover Channels: сохранённые исходники и изолированный runtime

`code/cover_runtime/upstream/` включает main commit `b4869a7695df464a5d3d1845f4c50719eb5dab09` и Stage M `1028b4a922c9b59e841fc71d58ae1df60ded6da4`. source_lock/upstream_files содержат hashes. Роль и степень fidelity различаются по механике; presence в registry не доказывает исполнение. Полный закрытый комплект содержит mechanism_coverage.csv; в GitHub опубликованы registry и агрегированные результаты, без офисных таблиц.

Для Linux x86_64 нужны Docker, iproute2, tcpdump, ethtool, sudo и зависимости исходного проекта. Dockerfile скачивает некоторые toolchains/browser packages; это сборочный рецепт, а не побайтная фиксация всех внешних пакетов. Зафиксируйте фактический image ID в новом run. Версии прошлого образа не надо представлять как сегодняшний новый image.

```bash
cd code/cover_runtime
docker build -f Dockerfile -t cover-complete:20261002 .
docker build -f Dockerfile.wire -t cover-complete-wire:20261002 .
# --all может быть объёмным: начните с явно выбранного entry/profile.
python3 run_batch.py --image cover-complete-wire:20261002 \
  --registry registry.json --entry CC_BODY_01 --mechanics \
  --out /path/to/NEW_CAPTURE
# native registry: отдельные наблюдаемые интервалы, без accelerated-smoke.
python3 run_batch.py --image cover-complete-wire:20261002 \
  --registry native_registry.json --all --timing native --mechanics \
  --out /path/to/NEW_NATIVE_CAPTURE
```

Образы запускаются без внешней сети, со своими namespaces/veth. Драйвер ограничивает CPU/RAM и проверяет минимум 15 ГиБ свободного места; load average записывается как telemetry, но сам по себе не является причиной откладывать batch. `captured` означает начальный успех клиента/PCAP; импорт проверяет manifest, прикладное evidence, реальное время, wire membership и coverage отдельно. Новый registry/path profile создавайте отдельным файлом, не переписывая сохранённые source pins.

## Adaptix

В `code/framework_runtime/adaptix` лежат adapter, fixed telemetry control и Dockerfile. Серверный source context следует получить отдельно из upstream AdaptixC2/AdaptixC2, commit `e99535c9ef4642190f7ea125c2983d1611f1a3f3`. Для сборки Dockerfile нужен Go 1.25.4 archive в `tools/` и предварительно заполненный `tools/gomodcache`; image использует GOPROXY=off. Этот module cache (1 ГиБ) и Go binary distribution не включены. Развёртывание своей среды потребует отдельного получения этих закреплённых зависимостей и сборки образа.

Разложите закреплённый upstream AdaptixServer в `sources/adaptix/AdaptixServer` внутри adapter directory. Source archive закрытого комплекта в GitHub не включён. Нужный прошлый image tag — `cover-adaptix-isolated:20261004-v4`. `capture.runtime_command(output, script, name)` возвращает команду собственного изолированного контейнера; её следует запускать из Python после проверки доступного места и нового output. Внутри контейнера CLI: `/capture_code.py --out /capture --path-profile lab_fixed_v1`. Adapter разрешает только чтение заранее созданных `/fixture/item_N.txt`; нет параметра произвольной команды или цели. В сохранённом срезе проверены TCP/mTLS, registration/task/result, три профиля, обычный telemetry control. Другие возможности upstream в покрытие не включаются.

## Arkime 6.8.0 и OpenSearch 2.19.4

В `code/arkime` находятся текущие local scripts, C plugin source, lifecycle patch Исходный source tar Arkime 6.8.0 следует получить отдельно; в GitHub он не включён. SHA256 tar: `ec2134bebde8ccdebdc1c1230344c5d913a54caee9fe9f406a554accc4077f69`. Изменения lifecycle нужны для совпадения границ сессий с офисным конвейером; обычный prebuilt Arkime бинарник не является эквивалентной заменой. Runtime binary distributions/OpenSearch/GeoIP не включены.

На Linux:

1. Разложить source tar в `code/arkime/downloads/arkime-6.8.0/`, также положить исходный tar как `downloads/source.tar.gz` для patch_capture.py.
2. Установить build dependencies Arkime 6.8.0, выполнить его configure/build workflow. Применить `python3 bin/patch_capture.py` и пересобрать capture. Команда compiler для officeentropy приведена ниже. Plugin должен быть собран с той же изменённой session struct.
3. Установить OpenSearch 2.19.4, инициализировать Arkime indices/field catalog с prefix `office_arkime_` на loopback 19200. Системные службы автоматически не устанавливаются.
4. Вручную разместить DB-IP Lite Geo/ASN и вспомогательные rir/oui файлы, которые перечислены в INI templates. Если их нет, явно зафиксировать отсутствие enrichment; не объявлять новую среду эквивалентной старому экспорту.
5. `python3 code/arkime/configure_paths.py` создаёт INI из relocation templates, привязывая пути к текущему каталогу и текущему пользователю. Он откажется перезаписывать готовую конфигурацию. Настройки прежних хостов исключены из публичной копии.

Сохранённый guard Arkime требует 40 ГиБ свободно. На исследовательской VM на момент передачи оставалось ~37 ГиБ, поэтому новый native Arkime прогон в этой работе не запускался. Готовые таблицы и hashes проверены на Mac.

## Общий вход Arkime без старых директорий Cover Channels

Создайте `sources.json` с `sources`: для каждого файла `pcap` (относительно JSON), `sha256`, `dataset`, `label_state`, `label_binary`, необязательные `technique/campaign_id/arm`. Для офиса dataset начинается с `office`, label_state=`unlabelled_office`, label_binary=null. Для внешней активности без независимой разметки — label_state=`operator_asserted`, label_binary=null. Если есть точное wire observation, приложите `observation_path` и `observation_sha256`; без этого membership техники не считается проверенным.

```bash
export PYTHONPATH="$PWD/code:$PWD/code/arkime/bin"
.venv/bin/python code/prepare_arkime_inputs.py \
  --spec /path/to/sources.json --out /path/to/NEW_PREPARED
.venv/bin/python code/run_arkime_cover.py \
  --prepared /path/to/NEW_PREPARED --out /path/to/NEW_ARKIME
```

Первый шаг сохраняет кадры и наносекундные интервалы, сдвигая независимые captures одной константой и разделяя их промежутком не менее 1201 секунды. Это не подмешивание в офис и не evidence естественности. Второй шаг требует подготовленного native runtime и сохраняет все emitted SPI fields, full raw SPI CSV, field catalog и typed data. Запрещённые/неизвестные определения не заменяются нулями.

Сопоставление на тех же входах:

```bash
.venv/bin/python code/compare_arkime_pipeline.py \
  --office-code "$PWD/code" --arkime "$PWD/code/arkime" \
  --source /path/to/NEW_ARKIME --out /path/to/NEW_COMPARISON_STAGE
.venv/bin/python code/finalize_arkime_comparison.py \
  --stage /path/to/NEW_COMPARISON_STAGE --source /path/to/NEW_ARKIME \
  --runtime "$PWD/code/arkime" --out /path/to/NEW_COMPARISON_FINAL
```

Сравнение удерживает всю базовую схему и все Arkime поля, а не training projection. Сначала проверяются идентичность потока кадров и границы; совпадение только 5-tuple не достаточно.

`prepare_arkime_cover.py` оставлен как совместимый parser старого формата; новые источники подавайте через `prepare_arkime_inputs.py`. Дубликаты wrappers, live collectors и site-specific deployment scripts исключены из публичной копии.

### Компиляция officeentropy на подготовленном Arkime source tree

Из `code/arkime`, после patch и сборки capture:

```bash
mkdir -p runtime/office-plugins
gcc -shared -fPIC -O2 -I downloads/arkime-6.8.0/capture \
  -I downloads/arkime-6.8.0/thirdparty $(pkg-config --cflags glib-2.0) \
  bin/officeentropy.c -o runtime/office-plugins/officeentropy.so \
  $(pkg-config --libs glib-2.0) -lm
```

## Natural Traffic Generator v2 и real-capture gates

Полное руководство: [NATURAL_TRAFFIC_GENERATOR_V2.md](NATURAL_TRAFFIC_GENERATOR_V2.md).

В GitHub Actions `natural-traffic-tdd` выполняет unit/full regression, отдельный **real-capture** smoke на Ubuntu и production-extractor smoke. Capture считается пригодным к extraction только пока SHA256 PCAP совпадает с hash, закреплённым сразу после захвата. Полный corpus run дополнительно делает benign-only calibration и confirmation; scenario rows calibration не видит.

Минимальный resource gate перед capture/generation — **15 ГиБ** свободного места. Windows profile не fallback-ится на Linux: неподдерживаемый `pktmon` возвращает explicit unsupported.
