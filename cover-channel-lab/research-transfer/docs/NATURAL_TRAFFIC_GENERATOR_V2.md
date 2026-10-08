# Natural Traffic Generator v2

Этот слой предназначен для исследовательской генерации **парных control/scenario сетевых сессий через реальные клиентские стеки** и проверки, не выучивает ли модель происхождение лаборатории вместо поведения техники.

`passed_candidate` означает только прохождение зафиксированных offline naturalness-gates на конкретном reference slice. Это **не** эквивалент `production_ready=true` и не доказывает перенос на любую офисную сеть. Весь сохранённый офис не считается benign.

## Контракт

1. Naturalness calibration видит только office reference и benign controls.
2. После calibration записывается `frozen_profile_manifest.json` и его SHA256.
3. Scenario generation разрешена только после freeze; позитивные сессии не участвуют в выборе runtime/profile weights.
4. Managed captures не переписываются после захвата: extraction принимает только PCAP с тем же SHA256.
5. Splits делаются по независимым capture/runtime ancestors, не по повторным размещениям одного PCAP.
6. Public reference data остаются псевдонимизированными; приватный ключ и расшифрованный dictionary не нужны для числовой naturalness-проверки.

## Быстрая проверка reference

```bash
cd cover-channel-lab/research-transfer
export PYTHONPATH="$PWD/code"
python -m natural_traffic.cli validate-reference --verify-hashes --out /tmp/reference.json
```

## Capability probes

```bash
python -m natural_traffic.cli probe --profile linux-curl --out /tmp/linux-capability.json
python -m natural_traffic.cli probe --profile windows-native-http --out /tmp/windows-capability.json
```

Windows profile fail-closed: наличие `pktmon` само по себе не означает поддержку захвата. На текущей версии native Windows ETL→PCAP backend не реализован, поэтому capability report возвращает `supported=false`; Linux-профилем он не заменяется.

## Managed benign generation

Cover Channels подключаются через `CoverChannelAdapter`. Внешние готовые captures подключаются через `ExternalActivityAdapter` и `activity.json`.

```bash
python -m natural_traffic.cli generate-benign --entry M-HTTPS-BEACON --source-profile original_dispatch --out /tmp/benign-run
```

## Calibration и freeze

```bash
python -m natural_traffic.cli calibrate --office /data/office_train.parquet --controls /data/control_train.parquet --office-group host_key --control-group capture_group --out /tmp/frozen_profile_manifest.json
```

## Confirmation

```bash
python -m natural_traffic.cli confirm --manifest /tmp/frozen_profile_manifest.json --manifest-sha ACTUAL_SHA256 --office /data/office_confirm.parquet --controls /data/control_confirm.parquet --office-group host_key --control-group capture_group --out /tmp/naturalness.json
```

Возможные статусы: `passed_candidate`, `not_passed`, `insufficient_data`, `integrity_failed`.

## Scenario generation после freeze

```bash
python -m natural_traffic.cli generate-scenarios --manifest /tmp/frozen_profile_manifest.json --manifest-sha ACTUAL_SHA256 --naturalness-report /tmp/naturalness.json --runtime-profile linux-protocol-native --entry M-HTTPS-BEACON --source-profile original_dispatch --out /tmp/scenario-run
```

Команда блокируется, если naturalness status не `passed_candidate`.

## Technique signal

```bash
python -m natural_traffic.cli evaluate-techniques --manifest /tmp/frozen_profile_manifest.json --manifest-sha ACTUAL_SHA256 --naturalness-report /tmp/naturalness.json --scenario /data/scenario.parquet --control /data/control.parquet --pair-group capture_group --out /tmp/technique.json
```



## Дополнительные офисные дни (22/28 сентября)

Новые файлы `datasets/office-additional-days-20261008/` содержат 8 002 строки и 8 000 целых TCP-сессий, выбранных по одинаковому правилу (порт 80/443 и ≥6 пакетов). Они включены в PR с сохранением исходных SHA.

```bash
PYTHONPATH=code python -m natural_traffic.office_day_transfer \
  --root datasets/office-additional-days-20261008 \
  --out /tmp/office-additional-day-transfer.json
```

Диагностика сравнивает **только общие измеренные числовые транспортные признаки** с проверкой независимых `independent_source_group`. Нельзя приписывать неудачу по TLS отличию клиентов: TLS-поля за 22 сентября не измерялись и остаются null. Межвыпусковые HMAC-идентификаторы не объединяются. Исходные дни уже использовались в прошлой диагностике; это не незатронутый финальный holdout. Выводимый JSON содержит только агрегаты и наименования признаков, не отдельные строки, токены или PCAP. Успешное выполнение этого job не меняет `production_ready=false` и не разблокирует attack/scenario training.

## Офисная статистическая baseline-модель

В публичном репозитории **нет исходного офисного PCAP**: имеются псевдонимизированные таблицы с 5 726 офисными сессиями, 127 feature-колонками и пакетными последовательностями. Поэтому невозможно заявить о восстановлении исходных TLS/TCP пакетов из этих таблиц.

Для того чтобы измерить достижимую статистическую близость хотя бы на уровне признаков, доступен **train-only Gaussian-rank-copula baseline**:

```bash
PYTHONPATH=code python -m natural_traffic.office_feature_baseline \
  --reference datasets/office-cover-20261006 \
  --out /tmp/office-feature-baseline-report.json
```

Модель использует числовые features из заранее объявленного dictionary, а не метки, идентификаторы или значения HMAC-токенов. Группы `host_key` разделяются между обучением и подтверждением; совпадающие исходные host groups не попадают в обе выборки. Статистическая зависимость между признаками моделируется через ранговую копулу, а пропуски — через совместные наблюдавшиеся masks. В отчёт выводятся только агрегированные метрики и индикатор точного совпадения со строками train; сами синтетические строки, модель и исходные host IDs в artifact **не публикуются**.

Эта модель намеренно **не способна создавать PCAP**. Её оценка всегда `packet_level_fidelity=false`, `training_eligible=false`, `production_ready=false`: даже AUC около 0.5 в feature-only эксперименте не доказывает естественность TLS и TCP байтов. Офисные строки также не были подтверждены как исключительно benign.

### Что ещё нужно для полноценной проверки без машины в офисе

При возможности лучше использовать **сохранённый ранее mirror PCAP**, а не подключать новую машину. Минимальный полезный набор — 2–3 небольших, самостоятельно отобранных временных окна 10–20 минут с разных рабочих дней, со стабильным форматом и направленностью потока. Прежде чем публиковать что-либо, следует удалить payload/содержимое HTTP, IP/доменные и пользовательские идентификаторы, токены и другие чувствительные поля. Для открытого GitHub безопаснее публиковать только агрегированные per-flow/per-packet признаки и метаданные сенсора без содержимого; оригинальные PCAP, если они вообще нужны для сверки парсера, хранить **непублично** и с разрешения владельца сети.

Если PCAP нет, запасной вариант — повторная выгрузка **Parquet тех же feature-колонок** за ещё 2–3 разных дня с group/day IDs, а также краткая схема размещения зеркала и сенсора, распределения клиентских OS и программ (без имён компьютеров и людей). Это позволит оценить переносимость во времени, но не докажет байтовую естественность.

## Feature-table composition

Public GitHub не содержит raw office PCAP, поэтому public CI может проверить сопоставимость таблиц и membership, но не заявлять packet-level office overlay.

```bash
python -m natural_traffic.cli compose --office datasets/office-cover-20261006/pipeline_office_full.parquet --scenario /data/scenario.parquet --control /data/control.parquet --pair-id example-pair --out /tmp/composed
```


## PCAP quality gate

Managed real-stack captures проходят read-only проверку **до** temporal retime и extraction. Проверка не сортирует пакеты, не меняет timestamp, не обрезает MTU и не переписывает байты. Capture-writer jitter до 50 мкс допускается с предупреждением; превышение границы исключает capture из calibration.

```bash
python -m natural_traffic.cli audit-pcap --pcap /data/capture.pcap --max-regression-us 50 --out /tmp/pcap-quality.json
```

Если после quality gate остаётся недостаточно независимых control-групп, результат fail-closed, а порог naturalness не ослабляется.

## Attack Replay / MITRE external reference

Attack Replay и внешний PCAP-банк используются только как **read-only OOD/extractor regression reference**. Они не являются backend для naturalness: stateless replay, IP/MAC rewriting, MTU truncation и изменение скорости не превращают записанный PCAP в office-native session.

Источник закрепляется на immutable commit, а каждый внешний capture получает `training_eligible=false` и `naturalness_calibration_eligible=false`.

```bash
python -m natural_traffic.cli build-external-reference --root /data/MITRE-ATTACK-pcaps --source references/attack-replay-external.json --out /tmp/external-reference.json
```

Текущий pinned snapshot содержит 41 PCAP и фактически покрывает T1595.001 active scanning; будущие категории из README не считаются фактическим покрытием, пока в pinned tree нет соответствующих PCAP.


## Release package

```bash
python -m natural_traffic.cli package --input /tmp/naturalness.json /tmp/technique.json --out /tmp/natural-release
```

Packaging исключает private key, plaintext dictionary и HMAC key.

The primary PR workflow also validates the additional-day manifest and reports cross-day transport stability. `PYTHONPATH` is rooted at `github.workspace` so unit checks from a working-directory cannot accidentally fail on module import.

## GitHub Actions

- `.github/workflows/natural-traffic-tdd.yml` — веточный TDD/regression gate, real-capture smoke и экспериментальный generated-benign E2E.
- `.github/workflows/natural-office-traffic-v2.yml` — пользовательский workflow: PR выполняет безопасные проверки; полный pipeline предназначен для manual dispatch.
- До capture проверяется минимум **15 ГиБ** свободного места.
- Linux real-capture smoke проверяет реальный локальный TLS exchange и production extractor.
- Windows capture включается только после capability probe.

## Добавление новой техники

Для managed режима реализуйте adapter с фиксированным `ActivityDescriptor` и парой scenario/control. Adapter не получает произвольную shell-команду из dataset metadata. Для уже существующих внешних генераторов используйте `ExternalActivityAdapter` и неизменяемые PCAP/evidence hashes.

Новая техника становится training-eligible только если одновременно выполнены integrity/fidelity, benign naturalness и technique-signal gates.