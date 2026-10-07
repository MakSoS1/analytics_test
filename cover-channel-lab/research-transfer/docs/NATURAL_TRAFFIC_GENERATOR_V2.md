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

Windows profile fail-closed: неподдерживаемый `pktmon` не заменяется Linux-профилем.

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

## GitHub Actions

- `.github/workflows/natural-traffic-tdd.yml` — веточный TDD/regression gate, real-capture smoke и экспериментальный generated-benign E2E.
- `.github/workflows/natural-office-traffic-v2.yml` — пользовательский workflow: PR выполняет безопасные проверки; полный pipeline предназначен для manual dispatch.
- До capture проверяется минимум **15 ГиБ** свободного места.
- Linux real-capture smoke проверяет реальный локальный TLS exchange и production extractor.
- Windows capture включается только после capability probe.

## Добавление новой техники

Для managed режима реализуйте adapter с фиксированным `ActivityDescriptor` и парой scenario/control. Adapter не получает произвольную shell-команду из dataset metadata. Для уже существующих внешних генераторов используйте `ExternalActivityAdapter` и неизменяемые PCAP/evidence hashes.

Новая техника становится training-eligible только если одновременно выполнены integrity/fidelity, benign naturalness и technique-signal gates.