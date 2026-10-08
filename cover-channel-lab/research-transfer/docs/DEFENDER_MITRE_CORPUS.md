# Универсальный корпус MITRE ATT&CK для обучения защитной NDR-модели

## Что работает

Конвейер принимает **неизменённые** classic Ethernet PCAP или измеренные таблицы
Parquet/CSV/TSV/JSONL, извлекает/сопоставляет транспортные признаки, связывает
метку техники с **конкретной подтверждённой сессией**, отдельно хранит
provenance и учит исследовательские one-vs-control модели по разным MITRE ID.
Сохраняется воспроизводимая карта train/validation/test. На доступных офисных
днях измеряются доли срабатываний и перенос схемы, а не ложные FPR/recall.

Ни один этап этого интерфейса **не редактирует PCAP, не переставляет пакеты,
не переписывает адреса, TLS, payload или timestamps, не подгоняет атаку
под офисное распределение**. Это метод построения корпуса и обучения NDR,
а не инструмент маскировки сетевых техник.

## Требования

- Python 3.12; зависимости из `requirements-tested.txt` (numpy, pandas,
  pyarrow, scipy, scikit-learn) и системные зависимости штатного PCAP extractor.
- Доступные офисные дни: 22 сентября (`4000` строк), 28 сентября (`4002`),
  дополнительный независимый диагностический вид 23 сентября (`5726`).
  SHA-256 манифестов закреплены в `natural_traffic.office_reference`.
- Исходные таблицы требуют минимум 12 поддерживаемых измеренных числовых
  transport features с минимум 80% конечных наблюдений по каждой.
- Для валидной supervised-оценки каждой техники — достаточные **независимые**
  группы сценария и контроля в train, validation и test (минимум две группы
  каждого split; всего в исходном разбиении минимум 10 компонентов).
  Несколько строк или сегментов одного PCAP не являются независимыми группами.

## Манифест одного источника

Манифест JSON версии `defender-source-manifest-v1` содержит массив `sources`.
Пример *одного* source внутри массива (нужен ещё как минимум matched control с
той же `pair_id` и совместимой средой; для обучения нужны многие независимые пары):

```json
{
  "source_id": "allowed-lab-scenario-001",
  "relative_path": "captures/scenario-001.pcap",
  "sha256": "<64 lowercase hex of original capture>",
  "label_state": "verified_positive",
  "technique_ids": ["T1071.001"],
  "pair_id": "pair-001",
  "parent_campaign_id": "campaign-001",
  "runtime_profile_id": "independent-runtime-001",
  "capture_group_id": "capture-001",
  "capture_day_id": "2026-09-22",
  "measurement_vantage": "authorized-lab-nic",
  "extractor_version": "office-sessions-v1",
  "evidence_tier": "operator_attested",
  "membership_relative_path": "evidence/scenario-001-members.jsonl",
  "membership_sha256": "<64 lowercase hex>",
  "receipt_relative_path": "evidence/scenario-001-receipt.json",
  "receipt_sha256": "<64 lowercase hex>"
}
```

Файл membership JSONL содержит одну строку **на подтверждённую сессию**:

```json
{"source_id":"allowed-lab-scenario-001","session_key":"actual-global_session_uid","label_binary":1,"technique_id":"T1071.001"}
```

- Для `matched_control` аналогичная строка имеет `label_binary: 0`, идентификатор
  той же техники и свой `source_id`; если membership отсутствует, строки
  остаются `-1`, а не автоматически benign.
- `hard_negative` требует отдельного receipt; позитивную технику ему
  приписывать нельзя. Для размеченного hard negative нужен membership по
  конкретным сессиям.
- `unverified_external` и `unlabeled_office` — только `label=-1`.
- `fixture_only` предназначен для CI; `operator_attested` фиксирует заявление
  оператора. Только независимо проверенные внешним процессом receipts могут
  иметь `evidence_tier=independently_verified` и допускаться к научному gate.
  Проверка наличия файла и SHA **сама по себе не подтверждает истинность метки**.
- `runtime_profile_id` означает независимый **экземпляр среды выполнения**,
  а не просто «Linux» или «Windows»; повторно использованные ID связываются
  в один общий компонент и не разъединяются между train и test.
- Относительные пути и symlink проверяются на пребывание внутри `--source-root`;
  два одинаковых `source_id`, несовпадающие хеши, недоверенные метки и
  нестыкующиеся пары отвергаются до обучения.

## Командный интерфейс

Из `cover-channel-lab/research-transfer`:

```bash
export PYTHONPATH=code
python -m natural_traffic.defender_corpus_cli prepare \
  --manifest /trusted/mitre/sources.json \
  --source-root /trusted/mitre \
  --out research-prepared

python -m natural_traffic.defender_corpus_cli train \
  --prepared research-prepared \
  --office-dir datasets/office-additional-days-20261008 \
  --office-cover-dir datasets/office-cover-20261006 \
  --out research-models

python -m natural_traffic.defender_corpus_cli evaluate \
  --prepared research-prepared --models research-models \
  --office-dir datasets/office-additional-days-20261008 \
  --office-cover-dir datasets/office-cover-20261006 \
  --out research-evaluation

python -m natural_traffic.defender_corpus_cli report \
  --evaluation research-evaluation
```

Каждому `--out` необходим новый каталог; уже существующие файлы
не перезаписываются. В `research-prepared` создаются `features.parquet`,
`labels_metadata.parquet`, `corpus_manifest.json`; в `research-models` —
модели, `splits.parquet` с SHA, `feature_contract.json`, `training_report.json`;
в `research-evaluation` — агрегированный `evaluation_report.json`.

Модель обучается только на подтверждённых позитивных и парных контрольных
сессиях. Фактические IP/host/day/source, labels и provenance исключены
из model-X. Office reference остаётся немаркированной. Выбор порога идёт
только по validation-контролям; test и офисные дни не участвуют в подборе.

## Независимые проверки и статусы

| Поле | Что действительно доказывает |
|---|---|
| `pipeline_verified` | Хеши и схемы, извлечение, сохранённые groups и статистически корректный test pipeline |
| `technique_research_validated` | Обнаружение на независимых подтверждённых группах при отсутствии измеренных provenance shortcuts; фикстуры не дают этого статуса |
| `office_transfer_diagnostic` | Доля срабатываний на 22/28 сентября; 23 сентября отдельно по доступной схеме |
| `production_ready` | Всегда `false` без слепой новой офисной даты, sensor parity и размеченных целевых MITRE-кейсов |

Отчёт содержит per-technique ROC-AUC, PR-AUC, recall на заранее фиксированном
validation-пороге, количество независимых групп, контроль provenance-only,
контроль с перемешанными train-метками и сравнение с baseline. Отсутствие
минимальной поддержки или двух классов вызывает отказ, не `AUC=1`.

`naturalness_status=not_passed`: исторический C2ST AUC порядка `0.9997–1.0`
для старого generated-vs-office PCAP **остаётся нерешённым**. Новый ML
конвейер не создаёт новых подтверждений естественности пакетов.

## Легитимная офисная активность

Разрешённый локальный адаптер `verified_local_https` использует настоящий
peer-verified TLS клиент и семантически проверяемые задачи с документами,
загрузкой/скачиванием файлов и сообщениями:

```python
from pathlib import Path
from natural_traffic.workload_adapters import run_benign_adapter

receipt = run_benign_adapter(
    "verified_local_https", Path("new-local-workload"), sessions=3, seed=20261008,
)
```

Это *не* настоящий пользовательский браузер, корпоративное ПО или облачная
синхронизация. Для таких стеков нужны собственные локально зарегистрированные
адаптеры и независимая проверка receipts; manifest не может содержать
исполняемую команду. Исходные PCAP и приватные ключи нельзя публиковать
как CI-артефакты. Raw `.pcapng`/EVE/Zeek пока не поддержаны как эквивалент
таблиц сессий без собственного проверенного извлекателя.
