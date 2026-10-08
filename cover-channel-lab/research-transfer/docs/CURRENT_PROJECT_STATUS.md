# Текущее состояние генератора офисного фона и NDR-исследований

Актуализация: **2026-10-09**. Этот индекс относится к `cover-channel-lab/research-transfer`, а не к независимым упражнениям в корневом README. Исходные отчёты остаются доступными; новые эксперименты не переписывают их результаты.

**Итог:** `production_ready=false`, `naturalness_status=not_passed` для исторического генератора, `office_labels=unverified`: офисные данные **неразмеченные**. Обучаемый на текущих материалах детектор — **исследовательская проверка на шести лабораторных парах**, не готовый NDR для офиса. Для нового HTTPS workload естественность пока `not_proven`, а не `passed`.

## Указатель на документы

| Документ | Область |
|---|---|
| [Новая проверка офисного фона и техники](OFFICE_BENIGN_AND_TECHNIQUE_TRANSFER_RESULTS.md) | Проверки CI, сопоставимые метрики, честные неудачи и условия для продолжения |
| [Парное обнаружение Adaptix](ADAPTIX_PAIRED_DETECTION_RESEARCH.md) | Feature selection только на training, LOPO/LOTO, ExtraTrees, hard negatives и пороги |
| [Подтверждённая офисная HTTPS-активность](VERIFIED_BENIGN_OFFICE_WORKLOAD.md) | Легитимные приложения, TLS, PCAP и семантический receipt |
| [Хронология исследований](RESEARCH_CHANGELOG_2026.md) | Запуски, результаты и принятые ограничения по датам |
| [Проверка достижимости naturalness](OFFICE_NATURALNESS_FEASIBILITY_2026-10-08.md) | 64 real-stack контроля и copula baseline; почему высокая C2ST не прошла |
| [Паритет измерений](MEASUREMENT_PARITY_AND_NATURALNESS_2026-10-08.md) | Измерения и эффект происхождения |
| [Benign workload research](BENIGN_USER_WORKLOAD_RESEARCH_2026-10-08.md) | Рабочие действия и отличие лаборатории от офиса |
| [MITRE / corpus contract](DEFENDER_MITRE_CORPUS.md) | Состав экспериментального корпуса и семантика labels |
| [Natural Traffic Generator v2](NATURAL_TRAFFIC_GENERATOR_V2.md) | Историческая архитектура real-stack генератора |
| [Импорт техник](UNIVERSAL_IMPORT.md) | Ограничения входных PCAP, activity/evidence и целостность |
| [Запуск](RUNNING.md) | Требования и существующие CLI |

## Что работает на проверенном уровне

| Компонент | Модуль / workflow | Подтверждённый уровень и предел |
|---|---|---|
| Офисные референсы | `datasets/office-cover-20261006/`, `datasets/office-additional-days-20261008/` | Immutable Parquet + manifest. Нет raw офисного PCAP или доверенной разметки benign |
| Профиль офиса | `code/natural_traffic/office_profile_audit.py` | Агрегаты 22/23/28 сентября, внутридневные группы, coverage/квантили; без cross-day HMAC join |
| Реальная легитимная активность | `code/natural_traffic/office_workload.py` | Локальный проверенный HTTPS: документы, правки, файл, сообщения; semantic receipt и PCAP quality. Это Python fixture, не браузер/Office 365 |
| Импорт исходных данных | `code/natural_traffic/defender_domain.py` | `.pcap`, `.parquet`, `.csv`, `.tsv`, `.jsonl` с проверкой измеренных транспортных полей; не принимает произвольные Zeek events за полную схему |
| Сравнение фона | `code/natural_traffic/benign_transfer_evaluation.py` | Групповой ExtraTrees/HGB C2ST на фиксированных numeric transport features; 22 vs 28 как контроль; мало независимых групп ⇒ `insufficient_support` |
| Adaptix/Cover | `code/framework_runtime/adaptix/`, `code/cover_runtime/` | Изолированный реальный стек, ограниченные задания и matched scenario/control, без публикации PCAP |
| Детектор техники | `code/natural_traffic/adaptix_detector_research.py` | Медиана признаков на **физический capture**, парные train-only features, LOPO/LOTO logistic и ExtraTrees, не FPR на офисе |
| Проверка качества | `.github/workflows/natural-traffic-tdd.yml`, `.github/workflows/isolated-cover-adaptix-research.yml` | TLS/capture/extractor gates, group-held-out отчёт и только безопасные JSON артефакты |

**Исключение в истории артефактов:** отменённый прежний run [37855273730](https://github.com/MakSoS1/analytics_test/actions/runs/37855273730) успел создать `natural-generated-benign-e2e-37855273730` (artifact ID `11584696320`) по старой матрице, где upload path включал **лабораторные raw PCAP**. Это не офисные packet captures; однако архив не соответствует текущему контракту безопасной публикации. Новая матрица публикует только `naturalness.json`, `additional_day_control_transfer.json`, `release_gate.json`; тест запрещает возврат пути к capture. Удаление **старого** Actions-артефакта остаётся операционным действием владельца репозитория (в доступном GitHub-интерфейсе нет операции delete artifact).

На отдельной исследовательской ветке `office-benign-adaptix-transfer-2026-10-09` длительный **исторический** `generated-benign-e2e` (матрица 64 Cover-контролей) намеренно пропускается: эта ветка проверяет реальный semantic HTTPS workload и paired Adaptix через их собственные capture/extractor jobs. Исторические результаты 64 захватов сохраняются по ссылкам в хронологии; такая изоляция не считается повторным naturalness pass.

## Офисные выборки (локальный воспроизводимый аудит)

| День | Измеренных строк | Внутридневных групп | Медиана `pkt_count` | TLS |
|---|---:|---:|---:|---|
| 2026-09-22 | 4 000 | 382 | 21 | не измерялся |
| 2026-09-23 | 5 726 | 332 | 2 | отдельная historical unmatched view; не тот же scope |
| 2026-09-28 | 4 002 | 348 | 21 | частично измерен, нули не считаются TLS |

Источник: `office_profile_audit` с закреплёнными manifest; повторяйте команду ниже. Группы и HMAC между выгрузками **не соединяются**; сравнение 22/28 исторически уже использовалось при подборе диагностики и **не является свежим blind holdout**.

Первый новый подтверждённый [CI-захват 37855273730](https://github.com/MakSoS1/analytics_test/actions/runs/37855273730): 3 HTTPS-сессии/12 действий/3 handshake с extractor parity, 1 независимый benign runner, а потому C2ST `insufficient_support`. После исключения не измеренного офисного TCP RTT воспроизведён office-only отрицательный контроль ExtraTrees ROC-AUC 0.52687 и HGB 0.58594; точные fold-level числа — в [отчёте](OFFICE_BENIGN_AND_TECHNIQUE_TRANSFER_RESULTS.md). `office_labels=unverified`.

Повторный [verified benign job 37856781527](https://github.com/MakSoS1/analytics_test/actions/runs/37856781527) подтвердил offline office-negative-control ExtraTrees **0.52687** / HGB **0.58607** ROC-AUC на 60 общих transport features; generated-vs-office по-прежнему `insufficient_support` из-за одной независимой группы. Он также выявил устаревший тест публикации runtime-логов (исправлен, требуется повтор CI); научные C2ST-артефакты самого benign job корректны.

Новый [Adaptix paired v2 CI 37855273740](https://github.com/MakSoS1/analytics_test/actions/runs/37855273740) **успешен**: ExtraTrees LOPO AUC/AP 1.0/1.0, LOTO AUC/AP **0.8333/0.9167**; logistic LOTO AUC/AP лишь **0.5556/0.6528**, recall на withheld TCP **0/3**. `hard_negative_status=insufficient_support` (0 независимых hard negatives). Полная таблица и числа офисных тревог — в [результатах](OFFICE_BENIGN_AND_TECHNIQUE_TRANSFER_RESULTS.md); production-валидации нет.

## Повторить проверки

```bash
cd cover-channel-lab/research-transfer
python -m pip install -r requirements-tested.txt
export PYTHONPATH=code
python -m unittest discover -s code/tests -v

python -m natural_traffic.office_profile_audit \
  --office-dir datasets/office-additional-days-20261008 \
  --office-cover-dir datasets/office-cover-20261006 \
  --out /tmp/office-profile-report.json

# На Linux с openssl и разрешённым tcpdump; только localhost, без реальных сотрудников
python -m natural_traffic.office_workload \
  --out /tmp/verified-office-fixture --sessions 3 --capture
```

Для `benign_transfer_evaluation` следует сначала измерить реальный PCAP **штатным extractor**, затем передать DataFrame с одинаковыми колонками и правдивыми независимыми `benign_group_ids`. Рабочий пример именно этого пути встроен в job `verified-benign-office-workload`; исходный PCAP и приватные материалы не публикуются.

На CI выполняются также `adaptix-research` с 12 PCAP / 6 парами и агрегированным `adaptix-detector-report.json`, но локальное выполнение реального Adaptix требует Docker, закреплённых исходников Go и достаточных ресурсов. Все фичи и результаты подлежат внешней валидации.

## Как трактовать цифры

- **Detection ROC-AUC / PR-AUC**: способность ранжировать подтверждённый *лабораторный* Adaptix против его *лабораторного парного контроля*. Не гарантия детектирования произвольной техники или офисных атак.
- **LOPO / LOTO**: вынос целого сетевого профиля / TCP или mTLS транспорта за пределы обучения; полезнее случайного разбиения тех же сессий.
- **C2ST AUC**: различимость происхождения двух наборов; высокое число свидетельствует о domain shift, но само по себе не показывает, какие признаки являются сигналом техники.
- **Unlabeled office alert fraction**: доля сессий выше экспериментального порога, **не FPR**, поскольку нельзя считать все офисные строки benign.
- **Threshold recall**: доля подтверждённых сценариев выше порога, выбранного на *training controls*. При малой выборке широкая неопределённость.
- **`insufficient_support`**: недостаточно независимых захватов или достоверных меток; не заменять нейтральной AUC 0.5.

До переключения `production_ready` требуется: новые независимые реальные benign-контроли разных клиентов/приложений с семантикой, внешняя размеченная и ранее не использованная офисная выборка, независимые confirmed attack/control пары и hard negatives, проверки sensor/vantage parity, интервалы неопределённости и заранее фиксированные метрики FPR/recall. Сохранение оригинальных PCAP и запрет сетевой мимикрии атак принципиальны.
