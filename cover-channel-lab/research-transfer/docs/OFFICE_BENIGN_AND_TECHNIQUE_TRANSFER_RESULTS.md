# Независимая проверка офисного фона и Adaptix — отчёт исследования

Проверка протокола и кода: **2026-10-09**. Состояние: `production_ready=false`, `office_labels=unverified`, `office_naturalness_proven=false`. Текущие лабораторные контроли имеют подтверждённую семантику действий, но офисные записи остаются **неразмеченными**, поэтому здесь нельзя вычислять production FPR.

## Что измеряется отдельно

| Вопрос | Измерение | Что не следует заключать |
|---|---|---|
| Отличается ли *происхождение* нового benign-фона от офиса? | Групповой C2ST ExtraTrees/HGB и семейства feature shifts; отдельно 22 vs 28 сентября как контроль | C2ST не проверяет наличие атаки. У одного loopback-host нет независимых test capture groups |
| Отличается ли *техника* Adaptix от matched легитимного контроля? | На 12 реальных исходных PCAP, 6 matched pairs: LOPO/LOTO ROC-AUC и AP, train-only выбор признаков | Контроль — ограниченная лабораторная телеметрия, а не репрезентативный офис |
| Будет ли задет реальный офис? | `unlabeled_alert_fraction` для опубликованных 22/28 сентября | Это не false-positive rate без подтверждённых benign labels |
| Устойчив ли детектор к похожей легитимной активности? | Дополнительные `hard_negative_captures` с явно подтверждённой семантикой | Пока таких независимых hard-negative наборов нет, оценка `insufficient_support` |

## Последний завершённый независимый Adaptix-прогон (исторический v1)

Источник: [GitHub Actions run 37844041216](https://github.com/MakSoS1/analytics_test/actions/runs/37844041216), безопасный `adaptix-detector-report.json` (12 подтверждённых физических PCAP, 6 пар, TCP/mTLS и 3 лабораторных профиля). Ниже значения исторического логистического детектора; это **не новые измерения v2**.

| Групповая проверка | Mean ROC-AUC | Mean AP / PR-AUC | Worst ROC-AUC | Поддержка |
|---|---:|---:|---:|---|
| Leave-one-profile-out | 1.0000 | 1.0000 | 1.0000 | 3 внешних фолда; только 2 withheld пары / фолд |
| Leave-one-transport-out | 0.5556 | 0.6528 | 0.3333 | 2 внешних фолда; по 3 withheld пары |
| TCP train → mTLS test | 0.7778 | 0.8056 | — | 3 withheld пары |
| mTLS train → TCP test | 0.3333 | 0.5000 | — | 3 withheld пары |

- Origin-only явный profile/transport diagnostic AUC = 0.5 на этом протоколе; это не исключает неявного client-stack shortcut в числовых фичах.
- `unlabeled_alert_fraction` в этом историческом эксперименте: 22 сентября **26.095%** (4 000 строк), 28 сентября **28.5907%** (4 002 строки). Не FPR.
- Чаще выбирались на train folds: `burst_count` (4/5), `small_data_up_bytes` (3/5), `direction_changes` (2/5), `down_pkt_count` (2/5). Частота выбора — не причинное доказательство техники.
- Шесть пар не дают узкого confidence interval или независимой проверки на других организациях. Высокая LOPO AUC **не компенсирует** сильную деградацию LOTO.

## Новая реализация v2 и протокол воспроизведения

### Фактическая проверка benign-фона 9 октября

[Первый свежий CI run 37855273730](https://github.com/MakSoS1/analytics_test/actions/runs/37855273730), job `verified-benign-office-workload`, **успешен**. Прочитан его `benign-office-workload-evidence` artifact (четыре агрегированных JSON, без PCAP): три реальные извлечённые TLS-сессии, три захваченных TCP-handshake, 12 подтверждённых заданий; совпадение hash, семантика и extractor coverage подтверждены. Независимых benign-клиентов **1** против **348** офисных групп; `generated_vs_office.status=insufficient_support`. Никакого нового `generated_vs_office` AUC не существует.

В первом артефакте `office_negative_control.status=insufficient_support`: полный список 61 transport feature ошибочно включал `tcp_handshake_rtt_ms`, не измеренный на 22 сентября. Это **не пропуск данных, который допустимо заменить нулём**. Исправление заранее фиксирует 60 общих числовых transport features без RTT. Локальный повтор на **реальных 4 000 и 4 002 офисных строках, 382 и 348 группах**, с тремя `StratifiedGroupKFold` даёт следующие *исследовательские* office-vs-office результаты:

| Модель | Mean C2ST ROC-AUC | Worst ROC-AUC | Фолды AUC |
|---|---:|---:|---|
| ExtraTrees | **0.52687** | 0.51066 | 0.52588, 0.51066, 0.54408 |
| HGB | **0.58594** | 0.56940 | 0.57848, 0.56940, 0.60994 |

Это независимые *групповые* разбиения внутри уже исследованных дней, а не новый blind holdout. Значения локальные и станут частью воспроизводимого CI-артефакта только после отдельного запуска с исправленным frozen feature set. Они не свидетельствуют о естественности лабораторного трафика.

Новый модуль `natural_traffic.adaptix_detector_research` добавляет **ExtraTrees как заранее зафиксированный сравнительный алгоритм** на тех же train-only отобранных признаках; fold-level `positive_count`, `control_count`, `threshold_source`, `recall_at_train_control_threshold`, `hard_negative_alert_fraction`, `uncertainty_status`. Выбор порога — p99 **только training-control**; статистика не заявляется как production FPR. Hard negatives разрешены только при явной semantic verification и не подставляются из unverified офиса.

Workflow `.github/workflows/isolated-cover-adaptix-research.yml` на ветке `office-benign-adaptix-transfer-2026-10-09` заново получает pinned Adaptix, строит изолированное окружение, верифицирует все 12 PCAP, извлекает штатные признаки, запускает оценку и сохраняет **только безопасный агрегированный JSON**. В историческом v1 отчёте ExtraTrees/threshold/hard negatives отсутствовали — их новые числа можно публиковать **только после завершения нового CI run**.

### Проверка benign workload

`verified-benign-office-workload` в `.github/workflows/natural-traffic-tdd.yml`:

1. Создаёт настоящий server/client TLS 1:1, выполняет четыре типа легитимных действий за сессию (документ, правка, файл, сообщение) и проверяет семантический receipt.
2. Сохраняет оригинальный PCAP в эфемерном runner, проверяет tcpdump handshake count, SHA-256, parity и штатный extractor до продолжения.
3. Аудирует реальные офисные Parquet и запускает `benign_transfer_evaluation`: immutable train/test groups, predeclared numeric transport features, office-negative-control (22 vs 28), generated-vs-office C2ST только если достаточно **независимых** benign captures.
4. Объявляет три сеанса в одном запуске **одной** независимой benign-группой `single_verified_local_python_fixture`. Следовательно, `generated_vs_office.status=insufficient_support` — это **ожидаемый честный результат**, а не ошибка, которую следует обходить клонированием IDs.
5. Публикует лишь `workload_receipt.json`, `extractor_summary.json`, `office-profile-report.json`, `benign-transfer-report.json`, без raw PCAP, TLS key, пользовательских payloads и per-host строк.

Статус нового paired v2 CI-прогона и новая точная таблица ExtraTrees должны быть заполнены **после завершения GitHub Actions** из его артефактов. На дату подготовки этого текста независимый v2 run ещё не подтверждён, поэтому **не указываем выдуманные AUC/recall**. Историческая naturalness C2ST ExtraTrees/HGB ≈ 0.9997–1.0 остаётся `naturalness_status=not_passed` ([первичный обзор](MEASUREMENT_PARITY_AND_NATURALNESS_2026-10-08.md)).

## Критерии следующего эксперимента

- Десятки независимо созданных легитимных сеансов из нескольких реальных клиентских стеков и пользовательских приложений — с доказательством действий, не одним синтетическим Python TLS;
- Новые размеченные benign и confirmed technique/normal пары, независимые от train, с отдельным неприкосновенным днем/организацией/сенсором;
- Отдельные application-matched hard negatives, ablations, predeclared thresholds и PR-AUC/recall при известном бюджете ложных тревог;
- Репликация через Linux/Windows/browser/network vantage; защита от provenance/identity leakage; измеренная uncertainty без переиспользования target holdout;
- Выполнение строгого `naturalness_release_gate` и подписанный экспертный аудит разметки перед каким-либо утверждением `production_ready=true`.

Документация входов/запуска: [текущее состояние](CURRENT_PROJECT_STATUS.md), [рабочий HTTPS-контроль](VERIFIED_BENIGN_OFFICE_WORKLOAD.md), [paired Adaptix](ADAPTIX_PAIRED_DETECTION_RESEARCH.md).
