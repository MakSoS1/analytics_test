# Результаты и границы вывода

> Это **исторический срез 6 октября**, цифры сохранены без ретроспективной замены. Реальные последующие проверки 8–9 октября, экспериментальный Adaptix детектор и актуальные статусы приведены в [CURRENT_PROJECT_STATUS](docs/CURRENT_PROJECT_STATUS.md) и [OFFICE_BENIGN_AND_TECHNIQUE_TRANSFER_RESULTS](docs/OFFICE_BENIGN_AND_TECHNIQUE_TRANSFER_RESULTS.md). `production_ready=false`.

Исторические агрегаты исследования 6 октября; публикуемый код не выполняет новый сбор или обучение.

| Сопоставимый срез | Строки | Колонки |
|---|---:|---:|
| Pipeline office | 5726 | 180 |
| Pipeline added scenario/control | 2784 | 180 |
| Pipeline original combined | 8510 | 155 |
| Arkime office | 6053 | 833 |
| Arkime added | 2790 | 833 |
| Strict matched pipeline + Arkime | 8507 | 990 |

Одинаковые 1 323 067 входных кадров: офисный фрагмент 23.09 + 580 лабораторных захватов, включая 12 Adaptix. Независимые captures разделены временными окнами: это сравнение извлекателей, а не одновременная активность офисного сенсора. Arkime имеет 813 emitted fields + metadata и presence mask. Три pipeline DHCP-сессии не сопоставлены. Packet counts и bare SYN/FIN/RST/PSH/URG совпали; максимум разницы длительности 0,994 мс при допуске 2 мс. Два расхождения byte counts связаны с IPv4 reassembly; определения ACK bit/bare ACK различаются.

Отдельные последние 89-X композиции: balanced origin AUC оставался 0,999–1,000; office-session sanity AUC 0,477–0,496. AUC около 0,5 при шести generated train-строках не доказывает естественность. Эти цифры не пересчитывались на полном 127-feature/Arkime срезе. Красивые PCA-скопления не подтверждают production validity.

Новый browser supplement: 48 captures, 45 structurally valid; импорт всего дополнения отклонён из-за отсутствующего SYN и timestamp regressions выше допуска. Failed inputs сохранены локально; в опубликованный результат они не включены.

Офисная разметка неизвестна, весь офис нельзя объявлять benign. Split нужен по независимым исходным запускам/профилям и дням; размещения одного PCAP не являются независимыми примерами. Для окончательной оценки переноса нужны позитивы с реального офисного сенсора и новые дни.
