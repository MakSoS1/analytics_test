# Полный сопоставимый срез: псевдонимизированные Parquet

Опубликован по прямому поручению владельца с Mac. Исходный офисный фрагмент 23 сентября и 580 лабораторных захватов, включая 12 Adaptix, обработаны двумя извлекателями на одинаковых 1 323 067 кадрах. Это сохранённое сравнение извлекателей с отдельными временными окнами, а не последняя 89-X композиция и не новый офисный сбор. Raw PCAP не включены.

| Файл | Строки | Колонки |
|---|---:|---:|
| pipeline_office_full.parquet | 5726 | 180 |
| pipeline_added_full.parquet | 2784 | 180 |
| pipeline_mixed_full.parquet | 8510 | 180 |
| pipeline_original_155.parquet | 8510 | 155 |
| arkime_office_all_fields.parquet | 6053 | 833 |
| arkime_added_all_fields.parquet | 2790 | 833 |
| arkime_mixed_all_fields.parquet | 8843 | 833 |
| matched_office_pipeline_arkime.parquet | 5723 | 990 |
| matched_added_pipeline_arkime.parquet | 2784 | 990 |
| matched_mixed_pipeline_arkime.parquet | 8507 | 990 |
| pipeline_unmatched_sessions.parquet | 3 | 155 |
| session_comparison.parquet | 8843 | 50 |

В исходных 155 колонках — 127 feature-колонок; метки, ID и служебные поля не входят в ML X. Arkime содержит 813 emitted fields плюс metadata/presence mask. Число колонок не равно числу независимых числовых признаков.

## Что изменено ради публикации

Все строки, порядок, имена и типы колонок, числовые значения, временные метки и числовые пакетные последовательности сохранены. Меняются чувствительные текстовые значения: IP/MAC, host/domain/user, URI/headers/body, payload prefixes, идентификаторы, пути, fingerprint strings и вложенные JSON-значения заменены на `anon_<HMAC-SHA256>`. Ключ 256 бит хранится только на Mac. Равные строки во всём срезе получают равные токены; это лексическое равенство, не нормализация адресов. Списки сохраняют порядок, длину, null/empty distinction. Ограниченные enum, count strings и известные имена полей в presence mask остаются читаемыми. Несовместимые или незнакомые текстовые значения тоже токенизируются.

Schema metadata убрана из открытой копии и сохранена в зашифрованном словаре. Содержательные текстовые признаки нельзя интерпретировать или заново парсить как исходные строки до восстановления. Равенство категорий сохраняется, семантика текста скрыта. Например, поле с JSON-текстом остаётся строкой-токеном; его исходный JSON восстанавливается через словарь.

Это **псевдонимизация, а не гарантия анонимности**. Времена, объёмы, порты, числовая география/ASN и форма обменов остаются; они могут позволять корреляцию. Числовые признаки не подгонялись под офис или нужный AUC. Naturalness=false, production_ready=false. Весь офис не считается benign; split — по независимым исходным запускам/профилям и дням, не по повторным размещениям одного PCAP.

## Читать без словаря

```python
from pathlib import Path
import pandas as pd
root = Path('cover-channel-lab/research-transfer/datasets/office-cover-20261006')
office = pd.read_parquet(root / 'pipeline_office_full.parquet')
added = pd.read_parquet(root / 'pipeline_added_full.parquet')
matched = pd.read_parquet(root / 'matched_mixed_pipeline_arkime.parquet')
print(office.shape, added.shape, matched.shape)
```

Для анализа числовых признаков расшифрование не требуется. ID/метки/происхождение не должны становиться X.

## Словарь и восстановление исходных значений

`dictionary.json.gpg` содержит 65 876 соответствий токен → исходное значение и исходные Arrow schemas. Формат OpenPGP: RSA-3072 recipient, AES-256, MDC. `recipient-public-key.asc` — только публичный ключ; расшифровать им нельзя. Fingerprint: `32D37D34A82966137BA80C667163C26216F27937`.

Приватный ключ оставлен владельцу отдельно на Mac, вне GitHub checkout. Передавать его следующему исполнителю нужно отдельно от публичного репозитория. Ключ экспортирован без парольной фразы и защищён локальными правами 0600/каталогом 0700; обладание файлом даёт возможность расшифровать словарь.

На доверенном компьютере, из `cover-channel-lab/research-transfer`:

```bash
gpg --import /secure/path/PRIVATE-KEY.asc
(umask 077; gpg --output /secure/path/dictionary.json \
  --decrypt datasets/office-cover-20261006/dictionary.json.gpg)
PYTHONPATH=code python code/pseudonymize_tables.py \
  --dictionary /secure/path/dictionary.json \
  --input datasets/office-cover-20261006/arkime_mixed_all_fields.parquet \
  --out /secure/path/arkime_mixed_all_fields.parquet
```

Проверяйте успешный код возврата GPG перед использованием словаря. Расшифрованные файлы и ключ не кладите в репозиторий. Сохраняйте имя входного Parquet: по нему восстанавливается исходная schema metadata. CLI откажется перезаписывать существующий output. Восстановление проверено для всех 12 таблиц по значениям и полной схеме, включая metadata; побайтное совпадение повторно записанного Parquet не обещается из-за формата/компрессии.

## Проверки

`DATA_MANIFEST.json`: размеры, source/export SHA256, числовые column digests и полное обратное восстановление после фактического расшифрования. `PRIVACY_VERIFICATION.json`: проверка всех публичных текстовых значений, отказ расшифрования только публичным ключом и успешное расшифрование резервной копией приватного ключа. Новый capture/training не запускался. Исходные закрытые таблицы на Mac не менялись.
