# Проверка публичного состава перед push

Публикация разрешена пользователем в MakSoS1/analytics_test; подтверждено, что репозиторий публичный. Проверки выполнялись только с Mac, без SSH/SCP/команд на VM.

187 upstream files сверены по SHA256 и по Git blob IDs с уже публичными коммитами b4869a7695df464a5d3d1845f4c50719eb5dab09 / 1028b4a922c9b59e841fc71d58ae1df60ded6da4 в том же GitHub-репозитории (Git Trees API). Их байты сохранены.

Остальные файлы — исходный код, схемы, синтетические unit-test fixtures, dependency pins, документация, агрегированные результаты и notebook source без outputs/attachments. Все файлы проверены как текст; PCAP/Parquet/sidecar/index/database/archives/compiled binaries не включены. В test inventory удалена секция runtime_preflight: host, CPU, disk и Docker состояния исследовательского хоста не публикуются.

Из публичной копии убраны live collectors, deployment wrappers, historical host configs и публикация в корпоративное хранилище. Личные имена, офисные адреса и локальные пути заменены placeholders только в публикуемой копии. Исходные данные/локальный полный комплект не изменены.

Проверены все оставшиеся IP/path literals. 10.20/10.30/10.203 — код изолированных namespaces и synthetic fixtures; 10.0/172.16/192.168 range literals — generic private-address classification; 10.1.0.3 — встроенный unit self-test; 172.21.254.10 — константа synthetic клиента сценария. 192.0.2.* — documentation/test addresses. /opt/* — generic container/runtime installation paths; /home/jovyan — conventional notebook image path. Эти строки не являются адресами офисных машин или пользовательскими домашними каталогами. Файл-by-файл проверка не нашла исходные site/account literals, токены GitHub/AWS/Slack или private key blocks.

Публикуются только агрегированные размеры/метрики исследования. Офис не объявлен benign; naturalness_established=false и production_ready=false. Коммит содержит [skip ci], workflow files не меняются; новая ветка не совпадает с push branch filters существующих workflow. Виртуалка не участвует в публикации.
