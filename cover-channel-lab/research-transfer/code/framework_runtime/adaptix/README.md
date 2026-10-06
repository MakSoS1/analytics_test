# Изолированный реальный Adaptix capture

Этот adapter добавляет исследовательские примеры настоящего Linux Gopher обмена
к прежнему cover-корпусу. Он не включает deployment в офисе. Официальный source
pin: `e99535c9ef4642190f7ea125c2983d1611f1a3f3`.

Фактически исполняются registration, persistent TCP/AES-GCM task/result и
вариант mTLS. Для каждого транспорта три заранее заданных профиля: RTT
8/36/70ms, шесть задач с интервалами 2–9sec и synthetic fixtures разного размера.
Задача всегда `cat /fixture/item_N.txt`. API не принимает пользовательскую
команду или произвольную цель. Прочие возможности upstream binary не считаются
реализованными механиками, пока нет evidence их исполнения.

Control — обычный Go-клиент, отправляющий telemetry samples и проверяющий
SHA256 acknowledgement. Это отдельная программа, без Adaptix-агента. Для mTLS
пары используют одинаковую CA и TLS implementation. Plain TCP control остаётся
несовершенным криптографическим контролем: у него нет application AES-GCM.

Docker image строится offline из сохранённого module cache и source sums.
`runtime_command()` запускает `--network none`, без published ports или
privileged mode. `SYS_ADMIN` нужен для дочернего network namespace через
`unshare`; host namespaces/interfaces не используются. Main namespace содержит
сервер, client namespace — агент/telemetry client. Между ними только veth,
у клиента нет default route. API слушает loopback контейнера.

На обоих veth отключаются и проверяются GRO/GSO/TSO. Capture использует
`tcpdump --immediate-mode`. Проверки требуют successful tcpdump shutdown,
zero kernel drops, исходный SYN, Ethernet frames не больше1514bytes и
bidirectional application packets в каждом actual task window. Никакие PCAP
timestamps/lengths/payload не переписываются. Completed outputs проверяются
по synthetic fixture hashes. Import заново проверяет исходный PCAP и receipts.

`demo/add_framework_research.py` работает только на `.18` с ранее сохранёнными
office inputs. Он создаёт новый output, сохраняет старые sealed bundles, а
при объединении оставляет из нового overlay только GT segments. Офисный фон
не дублируется. `--frozen-labels` сохраняет split всех старых profile groups.
Все derived rows одного нового профиля и обе его роли получают один split.
Перед zero-shot оценкой original model проверяется по original COMPLETE.

Метрики не являются office FPR или доказательством естественности. Это один
source build/day, шесть пар, только TCP/mTLS. Нужны независимые source/day
проверки и будущие позитивы, наблюдавшиеся через офисный сенсор.
