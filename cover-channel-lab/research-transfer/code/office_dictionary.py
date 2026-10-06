#!/usr/bin/env python3
"""What every column of the office tables means, who may feed it to a model, and
what it duplicates.

One place for the column dictionary, used three ways: the CSV dictionaries that
go out with an export, the `feature_catalog` table in Gold, and the feature sets
of `office_features.py`, which select columns by `role` and `group` instead of
by long hand-written lists.

  role     признак | идентификатор | метка | служебное -- only `признак` may
           reach a model; the other three never do, whatever a set says
  group    the family a feature belongs to (sizes, intervals, TLS, ...)
  dup_of   the column this one repeats exactly or by construction, if any:
           a model given both splits its weight between two copies

  office_dictionary.py sessions --parquet FILE --out CSV
  office_dictionary.py context  --dir CONTEXT_DIR --out CSV
"""
from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

D = {
 "pkt_count": "пакетов в сессии", "up_pkt_count": "пакетов от клиента", "down_pkt_count": "пакетов от сервера",
 "total_bytes": "байт всего (на проводе)", "up_bytes": "байт от клиента", "down_bytes": "байт от сервера",
 "flow_duration": "длительность сессии, с", "up_down_pkt_ratio": "пакеты клиент/сервер",
 "up_down_bytes_ratio": "байты клиент/сервер", "pkt_rate": "пакетов в секунду", "byte_rate": "байт в секунду",
 "burst_count": "число пачек пакетов", "idle_ratio": "доля времени простоя", "direction_changes": "смены направления",
 "udp_share": "доля UDP", "tcp_share": "доля TCP", "iat_regularity": "регулярность интервалов",
 "small_pkt_share": "доля мелких пакетов", "low_rate_long": "длинная и медленная сессия",
 "dir_entropy": "энтропия направлений",
 "idle_gt60_count": "простоев дольше 60 с", "up_bytes_per_pkt": "байт на пакет от клиента",
 "down_bytes_per_pkt": "байт на пакет от сервера", "const_len_share_up": "доля одинаковых длин от клиента",
 "flow_boundary_count": "границ потока внутри сессии",
 "len_unique_up": "различных длин от клиента", "len_unique_down": "различных длин от сервера",
  "seq_signed_len": "массив: длина каждого пакета, знак = направление (+ клиент, − сервер)",
 "seq_iat_us": "массив: интервал до каждого пакета, мкс", "seq_flags": "массив: TCP-флаги каждого пакета",
 "proto": "протокол (tcp/udp)", "dest_port": "порт сервера", "host_key": "хеш адреса клиента",
 "server_key": "хеш адреса сервера", "session_uid": "идентификатор сессии",
 "segment_uid": "идентификатор строки (сессия + номер части)",
 "segment_index": "номер части длинной сессии (0 — первая)",
 "session_continues": "1 — у сессии есть следующая часть", "time_bucket": "час начала сессии",
 "session_start_epoch": "время начала, unix-секунды", "start_observed": "начало сессии попало в запись",
 "truncated_at_capture_end": "сессия ещё шла, когда запись кончилась", "closed_cleanly": "закрыта FIN с обеих сторон без RST",
 "out_of_scope_vpn": "вне области VPN-детектора (DNS)",
 "y_presumed": "метка класса (0 — обычный трафик)",
 "label_source": "откуда метка", "label_family": "семейство туннеля (для обычного трафика пусто)",
 "service_key": "хеш имени сайта (SNI)", "bytes_up_ip": "IP-байт от клиента", "bytes_down_ip": "IP-байт от сервера",
 "pay_entropy_up": "энтропия первых байт данных от клиента", "pay_entropy_down": "энтропия первых байт данных от сервера",
 "pay_printable_up": "доля печатаемых символов от клиента", "pay_printable_down": "доля печатаемых символов от сервера",
 "pay_null_share_up": "доля нулевых байт от клиента", "pay_b64_share_up": "доля символов base64 от клиента",
 "pay_bytes_sampled_up": "сколько байт данных клиента разобрано", "pay_bytes_sampled_down": "сколько байт данных сервера разобрано",
 "dns_qname_len_mean": "средняя длина DNS-имени", "dns_qname_len_max": "макс. длина DNS-имени",
 "dns_label_entropy": "энтропия частей DNS-имён", "dns_query_count": "DNS-запросов",
 "tls_has_sni": "есть имя сайта (SNI)", "tls_sni_len": "длина SNI", "tls_ja4_present": "есть отпечаток клиента JA4",
 "tls_ja4s_present": "есть отпечаток сервера JA4S", "tls_ja4_unique": "различных JA4 в сессии",
 "tls_version": "версия TLS", "tls_cipher_count": "шифров предложено", "tls_ext_count": "расширений TLS",
 "tls_group_count": "групп ключевого обмена", "tls_sigalg_count": "алгоритмов подписи",
 "tls_alpn_h2": "ALPN = HTTP/2", "tls_alpn_h3": "ALPN = HTTP/3", "tls_alpn_http11": "ALPN = HTTP/1.1",
 "tls_alpn_other": "другой ALPN", "tls_resumed": "возобновление TLS-сессии", "tls_early_data": "0-RTT",
 "quic_datagrams": "датаграмм QUIC", "quic_datagram_bytes": "байт QUIC", "quic_cid_changes": "смен идентификатора соединения QUIC",
 "dns_qtype_a": "DNS-запросов A", "dns_qtype_aaaa": "DNS-запросов AAAA", "dns_qtype_txt": "DNS-запросов TXT",
 "dns_qtype_null": "DNS-запросов NULL", "dns_qtype_other": "DNS-запросов других типов",
 "payload_schema_version": "версия справки о содержимом", "is_capwap_tunnel": "служебный туннель Wi-Fi (CAPWAP)",
 "capwap_packets": "пакетов CAPWAP", "payload_matched": "справка о содержимом найдена",
 "ra_small_up_count": "«нажатий клавиш»: пакетов клиента с короткой порцией данных (1–128 байт); пустые подтверждения TCP не считаются",
 "ra_small_up_share": "доля «нажатий» среди всех пакетов клиента с данными (1 — клиент шлёт только короткие команды)",
 "ra_keystroke_iat_p50": "медианная пауза между соседними «нажатиями», с (у человека за терминалом — десятые доли секунды)",
 "ra_echo_ratio": "доля «нажатий», на которые сервер ответил данными в пределах 1 с (эхо набранного символа); пусто, если ответы сервера зеркалу не видны",
 "ra_echo_latency_p50": "медианная задержка ответа сервера на «нажатие», с; пусто, если ответы сервера не видны",
 "ra_interactive_score": "признак интерактивной работы: доля «нажатий», если их не меньше 10 и медианное эхо быстрее 0,2 с, иначе 0; пусто, если ответы сервера не видны",
 "ra_burst_after_idle": "сколько раз активность возобновлялась после паузы дольше минуты",
 "ra_off_hours": "сессия началась в нерабочее время: до 8:00, после 20:00 по Москве или в выходной",
 "ra_known_admin_port": "порт сервера — известный порт удалённого доступа (SSH 22, Telnet 23, RDP 3389, VNC 5900/5901, WinRM 5985/5986, Radmin 4899, TeamViewer 5938)",
 "small_pkt_share": "доля кадров короче 100 байт (включая пустые подтверждения TCP)",
 "client_internal": "клиент во внутренней (частной) сети", "server_internal": "сервер во внутренней (частной) сети",
 "internal_pair": "обе стороны внутренние — соединение внутри периметра (возможное горизонтальное перемещение)",
 "admin_service_by_port": "сервис удалённого доступа по порту сервера: ssh/telnet/rdp/vnc/winrm/smb/rpc/radmin/teamviewer; пусто — не из списка. Только по порту, без разбора протокола",
 "conn_state": "состояние TCP-соединения в терминах Zeek, по всей сессии: SF — закрыто обеими сторонами (FIN); S0 — SYN без ответа; S1 — установлено, не закрыто; REJ — сервер отверг (RST на SYN); RSTO/RSTR — сброшено клиентом/сервером; RSTOS0 — клиент послал SYN и сбросил, сервер молчал; RSTRH — сервер сбросил, начала от клиента не видно; SH/SHR — закрыл только клиент/сервер, другая сторона молчала; S2/S3 — закрыл только клиент/сервер; OTH — подключились с середины и конца не видно. UDP: SF — обе стороны, S0 — одна. Для части длинной сессии — состояние на конец этой части. При одностороннем зеркале SYN без увиденного ответа тоже S0 — сверяйте с down_pkt_count",
 "data_pkt_up": "число пакетов клиента с данными (длина полезной нагрузки TCP/UDP > 0); чистые подтверждения не считаются",
 "data_pkt_down": "число пакетов сервера с данными (длина полезной нагрузки > 0)",
 "small_data_up_bytes": "сумма байт данных в коротких пакетах клиента (данные 1–128 байт) — объём «набранного руками»",
 "tcp_retx_pkts_up": "повторно отправленные клиентом пакеты с данными (номер TCP уже был передан; проверки keep-alive исключены); пусто для UDP",
 "tcp_retx_pkts_down": "повторно отправленные сервером пакеты с данными; пусто для UDP",
 "tcp_retx_bytes_up": "байт данных в повторах клиента", "tcp_retx_bytes_down": "байт данных в повторах сервера",
 "ssh_client_software": "семейство SSH-клиента по его строке идентификации (OpenSSH, PuTTY, libssh, paramiko, Go, WinSCP, Dropbear, Cisco, other); пусто — не SSH. Называет программу, а не поведение: осторожно, модель может выучить имя вместо сути",
 "ssh_server_software": "семейство SSH-сервера по его строке идентификации; пусто — не SSH",
 "ssh_client_fp_key": "отпечаток набора алгоритмов клиента из KEXINIT (в духе HASSH), солёный хеш; одинаковый у одной и той же программы-клиента. Для группировки и новизны, числом в модель не подавать",
 "ssh_server_fp_key": "отпечаток набора алгоритмов сервера из KEXINIT (в духе HASSHServer), солёный хеш",
 "tcp_handshake_rtt_ms": "время от SYN клиента до SYN/ACK сервера, мс (сетевая задержка до сервера); пусто, если не видно",
 "start_hour_sin": "час начала по Москве на круге суток: sin", "start_hour_cos": "час начала по Москве на круге суток: cos",
 "start_dow_sin": "день недели начала на круге недели: sin (пн = 0)", "start_dow_cos": "день недели начала на круге недели: cos",
}
DERIVED = {"tcp_share": "= 1 − udp_share", "byte_rate": "≈ pkt_rate × средняя длина пакета",
           "iat_mean": "= flow_duration / (pkt_count − 1)"}
PREFIX = [("pkt_len_", "размеры пакетов"), ("iat_", "интервалы между пакетами"), ("len_entropy", "размеры пакетов"),
          ("ra_", "удалённое администрирование: похоже ли на человека, работающего в удалённой консоли"), ("syn_", "TCP-флаги"), ("fin_", "TCP-флаги"),
          ("rst_count", "TCP-флаги"), ("psh_", "TCP-флаги"), ("ack_", "TCP-флаги"), ("urg_", "TCP-флаги"),
          ("seq_", "последовательность пакетов"), ("pay_", "содержимое (первые байты данных)"), ("tls_", "TLS"),
          ("quic_", "QUIC"), ("tcp_retx", "повторные передачи TCP"), ("ssh_", "SSH: программа и отпечаток"), ("dns_", "DNS"), ("capwap", "CAPWAP")]
IDS = {"proto", "dest_port", "host_key", "server_key", "session_uid", "segment_uid", "segment_index",
       "session_continues", "time_bucket", "session_start_epoch", "start_observed", "truncated_at_capture_end",
       "closed_cleanly", "out_of_scope_vpn", "payload_matched", "payload_schema_version", "service_key",
       "is_capwap_tunnel"}
CONTEXT = {"client_internal", "server_internal", "internal_pair", "admin_service_by_port",
           "conn_state", "tcp_handshake_rtt_ms", "data_pkt_up", "data_pkt_down", "small_data_up_bytes",
           "start_hour_sin", "start_hour_cos", "start_dow_sin", "start_dow_cos"}
LABEL = {"y_presumed", "label_source", "label_family"}
ID_COLS = {"host_key", "server_key", "session_uid", "segment_uid", "service_key", "ssh_client_fp_key", "ssh_server_fp_key"}
SERVICE_COLS = {"segment_index", "session_continues", "time_bucket", "session_start_epoch",
                "truncated_at_capture_end", "payload_schema_version", "payload_matched",
                "out_of_scope_vpn", "start_observed"}
def role(c):
    if c in LABEL: return "метка — не подавать в модель"
    if c in ID_COLS: return "идентификатор — не подавать в модель"
    if c in SERVICE_COLS: return "служебное — для фильтров и сборки, не признак"
    if c in DERIVED: return "признак, производный (" + DERIVED[c] + "); оставлен для совместимости с лабораторной схемой"
    return "признак"
def group(c):
    if c in LABEL: return "метка"
    if c in CONTEXT: return "контекст сессии: стороны, рукопожатие, сервис, время"
    if c in IDS: return "идентификация и состояние сессии"
    for p, g in PREFIX:
        if c.startswith(p): return g
    return "объём, темп и форма потока"
def desc(c):
    if c in D: return D[c]
    m = re.match(r"(pkt_len|iat)_(mean|std|min|max|median|p\d+|entropy|cv)", c)
    if m:
        what = {"pkt_len": "длина пакета", "iat": "интервал между пакетами"}[m.group(1)]
        stat = {"mean": "среднее", "std": "разброс", "min": "минимум", "max": "максимум",
                "median": "медиана (ближайший элемент ряда, без интерполяции)",
                "entropy": "энтропия", "cv": "коэфф. вариации"}.get(m.group(2), m.group(2).replace("p", "перцентиль ") + " (ближайший элемент ряда, без интерполяции)")
        return f"{what}: {stat}"
    if c.startswith("ra_"): return c[3:].replace("_", " ")
    if c.endswith("_count"): return "число пакетов с флагом " + c[:-6].upper()
    if c.startswith("len_entropy"): return "энтропия длин " + ("от клиента" if c.endswith("up") else "от сервера")
    return ""

D.update({
 "burst_count": "пачек по времени: сколько раз подряд шли пакеты с интервалом меньше 50 мс (в любую сторону)",
 "burst_len_mean": "средняя длина пачки по времени, пакетов (0 — пачек не было)",
 "burst_len_max": "самая длинная пачка по времени, пакетов",
 "dir_burst_count": "пачек по направлению: сколько раз подряд шли 2 и больше пакетов в одну сторону (время не учитывается)",
 "dir_burst_len_mean": "средняя длина пачки по направлению, пакетов",
 "dir_burst_len_max": "самая длинная пачка по направлению, пакетов",
 "run_id": "прогон захвата, из которого строка", "batch_id": "порция внутри прогона",
 "global_session_uid": "сессия во всех прогонах: run_id:session_uid",
 "global_segment_uid": "строка во всех прогонах: run_id:segment_uid (уникальна)",
 "segment_start_ts": "первый пакет строки, UTC", "segment_end_ts": "последний пакет строки, UTC",
 "event_date": "день первого пакета строки, UTC (раздел таблицы)",
 "seq_first_dir": "кто послал первый пакет строки: 1 клиент, −1 сервер",
 "seq_last_dir": "кто послал последний пакет строки: 1 клиент, −1 сервер",
})

IDS |= {"run_id", "batch_id", "global_session_uid", "global_segment_uid", "segment_start_ts",
        "segment_end_ts", "event_date", "seq_first_dir", "seq_last_dir"}
ID_COLS |= {"global_session_uid", "global_segment_uid"}
SERVICE_COLS |= {"run_id", "batch_id", "segment_start_ts", "segment_end_ts", "event_date",
                 "seq_first_dir", "seq_last_dir"}
PREFIX.insert(0, ("burst_", "пачки пакетов"))
PREFIX.insert(0, ("dir_burst_", "пачки пакетов"))
# Exact or constructed copies. Keep one of each pair in a model.
DUP_OF = {"tcp_share": "proto", "udp_share": "1 − tcp_share",
          "byte_rate": "pkt_rate × средняя длина пакета",
          "iat_mean": "flow_duration / (pkt_count − 1)", "total_bytes": "up_bytes + down_bytes"}


GROUP_KEYS = {
    "размеры пакетов": "sizes", "интервалы между пакетами": "intervals",
    "удалённое администрирование: похоже ли на человека, работающего в удалённой консоли": "remote_admin",
    "TCP-флаги": "tcp_flags", "последовательность пакетов": "sequence",
    "содержимое (первые байты данных)": "payload", "TLS": "tls", "QUIC": "quic", "DNS": "dns",
    "CAPWAP": "capwap", "повторные передачи TCP": "retransmissions",
    "SSH: программа и отпечаток": "ssh", "пачки пакетов": "bursts",
    "контекст сессии: стороны, рукопожатие, сервис, время": "context",
    "идентификация и состояние сессии": "identity", "объём, темп и форма потока": "volume",
    "метка": "label",
}


def kind(c: str) -> str:
    """feature | id | label | service -- only `feature` may reach a model."""
    if c in LABEL:
        return "label"
    if c in ID_COLS:
        return "id"
    if c in SERVICE_COLS:
        return "service"
    return "feature"


def entry(c: str) -> dict:
    g = group(c)
    return {"column": c, "kind": kind(c), "group_key": GROUP_KEYS[g], "role": role(c),
            "group": g, "meaning": desc(c), "dup_of": DUP_OF.get(c, "")}


W = "Все окна выровнены: 5 мин и 1 ч по часам, 24 ч от полуночи по Москве. Сессия попадает в окно, где её первый пакет."
T = {
 "office_host_windows": ("одна строка на клиентский хост и окно (5 мин, 1 ч, 24 ч). " + W, {
  "host_key": ("", "хеш адреса клиента (тот же, что в сессиях)", "идентификатор"),
  "window_seconds": ("", "длина окна, с: 300, 3600 или 86400", "служебное"),
  "window_start_epoch": ("", "начало окна, Unix-время UTC", "служебное"),
  "window_end_epoch": ("", "конец окна, Unix-время UTC", "служебное"),
  "coverage_share": ("", "какая доля окна попала в запись (10 минут из суток — 0,007): малая доля — не «тихий хост», а мало данных", "служебное"),
  "sessions": ("", "сессий клиента в окне (длинная сессия из нескольких частей считается один раз)", "признак"),
  "tcp_sessions": ("", "из них TCP", "признак"), "udp_sessions": ("", "из них UDP", "признак"),
  "unique_servers": ("", "различных серверов", "признак"),
  "unique_server_ports": ("", "различных пар «сервер + порт + протокол»", "признак"),
  "admin_sessions": ("l0_ra_flow_count / zeek_ra_session_count", "сессий к портам удалённого доступа (ssh, telnet, rdp, vnc, winrm, smb, rpc, radmin, teamviewer)", "признак"),
  "admin_keystrokes": ("l0_ra_small_up_total", "«нажатий» клиента во всех таких сессиях: пакеты клиента с данными 1–128 байт", "признак"),
  "admin_keystroke_share": ("l0_ra_small_up_share", "доля «нажатий» среди пакетов клиента с данными в этих сессиях; 0 — если таких сессий нет", "признак"),
  "admin_keystroke_bytes": ("l0_ra_small_up_bytes", "байт данных в коротких пакетах клиента (1–128 байт) в этих сессиях", "признак"),
  "admin_unique_servers": ("l0_ra_unique_dst", "различных серверов удалённого доступа", "признак"),
  "admin_unique_ports": ("l0_ra_unique_ports", "различных портов удалённого доступа", "признак"),
  "admin_off_hours_share": ("zeek_ra_off_hours_ratio", "доля таких сессий, начатых вне рабочих часов (до 8:00, после 20:00 по Москве, выходные); 0 — если сессий нет", "признак"),
  "admin_up_bytes_mean": ("zeek_ra_up_bytes_mean", "средний объём от клиента в таких сессиях, байт; 0 — если сессий нет", "признак"),
  "syn_no_answer_share": ("zeek_syn_no_response_ratio", "доля TCP-сессий в состоянии S0 (SYN без ответа); 0 — если TCP нет, смотрите tcp_sessions", "признак"),
  "rejected_share": ("zeek_rejected_ratio", "доля REJ (сервер ответил на SYN сбросом — порт закрыт)", "признак"),
  "reset_share": ("zeek_rst_ratio", "доля сброшенных: RSTO, RSTR, RSTOS0 и RSTRH (у Набора 1 без RSTRH — сброс сервером, когда начала не видно)", "признак"),
  "clean_close_share": ("zeek_clean_close_ratio", "доля SF — обе стороны закрыли соединение", "признак"),
  "unclosed_share": ("zeek_unclosed_ratio", "доля S1 и OTH — не закрыто к концу записи или начало/конец не видны", "признак"),
  "failed_connections": ("", "число неудавшихся попыток: S0, REJ, RSTOS0, SH", "признак"),
  "direction_changes_mean": ("l0_direction_switch_mean", "среднее число смен направления (клиент↔сервер) в сессии", "признак"),
  "direction_changes_max": ("l0_direction_switch_max", "максимум смен направления по сессиям окна", "признак"),
  "multi_direction_share": ("l0_multi_dir_flow_ratio", "доля сессий хотя бы с одной сменой направления", "признак"),
  "pay_entropy_up_mean": ("l0_payload_entropy_up_mean", "средняя энтропия первых байт данных клиента, бит на байт (0–8); пусто, если ни в одной сессии не было данных", "признак"),
  "pay_entropy_up_max": ("l0_payload_entropy_up_max", "максимум той же энтропии по сессиям", "признак"),
  "high_entropy_share": ("l0_high_entropy_flow_ratio", "доля сессий с энтропией выше 7,5 (шифр или сжатие); пусто — нет данных", "признак"),
  "pay_printable_up_mean": ("l0_payload_printable_up_mean", "средняя доля печатаемых символов в первых байтах клиента", "признак"),
  "pay_b64_up_mean": ("l0_payload_b64_up_mean", "средняя доля символов алфавита base64 там же", "признак"),
  "ports_per_server": ("l0_ports_per_dst_ratio", "различных портов на один сервер: много — похоже на перебор портов", "признак"),
  "short_session_share": ("l0_short_flow_ratio", "доля сессий из 3 пакетов и меньше", "признак"),
  "sessions_per_second": ("l0_flow_creation_rate", "новых сессий в секунду (на покрытую записью часть окна)", "признак"),
  "new_servers": ("l0_new_dst_count", "серверов, к которым хост раньше не обращался (по истории пар и предыдущим окнам)", "признак"),
  "new_server_share": ("l0_new_dst_ratio", "их доля среди серверов окна", "признак"),
  "new_server_ports": ("l0_new_port_count", "новых пар «сервер + порт»", "признак"),
  "new_server_port_share": ("l0_new_port_ratio", "их доля", "признак"),
  "new_ssh_fingerprints": ("", "новых для хоста отпечатков SSH-клиента: сменилась программа, которой он ходит по SSH", "признак"),
  "tcp_retx_share": ("", "доля повторно отправленных пакетов клиента с данными среди всех его TCP-пакетов с данными; пусто — данных не было", "признак"),
  "up_bytes_total": ("", "байт, отправленных хостом в пределах окна — по времени самих пакетов (таблица host_minutes); пусто — для порции поминутного объёма не считалось", "признак"),
  "down_bytes_total": ("", "байт, полученных хостом в пределах окна", "признак"),
  "bytes_per_second": ("", "байт в секунду на покрытую записью часть окна — всплеск объёма", "признак"),
  "peak_minute_bytes": ("", "самая тяжёлая минута окна, байт в обе стороны", "признак"),
  "top_peer_share": ("", "доля байт окна, приходящихся на главного собеседника каждой минуты: 1 — весь объём в одну точку", "признак"),
 }),
 "office_host_minutes": ("внутренний хост × минута UTC: объём по времени самих пакетов (всплески видны в свою минуту); строки одной минуты из двух порций складываются", {
  "host_key": ("", "хеш внутреннего адреса (тот же, что в сессиях)", "идентификатор"),
  "minute_epoch": ("", "начало минуты, Unix-время UTC", "служебное"),
  "minute_ts": ("", "начало минуты, UTC", "служебное"),
  "bytes_out": ("", "байт отправлено хостом за минуту (длина кадра на проводе)", "признак"),
  "bytes_in": ("", "байт получено хостом за минуту", "признак"),
  "pkts_out": ("", "пакетов отправлено", "признак"), "pkts_in": ("", "пакетов получено", "признак"),
  "peers": ("", "различных собеседников за минуту", "признак"),
  "top_peer_bytes": ("", "байт с самым тяжёлым собеседником минуты, в обе стороны", "признак"),
 }),
 "office_host_volume_windows": ("внутренний хост × окно 5 мин / 1 ч / 24 ч: объём по времени пакетов для ВСЕХ внутренних хостов, включая те, что только принимают (серверы) — в host_windows их нет", {
  "host_key": ("", "хеш внутреннего адреса", "идентификатор"),
  "window_seconds": ("", "длина окна, с: 300, 3600 или 86400", "служебное"),
  "window_start_epoch": ("", "начало окна, Unix-время UTC", "служебное"),
  "window_start_ts": ("", "начало окна, UTC", "служебное"),
  "coverage_share": ("", "какая доля окна попала в запись", "служебное"),
  "up_bytes_total": ("", "байт отправлено хостом в окне", "признак"),
  "down_bytes_total": ("", "байт получено хостом в окне", "признак"),
  "bytes_per_second": ("", "байт в секунду на покрытую записью часть окна", "признак"),
  "peak_minute_bytes": ("", "самая тяжёлая минута окна, байт", "признак"),
  "top_peer_share": ("", "доля байт на главного собеседника каждой минуты", "признак"),
 }),
 "office_pairs": ("одна строка на пару «клиент – сервер – порт – протокол» за всю историю; копится между прогонами (--pairs-in). Это и есть хранилище «first seen» из Набора 1", {
  "host_key": ("", "хеш клиента", "идентификатор"), "server_key": ("", "хеш сервера", "идентификатор"),
  "dest_port": ("", "порт сервера", "признак"), "proto": ("", "tcp или udp", "признак"),
  "first_seen_epoch": ("first_seen_store", "когда пара встретилась впервые, Unix-время UTC", "признак"),
  "last_seen_epoch": ("", "когда последний раз началась сессия этой пары", "признак"),
  "sessions": ("", "сессий пары за всю историю", "признак"),
  "up_bytes": ("", "байт от клиента за всю историю", "признак"), "down_bytes": ("", "байт от сервера", "признак"),
  "failed_sessions": ("", "неудавшихся попыток (S0, REJ, RSTOS0, SH)", "признак"),
  "admin_service_by_port": ("", "сервис удалённого доступа по порту, если порт из списка", "признак"),
 }),
 "office_ssh_fingerprints": ("одна строка на клиентский хост и отпечаток SSH-клиента; копится между прогонами", {
  "host_key": ("", "хеш клиента", "идентификатор"),
  "ssh_client_fp_key": ("", "отпечаток набора алгоритмов SSH-клиента (в духе HASSH), солёный хеш", "идентификатор"),
  "first_seen_epoch": ("", "когда хост впервые пришёл с этим отпечатком", "признак"),
  "sessions": ("", "SSH-сессий с этим отпечатком", "признак"),
 }),
 "office_capture_quality": ("одна строка на 20-секундный интервал записи: можно ли доверять данным этого времени", {
  "interval_start_epoch": ("", "начало интервала, Unix-время UTC", "служебное"),
  "status": ("", "ok — обработан; missing — интервала нет в записи (дыра); иное — ошибка", "служебное"),
  "error": ("", "текст ошибки, если была", "служебное"),
  "frames": ("", "кадров в интервале", "качество"), "flow_packets": ("", "из них попали в потоки", "качество"),
  "truncated_frames": ("", "кадров, обрезанных при записи (snaplen)", "качество"),
  "non_ip_frames": ("", "кадров не IP (ARP, LLDP и т. п.)", "качество"),
  "ip_fragments": ("", "IP-фрагментов (в потоки не собираются)", "качество"),
  "other_l4_frames": ("", "кадров не TCP/UDP (ICMP, GRE, ESP…)", "качество"),
  "bad_header_frames": ("", "кадров с битыми или короткими заголовками", "качество"),
  "pcap_bytes": ("", "размер записи интервала, байт", "качество"),
  "convert_seconds": ("", "сколько секунд обрабатывался", "качество"),
  "interval_seconds": ("", "длина интервала, с", "служебное"),
 }),
}


def context_entries() -> list[dict]:
    out = []
    for tab, (about, cols) in T.items():
        for c, (n1, d, r) in cols.items():
            out.append({"table": tab, "column": c, "nabor1_name": n1, "role": r, "meaning": d})
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("what", choices=("sessions", "context"))
    ap.add_argument("--parquet", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    if a.what == "sessions":
        import pyarrow.parquet as pq
        rows = [entry(c) for c in pq.read_schema(a.parquet).names]
    else:
        rows = context_entries()
    with a.out.open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    missing = [r["column"] for r in rows if not r["meaning"]]
    print(f"{len(rows)} колонок, без описания: {missing}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
