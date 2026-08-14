from __future__ import annotations

import csv
from io import StringIO
from typing import Iterable

import pandas as pd


NETFLOW_COLUMNS = [
    "time",
    "duration",
    "src_device",
    "dst_device",
    "protocol",
    "src_port",
    "dst_port",
    "src_packets",
    "dst_packets",
    "src_bytes",
    "dst_bytes",
]


def _parse_port(value: object) -> int | None:
    text = str(value).strip()
    if not text:
        return None
    if text.lower().startswith("port"):
        text = text[4:]
    try:
        port = int(text)
    except ValueError:
        return None
    return port if 0 <= port <= 65535 else None


def _parse_int(value: object) -> int:
    text = str(value).strip()
    try:
        return int(float(text))
    except (TypeError, ValueError):
        return 0


def parse_netflow_lines(
    lines: Iterable[str],
    remote_admin_ports: set[int],
    max_rows: int,
) -> pd.DataFrame:
    """Parse a bounded LANL 2017 netflow slice without inventing labels.

    Official LANL 2017 network rows contain eleven comma-separated fields:
    time, duration, source/destination device, protocol, ports, packet counts,
    and byte counts. Ports may appear as integers or as `PortNNN` tokens.
    Rows are retained when either endpoint port is in the caller's explicit
    remote-administration port set.
    """
    if max_rows <= 0:
        return pd.DataFrame(columns=NETFLOW_COLUMNS)
    rows: list[dict[str, object]] = []
    ports = {int(p) for p in remote_admin_ports}
    for raw in lines:
        if len(rows) >= max_rows:
            break
        text = str(raw).strip()
        if not text or text.lower().startswith("time,"):
            continue
        parsed = next(csv.reader(StringIO(text)))
        if len(parsed) != 11:
            continue
        src_port = _parse_port(parsed[5])
        dst_port = _parse_port(parsed[6])
        if src_port not in ports and dst_port not in ports:
            continue
        rows.append(
            {
                "time": _parse_int(parsed[0]),
                "duration": _parse_int(parsed[1]),
                "src_device": parsed[2].strip(),
                "dst_device": parsed[3].strip(),
                "protocol": parsed[4].strip(),
                "src_port": src_port,
                "dst_port": dst_port,
                "src_packets": _parse_int(parsed[7]),
                "dst_packets": _parse_int(parsed[8]),
                "src_bytes": _parse_int(parsed[9]),
                "dst_bytes": _parse_int(parsed[10]),
            }
        )
    return pd.DataFrame(rows, columns=NETFLOW_COLUMNS)


def parse_wls_lines(lines: Iterable[str], max_rows: int) -> pd.DataFrame:
    """Normalize bounded Windows-logon reference rows when logon type is present.

    This function intentionally accepts the normalized seven-field interchange
    used by the V2 reference builder:
      time,user,src_device,dst_device,logon_type,auth_package,status

    The source-specific LANL WLS decoder is responsible for converting the
    published source schema to this normalized form. No synthetic class label is
    ever added here.
    """
    columns = [
        "time",
        "user",
        "src_device",
        "dst_device",
        "logon_type",
        "auth_package",
        "status",
    ]
    if max_rows <= 0:
        return pd.DataFrame(columns=columns)
    rows: list[dict[str, object]] = []
    for raw in lines:
        if len(rows) >= max_rows:
            break
        text = str(raw).strip()
        if not text or text.lower().startswith("time,"):
            continue
        parsed = next(csv.reader(StringIO(text)))
        if len(parsed) != 7:
            continue
        rows.append(
            {
                "time": _parse_int(parsed[0]),
                "user": parsed[1].strip(),
                "src_device": parsed[2].strip(),
                "dst_device": parsed[3].strip(),
                "logon_type": parsed[4].strip(),
                "auth_package": parsed[5].strip(),
                "status": parsed[6].strip(),
            }
        )
    return pd.DataFrame(rows, columns=columns)
