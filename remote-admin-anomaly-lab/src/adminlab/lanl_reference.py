from __future__ import annotations

import csv
import json
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
WLS_COLUMNS = [
    "time",
    "event_id",
    "user",
    "domain",
    "src_device",
    "dst_device",
    "logon_type",
    "logon_type_id",
    "auth_package",
    "status",
    "logon_id",
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
    """Parse a bounded LANL 2017 netflow slice without inventing labels."""
    if max_rows <= 0:
        return pd.DataFrame(columns=NETFLOW_COLUMNS)
    rows: list[dict[str, object]] = []
    ports = {int(p) for p in remote_admin_ports}
    for raw in lines:
        if len(rows) >= max_rows:
            break
        text = str(raw).strip()
        if not text or text.lower().startswith(("time,", "epoch_time,")):
            continue
        try:
            parsed = next(csv.reader(StringIO(text)))
        except csv.Error:
            continue
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


def _normalized_wls_csv(text: str) -> dict[str, object] | None:
    try:
        parsed = next(csv.reader(StringIO(text)))
    except csv.Error:
        return None
    if len(parsed) != 7:
        return None
    logon_type = parsed[4].strip()
    if logon_type.lower() != "network":
        return None
    return {
        "time": _parse_int(parsed[0]),
        "event_id": 0,
        "user": parsed[1].strip(),
        "domain": "",
        "src_device": parsed[2].strip(),
        "dst_device": parsed[3].strip(),
        "logon_type": logon_type,
        "logon_type_id": 3,
        "auth_package": parsed[5].strip(),
        "status": parsed[6].strip(),
        "logon_id": "",
    }


def _rocketgraph_wls_csv(text: str) -> dict[str, object] | None:
    """Parse Rocketgraph's documented LANL AuthEvents `_2v.csv` row.

    The mirror's published 21-field order is:
      epoch_time,event_id,log_host,logon_type,logon_type_description,username,
      domain_name,logon_id,subject_username,subject_domain_name,subject_logon_id,
      status,source,service_name,destination,authentication_package,
      failure_reason,process_name,process_id,parent_process_name,parent_process_id
    """
    try:
        parsed = next(csv.reader(StringIO(text)))
    except csv.Error:
        return None
    if len(parsed) != 21:
        return None
    description = parsed[4].strip()
    logon_type_id = _parse_int(parsed[3])
    if description.lower() != "network" and logon_type_id != 3:
        return None
    event_id = _parse_int(parsed[1])
    if event_id not in {4624, 4625, 4634, 4648, 4672, 4768, 4769, 4770, 4774, 4776}:
        return None
    log_host = parsed[2].strip()
    source = parsed[12].strip() or log_host
    destination = parsed[14].strip() or log_host
    return {
        "time": _parse_int(parsed[0]),
        "event_id": event_id,
        "user": parsed[5].strip(),
        "domain": parsed[6].strip(),
        "src_device": source,
        "dst_device": destination,
        "logon_type": description or ("Network" if logon_type_id == 3 else ""),
        "logon_type_id": logon_type_id,
        "auth_package": parsed[15].strip(),
        "status": parsed[11].strip(),
        "logon_id": parsed[7].strip(),
    }


def _official_wls_json(text: str) -> dict[str, object] | None:
    try:
        event = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(event, dict):
        return None
    event_id = _parse_int(event.get("EventID", 0))
    description = str(event.get("LogonTypeDescription", "")).strip()
    logon_type_id = _parse_int(event.get("LogonType", 0))
    if description.lower() != "network" and logon_type_id != 3:
        return None
    if event_id not in {4624, 4625, 4634, 4648, 4672, 4768, 4769, 4770, 4774, 4776}:
        return None
    destination = str(event.get("Computer", event.get("LogHost", event.get("Destination", "")))).strip()
    source = str(event.get("Source", "")).strip()
    return {
        "time": _parse_int(event.get("Time", 0)),
        "event_id": event_id,
        "user": str(event.get("UserName", "")).strip(),
        "domain": str(event.get("DomainName", "")).strip(),
        "src_device": source,
        "dst_device": destination,
        "logon_type": description or ("Network" if logon_type_id == 3 else ""),
        "logon_type_id": logon_type_id,
        "auth_package": str(event.get("AuthenticationPackage", "")).strip(),
        "status": str(event.get("Status", "")).strip(),
        "logon_id": str(event.get("LogonID", "")).strip(),
    }


def parse_wls_lines(lines: Iterable[str], max_rows: int) -> pd.DataFrame:
    """Parse LANL WLS from official JSONL or documented mirror CSV forms.

    Official LANL WLS is JSONL. Rocketgraph publishes a documented transformed
    AuthEvents `_2v.csv` mirror with 21 fields. A compact seven-field interchange
    remains accepted for local tests. No class label is created in any path.
    """
    if max_rows <= 0:
        return pd.DataFrame(columns=WLS_COLUMNS)
    rows: list[dict[str, object]] = []
    for raw in lines:
        if len(rows) >= max_rows:
            break
        text = str(raw).strip()
        if not text or text.lower().startswith(("time,", "epoch_time,")):
            continue
        if text.startswith("{"):
            row = _official_wls_json(text)
        else:
            row = _rocketgraph_wls_csv(text) or _normalized_wls_csv(text)
        if row is not None:
            rows.append(row)
    return pd.DataFrame(rows, columns=WLS_COLUMNS)
