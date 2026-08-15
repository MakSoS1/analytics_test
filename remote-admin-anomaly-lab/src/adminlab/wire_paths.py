from __future__ import annotations

from typing import Any, Mapping

import pandas as pd

PROXYJUMP_HOST = "10.77.0.21"
SSH_PORT = 22


def expected_wire_tuples(row: Mapping[str, Any]) -> list[tuple[str, str, int]]:
    """Return the network tuples expected for one orchestrated remote-admin session.

    ``src_ip``/``dst_ip`` in the manifest remain the logical administration
    endpoints used by behavioral history.  A bounded approved SSH forwarding
    session is different on the wire: the client connects to the jump host and
    the jump host opens the second leg to the logical target.  Ground-truth
    correspondence may use these tuples, but they are never model features.
    """
    src = str(row.get("src_ip", ""))
    dst = str(row.get("dst_ip", ""))
    port = int(row.get("dst_port", 0) or 0)
    protocol = str(row.get("protocol", "")).lower()
    task = str(row.get("task_id", "")).lower()
    action = str(row.get("action", "")).lower()

    if protocol == "ssh" and port == SSH_PORT and (
        task == "approved_forwarding" or action == "bounded_proxyjump"
    ):
        hops = [(src, PROXYJUMP_HOST, SSH_PORT), (PROXYJUMP_HOST, dst, SSH_PORT)]
    else:
        hops = [(src, dst, port)]

    output: list[tuple[str, str, int]] = []
    seen: set[tuple[str, str, int]] = set()
    for hop in hops:
        if not hop[0] or not hop[1] or hop[2] <= 0:
            raise ValueError(f"invalid expected wire tuple: {hop}")
        if hop not in seen:
            output.append(hop)
            seen.add(hop)
    return output


def expand_sessions_for_wire_mapping(sessions: pd.DataFrame) -> pd.DataFrame:
    """Expand logical sessions into ground-truth wire-hop rows for parsers."""
    rows: list[dict[str, Any]] = []
    for session in sessions.to_dict("records"):
        hops = expected_wire_tuples(session)
        for index, (src, dst, port) in enumerate(hops):
            expanded = dict(session)
            expanded["src_ip"] = src
            expanded["dst_ip"] = dst
            expanded["dst_port"] = int(port)
            expanded["wire_hop_index"] = index
            expanded["wire_hop_count"] = len(hops)
            rows.append(expanded)
    return pd.DataFrame(rows)
