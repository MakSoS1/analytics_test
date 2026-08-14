from __future__ import annotations

import hashlib
from dataclasses import replace

from .manifest import SessionRecord

CLIENTS = {
    "ssh": ("openssh", "paramiko"),
    "smb": ("smbclient", "smbprotocol"),
    "rdp": ("freerdp",),
    "vnc": ("rfb-python",),
    "winrm": ("curl-wsman",),
    "dcerpc": ("rpcclient",),
}
SERVER_STACKS = {
    "ssh": "openssh-server",
    "smb": "samba",
    "rdp": "xrdp",
    "vnc": "tigervnc",
    "winrm": "wsman-fixture",
    "dcerpc": "samba-rpc",
}


def _bucket(record: SessionRecord, seed: int) -> int:
    identity = record.pair_id or record.session_id
    digest = hashlib.sha256(f"{seed}|{identity}|{record.protocol}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def materialize_implementation_variants(
    records: list[SessionRecord], *, stage: str, seed: int
) -> list[SessionRecord]:
    """Assign only client/server stacks that the wire runner actually implements.

    Alternative implementations are introduced in G/H. Earlier stages keep the
    stable primary client so V4/baseline fidelity changes one dimension at a time.
    Counterfactual pairs share one selection key and therefore the same stack.
    """
    output: list[SessionRecord] = []
    for record in records:
        clients = CLIENTS.get(record.protocol, (record.client_stack or "unknown",))
        if record.task_id == "approved_forwarding" and record.protocol == "ssh":
            client = "openssh"
        elif stage in {"G", "H"} and len(clients) > 1:
            client = clients[_bucket(record, seed) % len(clients)]
        else:
            client = clients[0]
        server = SERVER_STACKS.get(record.protocol, "unknown")
        implementation = f"{record.protocol}:{client}->{server}"
        output.append(
            replace(
                record,
                client_stack=client,
                server_stack=server,
                implementation_id=implementation,
            )
        )
    return output
