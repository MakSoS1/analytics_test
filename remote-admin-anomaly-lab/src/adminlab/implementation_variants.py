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


def _identity(record: SessionRecord) -> str:
    # Counterfactual twins must stay identical. Outside Stage F, campaigns are
    # the evaluation unit, so client implementation is selected for the whole
    # campaign rather than independently per session.
    return record.pair_id or record.campaign_id or record.session_id


def _hash_int(value: str, seed: int) -> int:
    digest = hashlib.sha256(f"{seed}|{value}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def _use_alternative(record: SessionRecord, seed: int) -> bool:
    # A bounded 20% implementation cohort leaves a large primary-client train
    # population while producing enough truly unseen implementation campaigns.
    return _hash_int(f"implementation-cohort|{_identity(record)}", seed) % 5 == 0


def materialize_implementation_variants(
    records: list[SessionRecord], *, stage: str, seed: int
) -> list[SessionRecord]:
    """Assign only client/server stacks that the wire runner actually implements.

    Alternative implementations are introduced in G/H. Earlier stages keep the
    stable primary client so V4/baseline fidelity changes one dimension at a time.
    Selection is label-neutral and group-stable: a counterfactual pair or campaign
    never gets a different implementation merely because of row order or label.
    """
    output: list[SessionRecord] = []
    for record in records:
        clients = CLIENTS.get(record.protocol, (record.client_stack or "unknown",))
        if record.task_id == "approved_forwarding" and record.protocol == "ssh":
            client = "openssh"
        elif stage in {"G", "H"} and len(clients) > 1 and _use_alternative(record, seed):
            client = clients[1]
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
