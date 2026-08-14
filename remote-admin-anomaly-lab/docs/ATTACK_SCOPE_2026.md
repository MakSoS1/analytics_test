# ATT&CK scope — Remote Admin Anomaly V1

Verified against the live MITRE ATT&CK `T1021 Remote Services` page on 2026-08-14.

Current sub-techniques:

| ID | Name | V1 treatment |
|---|---|---|
| T1021.001 | Remote Desktop Protocol | network corpus; Linux xrdp fixture is partial semantic fidelity; native Windows challenge required |
| T1021.002 | SMB/Windows Admin Shares | real SMB wire; Samba public/private shares are partial semantic fidelity until native Windows Admin Shares challenge |
| T1021.003 | Distributed Component Object Model | Samba DCE/RPC probe is `partial_dcom`; excluded from primary train corpus |
| T1021.004 | SSH | primary real-wire corpus |
| T1021.005 | VNC | primary real-wire corpus after interactive RFB gate |
| T1021.006 | Windows Remote Management | WS-Man fixture is `partial_winrm`; excluded from primary train corpus; native Windows challenge required |
| T1021.007 | Cloud Services | separate cloud/identity telemetry corpus, not mixed into this PCAP-centric network corpus |
| T1021.008 | Direct Cloud VM Connections | separate cloud control-plane/session telemetry corpus |

`X11` and `Bluetooth` are **not** T1021.007/.008 in the current ATT&CK version and must not appear in V1 documentation or labels.

## Why cloud is separated

T1021.007 and T1021.008 are not clean extensions of the same packet-observation problem. Cloud Services detection commonly depends on identity/control-plane evidence such as cloud logins, user agents, API/CLI activity and cloud audit logs. Direct Cloud VM Connections use provider-native control-plane/session mechanisms. Mixing those events with SSH/RDP/SMB/VNC PCAP rows would create an incoherent feature contract.

Therefore the project namespace is intentionally split conceptually as:

```text
remote-admin-network/
  T1021.001-.006

remote-admin-cloud/
  T1021.007-.008
```

The current repository implements `remote-admin-network`. A future cloud corpus should have its own Bronze contract (CloudTrail / Entra / GCP audit / cloud-session metadata rather than requiring PCAP for every record).

## Authoritative references

- MITRE ATT&CK T1021: https://attack.mitre.org/techniques/T1021/
- T1021.007: https://attack.mitre.org/techniques/T1021/007/
- T1021.008: https://attack.mitre.org/techniques/T1021/008/
