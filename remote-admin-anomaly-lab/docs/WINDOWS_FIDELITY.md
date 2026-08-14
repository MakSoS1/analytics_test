# Native Windows Fidelity Corpus

## Purpose

The Linux namespace corpus is intentionally insufficient to claim full semantic fidelity for:

- T1021.001 RDP — xrdp/FreeRDP proves transport/negotiation, not a native Windows desktop lifecycle;
- T1021.002 SMB/Windows Admin Shares — authenticated Samba is real SMB wire but not Windows `ADMIN$`/`C$`/`IPC$` semantics;
- T1021.003 DCOM — Samba DCE/RPC is not native DCOM;
- T1021.006 WinRM — the Linux WS-Man fixture is not PowerShell Remoting on Windows.

Those records remain explicitly `partial_*` and are not promoted as native-Windows ground truth.

## Accepted native topology

```text
Windows client / PAW         Windows target
10.77.0.31/24  ---------->   10.77.0.32/24
        |                         |
        +------ isolated L2 ------+
                  |
             packet capture
```

Hard requirements:

1. Both machines are real Windows hosts or VMs.
2. Both are inside the isolated `10.77.0.0/24` research network.
3. No default route to the Internet during capture.
4. Target address is fixed to `10.77.0.32`; the harness rejects other targets.
5. Test credentials are dedicated lab credentials supplied through secrets/environment and never copied to manifests.
6. Full pktmon capture is retained before feature extraction.
7. Native rows are a separate fidelity category and challenge slice.

## Automated native cases

The PowerShell harness `scripts/windows_fidelity_capture.ps1` can exercise, using inert read/query operations:

- authenticated SMB connection to `\\10.77.0.32\ADMIN$`;
- WinRM / PowerShell Remoting session to `10.77.0.32:5985`;
- DCOM-backed CIM query using `New-CimSessionOption -Protocol Dcom`;
- connectivity evidence for RDP `3389`.

SMB writes, remote service creation, scheduled task creation, payload execution, credential dumping and any external target are deliberately absent from V1.

## RDP limitation

A full RDP fidelity record requires an interactive Windows desktop session: authentication, desktop establishment, bounded benign interaction, reconnect/disconnect and retained capture. A service-context GitHub runner cannot honestly substitute for that GUI lifecycle. Therefore the automated harness records RDP port/preflight evidence but sets:

```json
{"rdp_full_session_accepted": false}
```

until an interactive Windows capture is supplied from the isolated lab.

## GitHub Actions workflow

`.github/workflows/remote-admin-windows-fidelity.yml` is manual-only.

- `hosted_preflight` runs a Windows hosted environment and reports tool availability only. Its result is **never accepted as native remote fidelity** because there is no second isolated Windows endpoint.
- `native_lab_capture` requires a self-hosted Windows runner labelled `remote-admin-client` in the isolated lab, plus a preconfigured Windows target at `10.77.0.32`. Credentials come from `WINDOWS_LAB_USER` and `WINDOWS_LAB_PASSWORD` repository secrets.

The workflow uploads capture/report artifacts; it does not publish GitHub Releases.

## Dataset placement

Accepted native captures use the same recoverable layering:

```text
bronze/windows-native/<shard>/captures/*.pcapng|*.pcap
bronze/windows-native/<shard>/manifests/*.jsonl|*.parquet
silver/windows-native/<shard>/suricata/*
silver/windows-native/<shard>/zeek/*
gold/windows-native/<shard>/*
quality/windows-native/<shard>/fidelity.json
```

Native Windows should initially remain a challenge/holdout slice. It must not silently replace or overwrite the Linux approximation shards.
