# Remote Admin Anomaly V1 — Protocol Fidelity Matrix

This document records what the V1 corpus actually exercises on the wire. A protocol is never promoted to `real` merely because a package is installed or a synthetic builder can emit similar bytes.

| Protocol | Current wire source | Wire fidelity | Semantic fidelity | V1 status | Evidence |
|---|---|---:|---:|---|---|
| SSH | OpenSSH client/server in separate Linux network namespaces | REAL | HIGH for SSH admin/SCP/SFTP-style behavior | validated | `Remote Admin Anomaly V1 Smoke` run `31788947200`: 25 successful real SSH sessions in mixed 40-session smoke |
| SMB | `smbclient` -> Samba server across namespace bridge | REAL | HIGH for SMB2/3 share/list/get/put; no payload execution | validated | run `31788947200`: 15 successful real SMB sessions; transferred suspicious markers are inert |
| RDP | planned xrdp/FreeRDP bounded session fixture | unmeasured | partial Windows semantics expected on Linux | pending probe | Must pass actual wire/session probe before inclusion in data stages |
| VNC/RFB | planned TigerVNC fixture | unmeasured | expected high RFB wire fidelity, partial user interaction fidelity | pending probe | Must pass real listener/client handshake and capture evidence |
| DCE/RPC | planned Samba/rpcclient fixture | unmeasured | partial DCOM semantics | pending probe | Must be labelled `real_dcerpc_samba` / `partial_dcom`; never represented as native Windows DCOM |
| WinRM | planned bounded WS-Man fixture | unmeasured | partial WinRM semantics | pending probe | Native Windows WinRM is explicitly deferred to later fidelity holdout |

## Promotion rules

A protocol may be marked `validated` only if all relevant conditions hold:

1. a real implementation process is running in a lab namespace;
2. a client process completes a bounded session or handshake over `br-adminlab`;
3. the traffic appears in a retained PCAP;
4. the parser/feature pipeline records the visibility actually used by the model;
5. failure of a package/tool/handshake is written as `unavailable` or `partial`, not silently replaced by synthetic bytes;
6. no external target, unrestricted forwarding, payload execution, malware or C2 framework is introduced.

## Deliberate V1 exclusion

Sliver, Mythic, Havoc, Cobalt Strike, Metasploit payloads and similar C2 frameworks are excluded from V1. A later adversarial challenge can add bounded framework-derived traffic only after the remote-admin behavioral baseline and challenge holdouts are stable. This prevents framework fingerprints from becoming an easy label shortcut.
