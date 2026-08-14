# Remote Admin Anomaly V1 — Protocol Fidelity Matrix

This document records what V1 actually exercised on the wire. A protocol is never promoted to `REAL` merely because a package is installed or a synthetic builder can emit similar bytes.

## Final V1 matrix

| Protocol | Final wire source | Wire fidelity | Semantic fidelity | Final V1 status | Evidence / limitation |
|---|---|---:|---:|---|---|
| SSH | OpenSSH client/server plus Paramiko client -> OpenSSH server in separate Linux network namespaces | REAL | HIGH for bounded SSH admin/SCP/SFTP-style behavior | **validated** | Core smoke `31788947200`; current Implementation Final `31817953836`; final 1k `31818445960` includes OpenSSH and Paramiko wire sessions |
| SMB | `smbclient` and `smbprotocol` -> Samba across namespace bridge | REAL | HIGH for SMB2/3 share/list/get/put; no payload execution | **validated** | Core smoke `31788947200`; alternate-client gate `31817953836`; final 1k `31818445960` includes both clients |
| RDP | FreeRDP -> xrdp bounded sessions across namespace bridge | REAL protocol wire | PARTIAL Windows semantics because server is Linux/xrdp, not native Windows | **validated for V1 network-wire cohort** | Current V4 `31817920754`, Implementation Final `31817953836`, final 1k `31818445960`; 250/250 RDP sessions successful in final 1k |
| VNC/RFB | bounded RFB client -> TigerVNC | REAL RFB wire | HIGH for RFB handshake/session transport; PARTIAL human-interaction semantics | **validated for V1 network-wire cohort** | Current V4 `31817920754`, Implementation Final `31817953836`, final 1k `31818445960`; 250/250 VNC sessions successful in final 1k |
| DCE/RPC / DCOM | Samba/rpcclient-style fixture only | PARTIAL / non-native | PARTIAL DCOM semantics | **not a claimed native-Windows training protocol** | Native Windows DCOM/TCP-135 semantics remain an external fidelity gap. V1 never relabels the Linux/Samba fixture as native Windows DCOM. |
| WinRM / WS-Man | bounded HTTP/SOAP fixture | PARTIAL | PARTIAL WinRM semantics | **challenge/fidelity fixture only; excluded from accepted V1 train corpus** | Native Windows WinRM remains an external fidelity gap. Final 1k train protocols are only SSH/SMB/RDP/VNC. |

## Implementation diversity evidence

Final implementation families retained in the 1k corpus include:

- `ssh:openssh->openssh-server`;
- `ssh:paramiko->openssh-server`;
- `smb:smbclient->samba`;
- `smb:smbprotocol->samba`;
- `rdp:freerdp->xrdp`;
- `vnc:rfb-python->tigervnc`.

The implementation choice is evaluation metadata and is forbidden from production model features. Alternative-client implementations are used as a challenge dimension rather than as an easy label cue.

## Promotion rules used in V1

A protocol is marked network-wire `validated` only when all relevant conditions hold:

1. a real implementation process is running in the isolated lab;
2. a client process completes a bounded session/handshake over `br-adminlab`;
3. traffic appears in retained full PCAP;
4. Suricata/Zeek parser visibility exists for the resulting traffic;
5. production Gold can map the protocol with >=90% session coverage;
6. failure is written as unavailable/partial instead of being replaced by synthetic bytes;
7. no external target, unrestricted forwarding, payload execution, malware or C2 framework is introduced.

Final 1k production mapping coverage by protocol:

- RDP: `1.000`;
- SMB: `1.000`;
- SSH: `0.972`;
- VNC: `1.000`.

## What V1 does **not** claim

- xrdp traffic is not evidence that native Windows RDP server behavior has been exhaustively covered.
- Samba/rpcclient is not native Windows DCOM.
- A bounded SOAP fixture is not native Windows WinRM.
- A Linux namespace topology is not an independent enterprise OS/identity/network estate.
- Passing wire fidelity does not imply that the final anomaly model passed; the V1 model hypothesis was rejected separately by the research quality gate.

## Deliberate V1 exclusion

Sliver, Mythic, Havoc, Cobalt Strike, Metasploit payloads and similar C2 frameworks remain excluded from V1. A later adversarial challenge may add bounded framework-derived traffic only after a new remote-admin behavioral hypothesis passes its own research gate. This prevents framework fingerprints from becoming an easy label shortcut.
