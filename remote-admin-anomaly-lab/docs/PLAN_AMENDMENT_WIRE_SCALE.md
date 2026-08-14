# V1 Plan Amendment — Evidence-Driven Wire Corpus Scaling

Date: 2026-08-14

## Why the original 201k target is no longer a blind acceptance criterion

The initial design budgeted about 201,000 behavioral sessions before a real kernel/application implementation existed. The first validated smoke disproved the implicit one-session/one-flow assumption: 40 behavioral sessions generated 102 real TCP connections. RDP/VNC also have materially different execution cost from synthetic packet builders.

Therefore the project must not manufacture synthetic padding merely to hit a pre-wire row count. The corpus target is now **quality- and learning-curve-driven** while 201k remains the upper planned scale envelope.

## Mandatory scaling gate

Before the expensive fan-out:

1. Generate an extended Stage A corpus with 1,000 real behavioral sessions using validated SSH, SMB, RDP and VNC wire fixtures.
2. Retain complete Bronze PCAP, Silver Suricata/Zeek and Gold features.
3. Require session-to-many-flow mapping coverage >= 0.95 and leakage audit PASS.
4. Measure sessions/minute, flows/session, capture bytes/session and parser bytes/session.
5. Train M0 deterministic, M1 LightGBM and M2 benign-only IsolationForest baselines.
6. Evaluate PR-AUC, Recall, Precision, F1, FPR and challenge/holdout behavior where defined.
7. Produce learning-curve points from increasing Stage A subsets.
8. Choose the next corpus size from observed model saturation and wall-clock/storage cost.

## Scale policy

- If validation/challenge quality is still materially improving, continue the B-H sharded expansion up to the 201k envelope.
- If curves saturate earlier, prefer more **diversity** (host pairs, nuisance profiles, timings, counterfactuals, client/server implementations) instead of duplicate sessions.
- If quality is poor, do not scale a broken generator. Fix wire fidelity, labels, mapping or feature leakage first.
- No generated row may replace the retained PCAP as the rollback source.

## Protocol inclusion policy

- Training core: SSH, SMB, RDP (Linux xrdp wire fidelity explicitly labelled partial Windows semantics), VNC/RFB after their integration smoke passes.
- Challenge-only: bounded WS-Man/WinRM-like HTTP fixture labelled `partial_winrm`.
- Fidelity evidence only, not native DCOM training: Samba/rpcclient DCE/RPC labelled `partial_dcom` because it does not reproduce native Windows DCOM endpoint behavior on TCP/135.
- Native Windows DCOM/WinRM remains a later Windows fidelity holdout.
- Sliver/Mythic/Havoc/Cobalt Strike/Metasploit-style framework traffic remains excluded from V1 training to prevent easy framework-fingerprint shortcuts.
