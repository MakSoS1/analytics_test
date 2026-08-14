# V1 Plan Amendment — Evidence-Driven Wire Corpus Scaling

Date: 2026-08-14  
Final resolution: **STOP_AT_1K**

## Why the original 201k target is not a blind acceptance criterion

The initial design budgeted about 201,000 behavioral sessions before a real kernel/application implementation existed. The first validated smoke disproved the implicit one-session/one-flow assumption: 40 behavioral sessions generated 102 real TCP connections. RDP/VNC also have materially different execution cost from synthetic packet builders.

Therefore the project must not manufacture synthetic padding merely to hit a pre-wire row count. The corpus target is quality- and learning-curve-driven while 201k remains only a historical upper design envelope, not a target V1 must reach.

## Mandatory scaling gate — completed

The project completed the required pre-fan-out evidence sequence:

1. real SSH/SMB/RDP/VNC implementation gates;
2. exact 1,000-session planner audit;
3. full 1,000-session real-wire capture;
4. complete Bronze PCAP + manifests/checksums;
5. Suricata + Zeek Silver;
6. production-compatible Suricata-flow Gold;
7. grouped split/leakage audit;
8. M0/M1/M2 training;
9. low-FPR, challenge, hard-benign and campaign evaluation;
10. grouped learning curve and shortcut audit.

Final research source: run `31818445960`.

## Final scaling evidence

M1 LightGBM:

- validation PR-AUC `0.5074707204`;
- test PR-AUC `0.5137590769`;
- challenge PR-AUC `0.4222839299`;
- challenge campaign recall at the primary operating point `0.0`.

The full M1 is outperformed by nuisance-only baselines, so the automatic quality failure remains `shortcut_risk`.

Grouped learning curve:

- 25%: PR-AUC `0.55944`;
- 50%: PR-AUC `0.51299`;
- 75%: PR-AUC `0.52296`;
- 100%: PR-AUC `0.50915`;
- final delta PR-AUC: `-0.0138075260`;
- recommendation: `prefer_diversity_or_holdout_analysis`.

## Final scale policy application

The policy said:

- scale only while validation/challenge quality is materially improving;
- prefer diversity when curves saturate;
- if quality is poor, do not scale a broken hypothesis;
- never replace retained PCAP with synthetic padding.

The observed result satisfies the **do not scale** branch. Therefore:

```text
decision      = STOP_AT_1K
allow_scale   = false
next_sessions = 0
4k/10k/20k/40k = blocked for V1
```

This is not a failure to execute the scaling plan. It is the intended evidence-driven stopping condition.

## What may reopen scaling

A future V2 may re-enter the gate only after changing the feature/data hypothesis materially, for example with independently collected environments, native Windows fidelity cohorts, richer longitudinal/policy context available at inference time, or real/reference traffic.

A V2 must pass a fresh 1k quality gate before any larger fan-out. Merely changing seeds or generating more rows from the same distribution is insufficient.

## Protocol inclusion result

- Accepted V1 train/research core: SSH, SMB, RDP, VNC.
- RDP uses FreeRDP -> xrdp and is explicitly partial Windows semantics despite real protocol wire.
- VNC uses real RFB/TigerVNC wire.
- Alternative SSH/SMB clients (Paramiko, smbprotocol) are exercised and used for implementation holdouts.
- Native Windows DCOM/WinRM remains an external fidelity gap.
- Sliver/Mythic/Havoc/Cobalt Strike/Metasploit-style framework traffic remains excluded from V1.

## Retained evidence

- GitHub Actions artifact: `remote-admin-research-gate-v2-31818445960`, ID `9226887886`.
- Artifact digest: `sha256:40a463b9f16d4251d3b40b8915ef7a7425a883edd2916484acab660328fbbf72`.
- Private HF quarantine: `Maksim123321/remote-admin-anomaly-v1/quarantine/rejected/gh-31818445960`.
- Full Bronze PCAP remains the rollback source; PCAP is not published as a GitHub Release asset.
