# Stage M VM-wire runbook

This runbook materializes the primary positive corpus with real operating-system and application network stacks. Hosted netns CI remains a functional/regression environment; VM-wire captures are the training-grade source of truth for stack, TCP/TLS and environment realism.

## Topology

    Linux client VM ----\
                         \
    Windows client VM ---- Router VM (tc/netem) ---- Server VM
                         /                            | 10.20.0.20 services
    holdout client VM --/                             | 10.20.0.21 WSS
                                                      | 10.20.0.22 nginx front
                               |
                               +---- Sensor VM / dumpcap mirror
                                      archival pcapng

A separate resolver VM uses 10.20.0.23. There must be no dependency on public DNS or Internet C2. All generated application destinations are local `.test` aliases or fixed private lab addresses.

## Required controller runners

Main corpus runner labels: `self-hosted`, `linux`, `coverlab-controller`.

Independent environment holdout runner labels: `self-hosted`, `linux`, `coverlab-controller-holdout`.

The second runner must control a genuinely different VM environment/host or hypervisor. Do not point both runner labels at the same VM set and call it H_environment.

## Node requirements

Every repository-bearing node must be checked out at the exact controller `GITHUB_SHA`. The remote controller fails closed on revision mismatch.

The controller needs Python 3.12, ssh/scp, dumpcap/editcap, Suricata, Docker (Zeek 8.2.1), zstd and sha256sum.

Linux client VMs are bootstrapped by `vm/bootstrap_linux_client.sh`. It creates the Python venv and builds the actual Go, Java and Rust helpers used by Stage M, discovers Chrome/Chromium, and validates passwordless sudo for the bounded raw-header family.

Windows VMs must provide PowerShell, .NET HttpClient, ClientWebSocket, WinHTTP, curl.exe when declared, and Microsoft Edge when `edge_chromium` is declared. Preflight fails before capture if a declared runtime is missing.

## Sensor correctness gate

The controller starts `dumpcap` on the configured sensor interface and forces real client-to-server HTTPS transactions. The capture file must grow before generation begins. A wrong NIC, management-only interface or broken mirror therefore fails closed.

The archival master is `capture.pcapng.zst`; a deterministic classic-PCAP derivative is used by the existing parser pipeline. SHA-256 digests for pcapng, PCAP, inventory and plan are stored in release metadata.

## Holdouts

Microsoft Edge is a strict `H_client` implementation. `edge_chromium` campaigns are never training eligible.

For a different host/hypervisor use `.github/workflows/cover-channel-stage-m-vm-holdout.yml` with a second inventory such as `vm/inventory.holdout.example.json`. Every row is forcibly `split_role=H_environment` and `training_eligible=false`.

## Real long timing

Use `.github/workflows/cover-channel-stage-m-vm-long.yml` for 1,200 s and 3,600 s cadences with `COVERLAB_STAGE_M_TIME_SCALE=1` and no sleep cap. Only wall-clock captures may be marked `timing_fidelity=wire_real`; hosted accelerated captures remain `accelerated_shape_only`.

## Main capture

The primary workflow is `.github/workflows/cover-channel-stage-m-vm.yml`. Always run VM smoke before full generation.

Example controller invocation:

    cd cover-channel-lab
    bash scripts/run_stage_m_vm.sh smoke 0 1 lan /opt/coverlab/inventory.json /tmp/stage-m-vm M-vm-positive-00 ~/.ssh/id_ed25519

## Promotion gates

A VM-wire release is not promotable unless: every campaign is positive-only; the sensor wire-path probe passed; pcapng and PCAP are non-empty and checksummed; Suricata/Zeek, capture-tail and dataset contract passed; diversity audit passed; H_client/H_environment do not leak into train; accelerated timing is not marked wire-real; and GitHub plus Hugging Face persistence is confirmed.

VM workflows are intentionally not presented as completed evidence until an actual self-hosted controller and its inventories have executed them.
