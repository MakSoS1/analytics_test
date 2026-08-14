#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
  iproute2 \
  iputils-ping \
  openssh-client \
  openssh-server \
  samba \
  smbclient \
  tcpdump \
  suricata \
  zstd \
  jq \
  ca-certificates \
  procps

sudo mkdir -p /run/sshd

printf 'installed: '
for cmd in ip tc ping ssh sshd smbd smbclient tcpdump suricata zstd jq; do
  command -v "$cmd" >/dev/null
  printf '%s ' "$cmd"
done
printf '\n'
