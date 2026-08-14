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
for cmd in ip tc ping ssh sshd smbd smbclient tcpdump suricata zstd jq docker; do
  command -v "$cmd" >/dev/null
  printf '%s ' "$cmd"
done
printf '\n'

# Keep the offline parser deterministic across hosted runner image updates.
docker pull zeek/zeek:8.2.1 >/dev/null
echo 'zeek_parser_image=zeek/zeek:8.2.1'
