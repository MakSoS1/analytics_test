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
  samba-common-bin \
  smbclient \
  tcpdump \
  suricata \
  zstd \
  jq \
  curl \
  netcat-openbsd \
  ca-certificates \
  procps

sudo mkdir -p /run/sshd

# Extended protocol implementations are useful for fidelity probes, but they are
# deliberately not a hard dependency of the SSH/SMB core. Ubuntu package names
# can differ across hosted-runner image revisions, so install only candidates
# present in the current apt index and record what was actually available.
optional_extended_packages=(
  xrdp
  freerdp3-x11
  freerdp2-x11
  tigervnc-standalone-server
  tigervnc-tools
)
installed_optional=()
missing_optional=()
for pkg in "${optional_extended_packages[@]}"; do
  if apt-cache show "$pkg" >/dev/null 2>&1; then
    if sudo apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1; then
      installed_optional+=("$pkg")
    else
      missing_optional+=("$pkg:install-failed")
    fi
  else
    missing_optional+=("$pkg:not-in-index")
  fi
done

printf 'installed: '
for cmd in ip tc ping ssh sshd smbd smbclient rpcclient tcpdump suricata zstd jq curl docker; do
  command -v "$cmd" >/dev/null
  printf '%s ' "$cmd"
done
printf '\n'
printf 'optional_extended_packages installed=%s missing=%s\n' \
  "${installed_optional[*]:-none}" "${missing_optional[*]:-none}"

# Keep the offline parser deterministic across hosted runner image updates.
docker pull zeek/zeek:8.2.1 >/dev/null
echo 'zeek_parser_image=zeek/zeek:8.2.1'
