#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-start}"
STATE_DIR="${2:-/tmp/adminlab-services}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "service operations require root" >&2
  exit 2
fi

mkdir -p "$STATE_DIR" "$STATE_DIR/pids" "$STATE_DIR/logs" "$STATE_DIR/ssh" "$STATE_DIR/samba"

stop_services() {
  shopt -s nullglob
  for pgfile in "$STATE_DIR"/pids/*.pgid; do
    pgid="$(cat "$pgfile" 2>/dev/null || true)"
    if [[ "$pgid" =~ ^[0-9]+$ ]] && kill -0 -- "-$pgid" 2>/dev/null; then
      kill -TERM -- "-$pgid" 2>/dev/null || true
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 -- "-$pgid" 2>/dev/null || break
        sleep 0.2
      done
      if kill -0 -- "-$pgid" 2>/dev/null; then
        kill -KILL -- "-$pgid" 2>/dev/null || true
      fi
    fi
    rm -f "$pgfile"
  done
}

start_ssh() {
  local ns="$1"
  local address="$2"
  local name="$3"
  local dir="$STATE_DIR/ssh/$name"
  mkdir -p "$dir"
  rm -f "$dir/host_key" "$dir/host_key.pub"
  ssh-keygen -q -t ed25519 -N '' -f "$dir/host_key" >/dev/null
  cp "$STATE_DIR/ssh/client_ed25519.pub" "$dir/authorized_keys"
  chmod 600 "$dir/authorized_keys" "$dir/host_key"

  cat >"$dir/sshd_config" <<EOF
Port 22
ListenAddress $address
HostKey $dir/host_key
PidFile $dir/sshd.pid
AuthorizedKeysFile $dir/authorized_keys
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
PrintMotd no
LogLevel VERBOSE
AllowTcpForwarding yes
PermitOpen 10.77.0.21:22 10.77.0.22:22 10.77.0.23:445 10.77.0.24:3389 10.77.0.25:5900
GatewayPorts no
PermitTunnel no
X11Forwarding no
Subsystem sftp internal-sftp
EOF

  setsid ip netns exec "$ns" /usr/sbin/sshd -D -e -f "$dir/sshd_config" >"$STATE_DIR/logs/$name-sshd.log" 2>&1 &
  echo $! >"$STATE_DIR/pids/$name-sshd.pgid"
}

ensure_samba_identity() {
  if ! id -u adminlab_smb >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin adminlab_smb
  fi
}

start_samba() {
  local share="$STATE_DIR/samba/share"
  local run="$STATE_DIR/samba/run"
  local lock="$STATE_DIR/samba/lock"
  local cache="$STATE_DIR/samba/cache"
  local state="$STATE_DIR/samba/state"
  local conf="$STATE_DIR/samba/smb.conf"
  mkdir -p "$share" "$run" "$lock" "$cache" "$state"
  ensure_samba_identity
  chown adminlab_smb:adminlab_smb "$share"
  chmod 0770 "$share"
  printf 'adminlab authenticated SMB seed file\n' >"$share/readme.txt"
  chown adminlab_smb:adminlab_smb "$share/readme.txt"
  chmod 0660 "$share/readme.txt"

  cat >"$conf" <<EOF
[global]
workgroup = WORKGROUP
server role = standalone server
security = user
map to guest = Never
guest account = nobody
interfaces = lo 10.77.0.23/24
bind interfaces only = yes
smb ports = 445
disable netbios = yes
server min protocol = SMB2
server max protocol = SMB3
pid directory = $run
lock directory = $lock
state directory = $state
cache directory = $cache
private dir = $STATE_DIR/samba/private
log file = $STATE_DIR/logs/samba.log
max log size = 1024

[adminlab_admin]
path = $share
read only = no
guest ok = no
valid users = adminlab_smb
admin users = adminlab_smb
force user = adminlab_smb
create mask = 0660
directory mask = 0770
EOF

  mkdir -p "$STATE_DIR/samba/private"
  # The credentials are fixed inert lab credentials. They are intentionally
  # scoped to the isolated namespace fixture and are not used outside 10.77/24.
  printf 'AdminlabSMB-2026!\nAdminlabSMB-2026!\n' | smbpasswd -c "$conf" -s -a adminlab_smb >/dev/null

  setsid ip netns exec ra-file01 /usr/sbin/smbd --foreground --no-process-group --configfile="$conf" >"$STATE_DIR/logs/smbd-stdout.log" 2>&1 &
  echo $! >"$STATE_DIR/pids/smbd.pgid"
}

verify_services() {
  for spec in \
    'ra-linux01 10.77.0.21 22' \
    'ra-linux02 10.77.0.22 22' \
    'ra-file01 10.77.0.23 445'; do
    read -r ns address port <<<"$spec"
    found=false
    for _ in $(seq 1 30); do
      if ip netns exec "$ns" ss -ltn | awk '{print $4}' | grep -Eq "(^|:)${port}$"; then
        found=true
        break
      fi
      sleep 0.2
    done
    if [[ "$found" != true ]]; then
      echo "service did not listen: ns=$ns address=$address port=$port" >&2
      [[ -f "$STATE_DIR/logs/smbd-stdout.log" ]] && cat "$STATE_DIR/logs/smbd-stdout.log" >&2 || true
      [[ -f "$STATE_DIR/logs/linux01-sshd.log" ]] && cat "$STATE_DIR/logs/linux01-sshd.log" >&2 || true
      exit 1
    fi
  done
  # Verify that guest access is denied and authenticated access succeeds.
  if ip netns exec ra-paw01 smbclient //10.77.0.23/adminlab_admin -N -c 'ls' >/dev/null 2>&1; then
    echo 'authenticated SMB fixture unexpectedly allowed guest access' >&2
    exit 1
  fi
  ip netns exec ra-paw01 smbclient //10.77.0.23/adminlab_admin -U 'adminlab_smb%AdminlabSMB-2026!' -m SMB3 -c 'ls' >/dev/null
  echo "services verified: ssh=10.77.0.21:22,10.77.0.22:22 smb-auth=10.77.0.23:445"
}

case "$MODE" in
  start)
    stop_services
    mkdir -p "$STATE_DIR/ssh"
    if [[ ! -f "$STATE_DIR/ssh/client_ed25519" ]]; then
      ssh-keygen -q -t ed25519 -N '' -f "$STATE_DIR/ssh/client_ed25519" >/dev/null
    fi
    start_ssh ra-linux01 10.77.0.21 linux01
    start_ssh ra-linux02 10.77.0.22 linux02
    start_samba
    verify_services
    ;;
  verify)
    verify_services
    ;;
  stop)
    stop_services
    ;;
  *)
    echo "usage: $0 {start|verify|stop} [state-dir]" >&2
    exit 2
    ;;
esac
