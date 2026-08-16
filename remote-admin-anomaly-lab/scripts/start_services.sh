#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-start}"
STATE_DIR="${2:-/tmp/adminlab-services}"

if [[ "${EUID}" -ne 0 ]]; then echo "service operations require root" >&2; exit 2; fi
mkdir -p "$STATE_DIR" "$STATE_DIR/pids" "$STATE_DIR/logs" "$STATE_DIR/ssh" "$STATE_DIR/samba"

stop_services() {
  shopt -s nullglob
  for pgfile in "$STATE_DIR"/pids/*.pgid; do
    pgid="$(cat "$pgfile" 2>/dev/null || true)"
    if [[ "$pgid" =~ ^[0-9]+$ ]] && kill -0 -- "-$pgid" 2>/dev/null; then
      kill -TERM -- "-$pgid" 2>/dev/null || true
      for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 -- "-$pgid" 2>/dev/null || break; sleep 0.2; done
      if kill -0 -- "-$pgid" 2>/dev/null; then kill -KILL -- "-$pgid" 2>/dev/null || true; fi
    fi
    rm -f "$pgfile"
  done
}

start_ssh() {
  local ns="$1" address="$2" name="$3" dir="$STATE_DIR/ssh/$3"
  mkdir -p "$dir"; rm -f "$dir/host_key" "$dir/host_key.pub"
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
PermitOpen 10.77.0.21:22 10.77.0.22:22 10.77.0.60:22 10.77.0.61:22 10.77.0.23:445 10.77.0.62:445 10.77.0.63:445 10.77.0.64:445 10.77.0.24:3389 10.77.0.65:3389 10.77.0.66:3389 10.77.0.67:3389 10.77.0.25:5900 10.77.0.68:5900 10.77.0.69:5900 10.77.0.70:5900
GatewayPorts no
PermitTunnel no
X11Forwarding no
Subsystem sftp internal-sftp
EOF
  setsid ip netns exec "$ns" /usr/sbin/sshd -D -e -f "$dir/sshd_config" >"$STATE_DIR/logs/$name-sshd.log" 2>&1 &
  echo $! >"$STATE_DIR/pids/$name-sshd.pgid"
}

ensure_samba_identity() {
  if ! id -u adminlab_smb >/dev/null 2>&1; then useradd --system --no-create-home --shell /usr/sbin/nologin adminlab_smb; fi
}

start_samba() {
  local ns="$1" address="$2" name="$3" root="$STATE_DIR/samba/$3"
  local share="$root/share" run="$root/run" lock="$root/lock" cache="$root/cache" state="$root/state" private="$root/private" conf="$root/smb.conf"
  mkdir -p "$share" "$run" "$lock" "$cache" "$state" "$private"
  ensure_samba_identity
  chown adminlab_smb:adminlab_smb "$share"; chmod 0770 "$share"
  printf 'adminlab authenticated SMB seed file for %s\n' "$name" >"$share/readme.txt"
  chown adminlab_smb:adminlab_smb "$share/readme.txt"; chmod 0660 "$share/readme.txt"
  cat >"$conf" <<EOF
[global]
workgroup = WORKGROUP
server role = standalone server
security = user
map to guest = Never
guest account = nobody
interfaces = lo $address/32
bind interfaces only = yes
smb ports = 445
disable netbios = yes
server min protocol = SMB2
server max protocol = SMB3
pid directory = $run
lock directory = $lock
state directory = $state
cache directory = $cache
private dir = $private
log file = $STATE_DIR/logs/$name-samba.log
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
  printf 'AdminlabSMB-2026!\nAdminlabSMB-2026!\n' | smbpasswd -c "$conf" -s -a adminlab_smb >/dev/null
  setsid ip netns exec "$ns" /usr/sbin/smbd --foreground --no-process-group --configfile="$conf" >"$STATE_DIR/logs/$name-smbd-stdout.log" 2>&1 &
  echo $! >"$STATE_DIR/pids/$name-smbd.pgid"
}

wait_listener() {
  local ns="$1" port="$2" name="$3" found=false
  for _ in $(seq 1 40); do
    if ip netns exec "$ns" ss -ltn | awk '{print $4}' | grep -Eq "(^|:)${port}$"; then found=true; break; fi
    sleep 0.2
  done
  if [[ "$found" != true ]]; then
    echo "service did not listen: $name ns=$ns port=$port" >&2
    [[ -f "$STATE_DIR/logs/$name-smbd-stdout.log" ]] && cat "$STATE_DIR/logs/$name-smbd-stdout.log" >&2 || true
    [[ -f "$STATE_DIR/logs/$name-sshd.log" ]] && cat "$STATE_DIR/logs/$name-sshd.log" >&2 || true
    exit 1
  fi
}

verify_services() {
  for spec in \
    'ra-linux01 10.77.0.21 22 linux01' 'ra-linux02 10.77.0.22 22 linux02' \
    'ra-linux03 10.77.0.60 22 linux03' 'ra-linux04 10.77.0.61 22 linux04' \
    'ra-file01 10.77.0.23 445 file01' 'ra-file02 10.77.0.62 445 file02' \
    'ra-file03 10.77.0.63 445 file03' 'ra-file04 10.77.0.64 445 file04'; do
    read -r ns address port name <<<"$spec"; wait_listener "$ns" "$port" "$name"
  done
  for ip in 10.77.0.23 10.77.0.62 10.77.0.63 10.77.0.64; do
    if ip netns exec ra-paw01 smbclient "//$ip/adminlab_admin" -N -c 'ls' >/dev/null 2>&1; then
      echo "authenticated SMB fixture unexpectedly allowed guest access at $ip" >&2; exit 1
    fi
    ip netns exec ra-paw01 smbclient "//$ip/adminlab_admin" -U 'adminlab_smb%AdminlabSMB-2026!' -m SMB3 -c 'ls' >/dev/null
  done
  echo "services verified: ssh_targets=4 smb_targets=4"
}

case "$MODE" in
  start)
    stop_services
    mkdir -p "$STATE_DIR/ssh"
    if [[ ! -f "$STATE_DIR/ssh/client_ed25519" ]]; then ssh-keygen -q -t ed25519 -N '' -f "$STATE_DIR/ssh/client_ed25519" >/dev/null; fi
    start_ssh ra-linux01 10.77.0.21 linux01
    start_ssh ra-linux02 10.77.0.22 linux02
    start_ssh ra-linux03 10.77.0.60 linux03
    start_ssh ra-linux04 10.77.0.61 linux04
    start_samba ra-file01 10.77.0.23 file01
    start_samba ra-file02 10.77.0.62 file02
    start_samba ra-file03 10.77.0.63 file03
    start_samba ra-file04 10.77.0.64 file04
    verify_services
    ;;
  verify) verify_services ;;
  stop) stop_services ;;
  *) echo "usage: $0 {start|verify|stop} [state-dir]" >&2; exit 2 ;;
esac
