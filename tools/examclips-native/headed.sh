#!/usr/bin/env bash
set -euo pipefail

: "${AUDIT_ROOT:?Native private work directory is required}"
native_desktop_size="${NATIVE_DESKTOP_SIZE:-1920x1200}"
if [[ ! "$native_desktop_size" =~ ^[0-9]{3,4}x[0-9]{3,4}$ ]]; then
  exit 2
fi
if [[ "${NATIVE_INSIDE_XVFB:-0}" != 1 ]]; then
  export NATIVE_INSIDE_XVFB=1
  exec dbus-run-session -- xvfb-run -a -s "-screen 0 ${native_desktop_size}x24 -nolisten tcp" bash "$0" "$@"
fi
: "${DISPLAY:?A real X11 display is required}"

openbox > "$AUDIT_ROOT/openbox-$$.log" 2>&1 &
native_wm_pid=$!
trap 'kill "$native_wm_pid" 2>/dev/null || true' EXIT
native_wm_ready=0
for native_wait in {1..100}; do
  native_wm_state="$(xprop -root _NET_SUPPORTING_WM_CHECK 2>/dev/null || true)"
  if [[ "$native_wm_state" == *'window id #'* ]]; then
    native_wm_ready=1
    break
  fi
  sleep 0.1
done
if [[ "$native_wm_ready" != 1 ]]; then
  exit 3
fi
"$@"
