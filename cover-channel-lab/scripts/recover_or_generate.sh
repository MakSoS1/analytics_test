#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 4 ]]; then
  echo "usage: $0 MODE SOURCE_RELEASE SHARD_NAME WORK_ROOT [mode args...]" >&2
  exit 2
fi
MODE="$1" SOURCE_RELEASE="$2" NAME="$3" WORK="$4"; shift 4
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELEASE="$WORK/release"
mkdir -p "$WORK" "$RELEASE"
REUSED_FROM=""

write_status() {
  local reused="$1"
  local source="${2:-$SOURCE_RELEASE}"
  local qdir="$RELEASE/quality/$NAME"
  mkdir -p "$qdir"
  printf '{"mode":"%s","shard":"%s","reused":%s,"source_release":"%s","recovery_contract_revision":2,"reuse_policy_revision":4}\n' \
    "$MODE" "$NAME" "$reused" "$source" | tee "$WORK/recovery_status.json" > "$qdir/recovery_status.json"
}

if [[ -n "${HF_TOKEN:-}" ]]; then
  # Fast path: first prefer the stable resume slot populated by any previous
  # corrected recovery run, then fall back to the older nominated release.
  # This makes recovery monotonic: once a shard is repaired successfully, later
  # runs never need to regenerate it just because another shard failed.
  python -m pip install -q 'huggingface_hub[hf_xet]>=1.0.0' 'zstandard>=0.23.0'
  sources=(resume)
  if [[ -n "$SOURCE_RELEASE" && "$SOURCE_RELEASE" != "resume" ]]; then
    sources+=("$SOURCE_RELEASE")
  fi
  for source in "${sources[@]}"; do
    rm -rf "$WORK/reuse-cache" "$RELEASE"
    mkdir -p "$RELEASE"
    echo "checking reusable shard $NAME from source=$source"
    if PYTHONPATH="$ROOT/src" python "$ROOT/scripts/reuse_hf_shard.py" \
        --repo "${HF_DATASET_REPO:-Maksim123321/cover-channel-web-protocols}" \
        --source-release "$source" \
        --shard "$NAME" \
        --dest-release "$RELEASE" \
        --cache-dir "$WORK/reuse-cache"; then
      REUSED_FROM="$source"
      write_status true "$source"
      echo "reused validated shard: $NAME from $source"
      exit 0
    fi
    echo "source=$source did not provide a reusable $NAME"
  done
  rm -rf "$WORK/reuse-cache" "$RELEASE"
  mkdir -p "$RELEASE"
  echo "no reusable source passed contract/hash/tail validation for $NAME; regenerating only this shard"
fi

"$ROOT/scripts/install_runner.sh"
case "$MODE" in
  shard)
    if [[ $# -ne 3 ]]; then echo "shard mode: STAGE SHARD SHARDS" >&2; exit 2; fi
    "$ROOT/scripts/run_shard_ci.sh" "$1" "$2" "$3" "$WORK" "$NAME"
    ;;
  mixed)
    if [[ $# -ne 1 ]]; then echo "mixed mode: INDEX" >&2; exit 2; fi
    "$ROOT/scripts/run_mixed_ci.sh" "$1" "$WORK" "$NAME"
    ;;
  stage-a)
    "$ROOT/scripts/run_shard_ci.sh" parser 0 1 "$WORK" "$NAME"
    ;;
  *)
    echo "unknown recovery mode: $MODE" >&2
    exit 2
    ;;
esac
write_status false ""
