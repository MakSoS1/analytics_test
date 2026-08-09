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

write_status() {
  local reused="$1"
  local qdir="$RELEASE/quality/$NAME"
  mkdir -p "$qdir"
  printf '{"mode":"%s","shard":"%s","reused":%s,"source_release":"%s","recovery_contract_revision":2}\n' \
    "$MODE" "$NAME" "$reused" "$SOURCE_RELEASE" | tee "$WORK/recovery_status.json" > "$qdir/recovery_status.json"
}

try_reuse=false
if [[ -n "$SOURCE_RELEASE" && -n "${HF_TOKEN:-}" ]]; then
  try_reuse=true
fi

if [[ "$try_reuse" == true ]]; then
  python -m pip install -q 'huggingface_hub[hf_xet]>=1.0.0'
  if PYTHONPATH="$ROOT/src" python "$ROOT/scripts/reuse_hf_shard.py" \
      --repo "${HF_DATASET_REPO:-Maksim123321/cover-channel-web-protocols}" \
      --source-release "$SOURCE_RELEASE" \
      --shard "$NAME" \
      --dest-release "$RELEASE" \
      --cache-dir "$WORK/reuse-cache"; then
    write_status true
    echo "reused validated shard: $NAME from $SOURCE_RELEASE"
    exit 0
  fi
  echo "source shard $NAME is missing/invalid under contract revision 2; regenerating"
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
write_status false
