#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 3 ]]; then echo "usage: $0 LOCAL_DIR PATH_IN_REPO COMMIT_MESSAGE" >&2; exit 2; fi
: "${HF_TOKEN:?HF_TOKEN GitHub secret with write permission is required}"
HF_DATASET_REPO="${HF_DATASET_REPO:-Maksim123321/cover-channel-web-protocols}"
LOCAL="$1" REMOTE="$2" MSG="$3"
export HF_XET_HIGH_PERFORMANCE=1

python - <<'PY'
import os
from huggingface_hub import HfApi
HfApi(token=os.environ["HF_TOKEN"]).create_repo(
    repo_id=os.environ.get("HF_DATASET_REPO", "Maksim123321/cover-channel-web-protocols"),
    repo_type="dataset", exist_ok=True, private=True,
)
PY

upload_with_retry() {
  local local_dir="$1" remote_path="$2" message="$3"
  for attempt in 1 2 3 4 5; do
    if hf upload "$HF_DATASET_REPO" "$local_dir" "$remote_path" \
        --repo-type dataset --commit-message "$message"; then
      return 0
    fi
    sleep $((attempt*5))
  done
  echo "HF upload failed after retries: $remote_path" >&2
  return 1
}

upload_with_retry "$LOCAL" "$REMOTE" "$MSG"

# A release-shaped dataset shard is also mirrored into a stable resume slot.
# HF/Xet deduplicates identical file content, while this stable per-shard path
# lets a later recovery run reuse every shard that already passed the current
# contract/hash/tail gates even if another matrix job failed afterwards.
if [[ "$REMOTE" =~ ^releases/([^/]+)/([^/]+)$ ]] \
   && [[ "${BASH_REMATCH[1]}" != "resume" ]] \
   && [[ -d "$LOCAL/bronze" && -d "$LOCAL/quality" ]]; then
  shard="${BASH_REMATCH[2]}"
  resume_remote="releases/resume/$shard"
  upload_with_retry "$LOCAL" "$resume_remote" "Resume slot $shard: $MSG"
  echo "HF resume slot updated: $resume_remote"
fi
