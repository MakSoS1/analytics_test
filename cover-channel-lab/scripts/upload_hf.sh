#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 3 ]]; then echo "usage: $0 LOCAL_DIR PATH_IN_REPO COMMIT_MESSAGE" >&2; exit 2; fi
: "${HF_TOKEN:?HF_TOKEN GitHub secret with write permission is required}"
HF_DATASET_REPO="${HF_DATASET_REPO:-Maksim123321/cover-channel-web-protocols}"
LOCAL="$1" REMOTE="$2" MSG="$3"
export HF_XET_HIGH_PERFORMANCE=1
python - <<PY
from huggingface_hub import HfApi
HfApi(token="$HF_TOKEN").create_repo(repo_id="$HF_DATASET_REPO",repo_type="dataset",exist_ok=True,private=True)
PY
for attempt in 1 2 3 4 5; do
  if hf upload "$HF_DATASET_REPO" "$LOCAL" "$REMOTE" --repo-type dataset --commit-message "$MSG"; then exit 0; fi
  sleep $((attempt*5))
done
echo "HF upload failed after retries" >&2; exit 1
