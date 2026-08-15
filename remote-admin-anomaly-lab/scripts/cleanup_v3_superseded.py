#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from huggingface_hub import CommitOperationDelete, HfApi

from adminlab.v3_cleanup import (
    select_github_run_ids_for_cleanup,
    select_hf_paths_for_cleanup,
    validate_cleanup_preconditions,
)


def _github_json(url: str, token: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "remote-admin-v3-cleanup",
        },
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.loads(response.read().decode("utf-8"))


def _github_delete(url: str, token: str) -> None:
    request = urllib.request.Request(
        url,
        method="DELETE",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "remote-admin-v3-cleanup",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            if response.status not in (200, 202, 204):
                raise RuntimeError(f"unexpected GitHub DELETE status {response.status}: {url}")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return
        raise


def _list_github_runs(repository: str, token: str) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for page in range(1, 101):
        payload = _github_json(
            f"https://api.github.com/repos/{repository}/actions/runs?per_page=100&page={page}",
            token,
        )
        batch = list(payload.get("workflow_runs", []))
        runs.extend(batch)
        if len(batch) < 100:
            break
    return runs


def _delete_hf_in_batches(api: HfApi, repo_id: str, paths: list[str], token: str) -> int:
    deleted = 0
    for offset in range(0, len(paths), 100):
        batch = paths[offset: offset + 100]
        api.create_commit(
            repo_id=repo_id,
            repo_type="dataset",
            token=token,
            operations=[CommitOperationDelete(path_in_repo=path) for path in batch],
            commit_message=f"Remote Admin V3 cleanup: remove {len(batch)} superseded objects",
        )
        deleted += len(batch)
    return deleted


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--status", type=Path, required=True)
    parser.add_argument("--hf-repo", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    status = json.loads(args.status.read_text(encoding="utf-8"))
    guard = validate_cleanup_preconditions(status)
    github_token = os.environ.get("GITHUB_TOKEN", "").strip()
    hf_token = os.environ.get("HF_TOKEN", "").strip()
    repository = os.environ.get("GITHUB_REPOSITORY", "").strip()
    current_run = int(os.environ.get("GITHUB_RUN_ID", "0") or 0)
    final_run = int(status.get("github_final_run_id", current_run) or current_run)
    if not github_token or not hf_token or not repository or current_run <= 0 or final_run <= 0:
        raise SystemExit("cleanup requires GITHUB_TOKEN, HF_TOKEN, GITHUB_REPOSITORY and run ids")

    api = HfApi(token=hf_token)
    before_hf = api.list_repo_files(args.hf_repo, repo_type="dataset", token=hf_token)
    hf_delete = select_hf_paths_for_cleanup(before_hf, retained_prefix=guard["retained_hf_prefix"])
    hf_deleted = _delete_hf_in_batches(api, args.hf_repo, hf_delete, hf_token) if hf_delete else 0

    runs = _list_github_runs(repository, github_token)
    run_delete = select_github_run_ids_for_cleanup(
        runs,
        final_run_id=final_run,
        current_run_id=current_run,
    )
    deleted_runs: list[int] = []
    for run_id in run_delete:
        _github_delete(f"https://api.github.com/repos/{repository}/actions/runs/{run_id}", github_token)
        deleted_runs.append(run_id)

    # Hub commits are immediately addressable but allow a short propagation
    # window before fail-closed post-delete inventory.
    time.sleep(2)
    after_hf = api.list_repo_files(args.hf_repo, repo_type="dataset", token=hf_token)
    residual = select_hf_paths_for_cleanup(after_hf, retained_prefix=guard["retained_hf_prefix"])
    retained_files = [
        path for path in after_hf
        if path == guard["retained_hf_prefix"] or path.startswith(guard["retained_hf_prefix"] + "/")
    ]
    if residual:
        raise RuntimeError(f"superseded HF objects remain after cleanup: {residual[:20]}")
    if not retained_files:
        raise RuntimeError("verified V3 final HF prefix disappeared during cleanup")

    report = {
        "status": "PASS",
        "policy": "B",
        "guard": guard,
        "github_repository": repository,
        "github_final_run_id": final_run,
        "github_cleanup_run_id": current_run,
        "github_deleted_run_count": len(deleted_runs),
        "github_deleted_run_ids": deleted_runs,
        "hf_repo": args.hf_repo,
        "hf_deleted_file_count": hf_deleted,
        "hf_deleted_paths_sample": hf_delete[:100],
        "hf_retained_prefix": guard["retained_hf_prefix"],
        "hf_retained_file_count": len(retained_files),
        "hf_residual_superseded_paths": residual,
        "unrelated_github_runs_preserved_by_selector": True,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
