from __future__ import annotations

from typing import Any


def _normalize(path: str) -> str:
    return str(path).strip().strip("/")


def expected_remote_paths(
    manifest: dict[str, Any],
    upload_status: dict[str, Any],
    *,
    shard: str,
    remote_prefix: str,
) -> list[dict[str, Any]]:
    """Map authoritative release-manifest files to their expected HF objects.

    Most files are persisted byte-for-byte under ``remote_prefix``.  Lossless
    transport transformations (currently the Windows pktmon UTF-16 text gzip)
    are declared by the uploader relative to the layer/shard root; for those
    rows the expected remote checksum/size must be the stored representation,
    while the authoritative local checksum remains unchanged in the release
    manifest.
    """
    shard = _normalize(shard)
    prefix = _normalize(remote_prefix)
    if not shard or not prefix:
        raise ValueError("shard and remote_prefix must be non-empty")

    transforms: dict[str, dict[str, Any]] = {}
    for item in upload_status.get("transport_transforms", []) or []:
        original = _normalize(item.get("original_path", ""))
        stored = _normalize(item.get("stored_path", ""))
        if not original or not stored:
            raise ValueError("transport transform requires original_path and stored_path")
        transforms[original] = dict(item)

    rows: list[dict[str, Any]] = []
    seen_remote: set[str] = set()
    marker = f"/{shard}/"
    for file_row in manifest.get("files", []) or []:
        local = _normalize(file_row.get("path", ""))
        if not local:
            raise ValueError("release manifest contains empty file path")
        if marker not in f"/{local}":
            continue
        layer, remainder = local.split(f"/{shard}/", 1)
        layer = _normalize(layer)
        remainder = _normalize(remainder)
        if not layer or not remainder:
            raise ValueError(f"invalid shard file path: {local}")

        transform = transforms.get(remainder) if layer == "quality" else None
        if transform is not None:
            remote_remainder = _normalize(transform["stored_path"])
            remote_sha = str(transform.get("stored_sha256", ""))
            remote_bytes = int(transform.get("stored_bytes", 0))
            transport = str(transform.get("transform", "lossless_transform"))
        else:
            remote_remainder = remainder
            remote_sha = str(file_row.get("sha256", ""))
            remote_bytes = int(file_row.get("bytes", 0))
            transport = "identity"

        if len(remote_sha) != 64:
            raise ValueError(f"invalid expected sha256 for {local}")
        if remote_bytes < 0:
            raise ValueError(f"invalid expected byte count for {local}")

        remote = f"{prefix}/{layer}/{shard}/{remote_remainder}"
        if remote in seen_remote:
            raise ValueError(f"duplicate expected remote path: {remote}")
        seen_remote.add(remote)
        rows.append(
            {
                "local_path": local,
                "local_sha256": str(file_row.get("sha256", "")),
                "local_bytes": int(file_row.get("bytes", 0)),
                "remote_path": remote,
                "remote_sha256": remote_sha,
                "remote_bytes": remote_bytes,
                "transport": transport,
            }
        )

    if not rows:
        raise ValueError(f"release manifest contains no files for shard {shard}")
    return rows
