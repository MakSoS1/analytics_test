from pathlib import Path


_original_read_bytes = Path.read_bytes


def _read_bytes_or_empty(path: Path) -> bytes:
    try:
        return _original_read_bytes(path)
    except FileNotFoundError:
        return b""


Path.read_bytes = _read_bytes_or_empty
