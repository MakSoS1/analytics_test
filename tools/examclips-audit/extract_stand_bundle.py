"""Verify a pinned private CI archive and extract only its declared static app assets."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import zipfile

MAX_FILES = 2000
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024


def digest(path):
    value = hashlib.sha256()
    with open(path, 'rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def safe_name(value):
    if not isinstance(value, str) or not value or len(value) > 1024 or '\\' in value or ':' in value:
        raise ValueError('Unsafe archive member')
    name = value[:-1] if value.endswith('/') else value
    if any(ord(c) < 32 or ord(c) == 127 for c in name) or any(piece in ('', '.', '..') for piece in name.split('/')):
        raise ValueError('Unsafe archive member')
    return name


def extract(archive, destination, config):
    archive, destination = Path(archive), Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError('Destination already exists')
    if archive.stat().st_size != config['artifact_bytes'] or digest(archive) != config['artifact_sha256']:
        raise ValueError('Archive integrity mismatch')
    assets = config['assets']
    declared = {}
    targets = set()
    for item in assets:
        source, target = safe_name(item['archive_path']), safe_name(item['path'])
        if source != 'dist/' + target or not target.startswith('app/') or source in declared or target.casefold() in targets:
            raise ValueError('Invalid asset manifest')
        if not isinstance(item['bytes'], int) or not 0 <= item['bytes'] <= MAX_FILE_BYTES or not re.fullmatch('[a-f0-9]{64}', item['sha256']):
            raise ValueError('Invalid asset integrity record')
        declared[source] = item
        targets.add(target.casefold())
    if not declared or len(declared) > MAX_FILES:
        raise ValueError('Invalid asset count')
    temporary = None
    try:
        with zipfile.ZipFile(archive) as source:
            entries = source.infolist()
            if len(entries) > MAX_FILES or sum(item.file_size for item in entries) > MAX_TOTAL_BYTES:
                raise ValueError('Archive limit exceeded')
            all_names, files, selected = set(), set(), {}
            for item in entries:
                name = safe_name(item.filename)
                folded = name.casefold()
                mode = item.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if folded in all_names or item.flag_bits & 1 or kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError('Unsafe or duplicate archive member')
                if item.file_size > MAX_FILE_BYTES or item.file_size < 0 or (item.is_dir() and item.file_size):
                    raise ValueError('Archive member limit exceeded')
                all_names.add(folded)
                if not item.is_dir():
                    files.add(folded)
                    if name.startswith('dist/app/'):
                        if name not in declared:
                            raise ValueError('Unexpected app asset')
                        selected[name] = item
            if set(selected) != set(declared):
                raise ValueError('Missing app asset')
            for name in all_names:
                pieces = name.split('/')
                if any('/'.join(pieces[:count]) in files for count in range(1, len(pieces))):
                    raise ValueError('Conflicting archive paths')
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            temporary = Path(tempfile.mkdtemp(prefix='.stand-extract-', dir=destination.parent))
            os.chmod(temporary, 0o700)
            for name, item in selected.items():
                record = declared[name]
                if item.file_size != record['bytes']:
                    raise ValueError('Asset size mismatch')
                target = temporary / record['path']
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                value, count = hashlib.sha256(), 0
                with source.open(item) as incoming, open(target, 'xb') as outgoing:
                    os.chmod(target, 0o600)
                    for block in iter(lambda: incoming.read(1024 * 1024), b''):
                        count += len(block)
                        if count > record['bytes']:
                            raise ValueError('Asset size limit exceeded')
                        value.update(block)
                        outgoing.write(block)
                if count != record['bytes'] or value.hexdigest() != record['sha256']:
                    raise ValueError('Asset integrity mismatch')
            if destination.exists() or destination.is_symlink():
                raise ValueError('Destination already exists')
            temporary.rename(destination)
            temporary = None
    finally:
        if temporary is not None:
            shutil.rmtree(temporary)


if __name__ == '__main__':
    try:
        if len(sys.argv) != 4:
            raise ValueError('Archive, output and pinned configuration paths required')
        with open(sys.argv[3], encoding='utf-8') as config_file:
            extract(sys.argv[1], sys.argv[2], json.load(config_file))
    except Exception:
        print('Private app extraction failed safety or integrity checks', file=sys.stderr)
        sys.exit(1)
