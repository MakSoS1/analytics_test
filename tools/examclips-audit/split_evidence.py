"""Bounded parts of already encrypted evidence; never a plaintext fallback."""
import hashlib
import json
import pathlib
import shutil
import sys

def digest(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()

def split_evidence(source, metadata, destination, part_bytes=240 * 1024**2, max_parts=20):
    source, metadata, destination = map(pathlib.Path, (source, metadata, destination))
    size = source.stat().st_size
    if not isinstance(part_bytes, int) or part_bytes <= 0 or size <= 0 or size > part_bytes * max_parts:
        raise ValueError('Encrypted evidence exceeds the part limit or is empty')
    destination.mkdir(parents=True, exist_ok=True)
    manifest = {'version': 1, 'bytes': size, 'sha256': digest(source), 'parts': []}
    with source.open('rb') as incoming:
        index = 0
        while incoming.tell() < size:
            index += 1
            directory = destination / f'part-{index:04d}'
            directory.mkdir(mode=0o700)
            target = directory / 'evidence.enc.part'
            count, checksum = 0, hashlib.sha256()
            with target.open('wb') as outgoing:
                while count < part_bytes and (block := incoming.read(min(1024**2, part_bytes - count))):
                    outgoing.write(block)
                    checksum.update(block)
                    count += len(block)
            shutil.copyfile(metadata, directory / 'encryption.json')
            manifest['parts'].append({'index': index, 'directory': directory.name,
                                      'bytes': count, 'sha256': checksum.hexdigest()})
    encoded = json.dumps(manifest, indent=2) + '\n'
    for entry in manifest['parts']:
        (destination / entry['directory'] / 'parts.json').write_text(encoded)
    (destination / 'parts.json').write_text(encoded)
    return manifest

def join_evidence(root, destination):
    root, destination = map(pathlib.Path, (root, destination))
    manifest = json.loads((root / 'part-0001/parts.json').read_text())
    if manifest.get('version') != 1 or not 1 <= len(manifest.get('parts', [])) <= 20:
        raise ValueError('Invalid encrypted part manifest')
    metadata = (root / 'part-0001/encryption.json').read_bytes()
    try:
        with destination.open('wb') as outgoing:
            for index, entry in enumerate(manifest['parts'], 1):
                directory_name = f'part-{index:04d}'
                if entry['index'] != index or entry['directory'] != directory_name:
                    raise ValueError('Part order integrity mismatch')
                directory = root / directory_name
                if json.loads((directory / 'parts.json').read_text()) != manifest or (directory / 'encryption.json').read_bytes() != metadata:
                    raise ValueError('Part metadata integrity mismatch')
                source = directory / 'evidence.enc.part'
                if source.stat().st_size != entry['bytes'] or digest(source) != entry['sha256']:
                    raise ValueError('Encrypted part integrity mismatch')
                with source.open('rb') as incoming:
                    shutil.copyfileobj(incoming, outgoing, 1024**2)
        if destination.stat().st_size != manifest['bytes'] or digest(destination) != manifest['sha256']:
            raise ValueError('Reconstructed ciphertext integrity mismatch')
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return manifest

if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == 'split':
        result = split_evidence(*sys.argv[2:])
    elif len(sys.argv) == 4 and sys.argv[1] == 'join':
        result = join_evidence(*sys.argv[2:])
    else:
        raise SystemExit('Usage: split_evidence.py split CIPHERTEXT METADATA DIRECTORY | join DIRECTORY CIPHERTEXT')
    print(json.dumps({'parts': len(result['parts']), 'bytes': result['bytes'], 'sha256': result['sha256']}))
