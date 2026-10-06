"""Export reversible pseudonymized Parquet + recipient-encrypted dictionary.

Run on an authorized local copy. GnuPG must already have the recipient public
key; private keys and decrypted dictionaries must be outside the output tree.
All outputs are retained on failure and must not be published until verified.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import pyarrow as pa
import pyarrow.parquet as pq
from pseudonymize_tables import Pseudonymizer, restore_table, has_text


def sha(path):
    with path.open('rb') as handle: return hashlib.file_digest(handle, 'sha256').hexdigest()


def private_json(path, obj):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as handle:
        json.dump(obj, handle, ensure_ascii=False, indent=2)
        handle.write('\n')


def column_digest(field, column):
    sink = pa.BufferOutputStream()
    schema = pa.schema([pa.field(field.name, field.type, field.nullable)])
    with pa.ipc.new_stream(sink, schema) as writer:
        # Normalize ignored null-slot bytes and bitmap padding; Arrow scalars
        # are reconstructed with the original type (including timestamp units).
        canonical = pa.array(column.to_pylist(), type=field.type)
        writer.write_table(pa.Table.from_arrays([canonical], schema=schema))
    return hashlib.sha256(sink.getvalue().to_pybytes()).hexdigest()


def export(source, out, private, gpg_home, recipient):
    source, out, private, gpg_home = [Path(p).resolve() for p in (source, out, private, gpg_home)]
    if out.exists(): raise FileExistsError('retain previous export')
    if private.is_relative_to(out) or out.is_relative_to(private) or gpg_home.is_relative_to(out):
        raise ValueError('keys/private artifacts must be outside the publication tree')
    files = sorted(source.glob('*.parquet'))
    if not files: raise ValueError('no Parquet inputs')
    private.mkdir(parents=True, exist_ok=True); private.chmod(0o700)
    key_path = private / 'hmac-key.bin'
    if key_path.exists(): raise FileExistsError('retain previous HMAC scope; use a new private directory')
    key = secrets.token_bytes(32)
    with os.fdopen(os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as f: f.write(key)
    obj = Pseudonymizer(key); out.mkdir(parents=True)
    dictionary = {'version': 'traffic-text-dictionary-v1', 'tables': {}, 'tokens': obj.dictionary}
    reports = []
    for path in files:
        before = sha(path); original = pq.read_table(path); public = obj.table(original)
        destination = out / path.name
        pq.write_table(public, destination, compression='zstd')
        stored = pq.read_table(destination)
        restored = restore_table(stored, obj.dictionary)
        if not restored.equals(original, check_metadata=False): raise ValueError('cell/schema restoration mismatch: ' + path.name)
        numeric = []
        for field, a, b in zip(original.schema, original.columns, stored.columns):
            if not has_text(field.type):
                digest = column_digest(field, a)
                if digest != column_digest(field, b): raise ValueError('numeric bit preservation mismatch: ' + field.name)
                numeric.append({'column': field.name, 'sha256': digest})
        if sha(path) != before: raise ValueError('source changed during export')
        dictionary['tables'][path.name] = {'schema_ipc_base64': base64.b64encode(original.schema.serialize().to_pybytes()).decode('ascii'), 'source_sha256': before}
        reports.append({'file': path.name, 'rows': stored.num_rows, 'columns': stored.num_columns,
                        'source_sha256': before, 'sha256': sha(destination), 'bytes': destination.stat().st_size,
                        'all_cell_values_restorable': True, 'numeric_columns_bit_exact': numeric,
                        'text_columns': [f.name for f in original.schema if has_text(f.type)]})
    plaintext = private / 'dictionary.json'
    private_json(plaintext, dictionary)
    common = ['gpg', '--no-options', '--homedir', str(gpg_home), '--batch', '--yes']
    cipher = out / 'dictionary.json.gpg'
    subprocess.run(common + ['--trust-model', 'always', '--cipher-algo', 'AES256', '--force-mdc', '--recipient', recipient, '--output', str(cipher), '--encrypt', str(plaintext)], check=True, capture_output=True)
    # Test the encrypted object, not only the in-memory dictionary.
    checked = private / 'dictionary.roundtrip.json'
    subprocess.run(common + ['--output', str(checked), '--decrypt', str(cipher)], check=True, capture_output=True)
    checked.chmod(0o600)
    if checked.read_bytes() != plaintext.read_bytes(): raise ValueError('encrypted dictionary roundtrip mismatch')
    recovered = json.loads(checked.read_text())
    for path in files:
        stored = pq.read_table(out / path.name)
        values = restore_table(stored, recovered['tokens'])
        schema = pa.ipc.read_schema(pa.BufferReader(base64.b64decode(recovered['tables'][path.name]['schema_ipc_base64'])))
        full = pa.Table.from_arrays(values.columns, schema=schema)
        if not full.equals(pq.read_table(path), check_metadata=True): raise ValueError('encrypted dictionary full-schema restoration mismatch')
    plaintext.unlink(); checked.unlink()
    report = {'version': 'pseudonymized-full-comparison-v1', 'recipient_fingerprint': recipient,
              'pseudonymization': 'HMAC-SHA256 with a private 256-bit key; global lexical value equality',
              'dictionary_cipher': 'OpenPGP RSA-3072 recipient / AES-256 / MDC',
              'dictionary_sha256': sha(cipher), 'dictionary_entries': len(obj.dictionary),
              'encrypted_dictionary_roundtrip': True, 'all_tables_restored_from_cipher': True,
              'metadata_removed_publicly_and_preserved_in_dictionary': True, 'tables': reports,
              'raw_pcaps_included': False, 'naturalness_established': False, 'production_ready': False,
              'privacy_claim': 'pseudonymization, not anonymization; traffic patterns/timestamps remain identifying'}
    (out / 'DATA_MANIFEST.json').write_text(json.dumps(report, indent=2) + '\n')
    return {'tables': len(reports), 'dictionary_entries': len(obj.dictionary), 'encrypted_roundtrip': True}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for flag in ['source', 'out', 'private-dir', 'gpg-home']: p.add_argument('--' + flag, type=Path, required=True)
    p.add_argument('--recipient', required=True)
    a = p.parse_args()
    print(json.dumps(export(a.source, a.out, a.private_dir, a.gpg_home, a.recipient)))
