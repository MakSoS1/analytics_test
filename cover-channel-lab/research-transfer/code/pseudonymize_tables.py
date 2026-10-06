"""Reversible text pseudonymization of Arrow tables; numeric traffic stays exact.

HMAC tokens preserve equality, not text semantics. This is not anonymization.
Encryption uses GnuPG separately; never put its private key or this HMAC key in Git.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path
import re
import pyarrow as pa
import pyarrow.parquet as pq

ENUMS = {
    'proto': {'tcp', 'udp', 'icmp', 'icmpv6', 'sctp', 'TCP', 'UDP'},
    'conn_state': {'new', 'established', 'closed', 'timeout', 'S0', 'S1', 'SF', 'REJ', 'RSTO', 'RSTR', 'OTH'},
    'arm': {'scenario', 'control'},
    'label_state': {'unlabelled_office', 'verified_scenario', 'matched_control', 'hard_negative', 'operator_asserted'},
    'dataset': {'office_background_20260923', 'generated_cover'},
}
COUNTERS = {'arkime.office.seq', 'arkime.office.final', 'arkime.segmentCnt', 'arkime.packetRange.lte'}
NUMBER = re.compile(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z')
TECHNIQUE = re.compile(r'(?:CC_[A-Z0-9_]+|M-[A-Z0-9-]+|adaptix_(?:tcp|mtls)(?:_[A-Za-z0-9_-]+)?)\Z')


def safe_text(name, value):
    leaf = name.removeprefix('pipeline.').removeprefix('arkime_meta.')
    if leaf in ENUMS and value in ENUMS[leaf]: return True
    if leaf == 'technique' and TECHNIQUE.fullmatch(value): return True
    if (name.endswith('Cnt') or name in COUNTERS) and NUMBER.fullmatch(value): return True
    return False


def has_text(dtype):
    if pa.types.is_string(dtype) or pa.types.is_large_string(dtype) or pa.types.is_binary(dtype) or pa.types.is_large_binary(dtype) or pa.types.is_fixed_size_binary(dtype): return True
    if pa.types.is_list(dtype) or pa.types.is_large_list(dtype) or pa.types.is_fixed_size_list(dtype): return has_text(dtype.value_type)
    if pa.types.is_struct(dtype): return any(has_text(f.type) for f in dtype)
    if pa.types.is_dictionary(dtype): return has_text(dtype.value_type)
    if pa.types.is_map(dtype): return has_text(dtype.key_type) or has_text(dtype.item_type)
    return False


class Pseudonymizer:
    def __init__(self, key):
        if len(key) != 32: raise ValueError('a 256-bit secret HMAC key is required')
        self.key = key
        self.dictionary = {}
        self.public_fields = set()

    def token(self, value):
        binary = isinstance(value, bytes)
        data = value if binary else value.encode('utf-8')
        token = 'anon_' + hmac.new(self.key, (b'bytes\0' if binary else b'str\0') + data, hashlib.sha256).hexdigest()
        record = {'type': 'bytes' if binary else 'string', 'value': base64.b64encode(value).decode('ascii') if binary else value}
        if token in self.dictionary and self.dictionary[token] != record: raise ValueError('token collision')
        self.dictionary[token] = record
        return token.encode('ascii') if binary else token

    def value(self, name, value):
        if value is None: return None
        if isinstance(value, str):
            leaf = name.removeprefix('pipeline.').removeprefix('arkime_meta.')
            if leaf in {'arkime_present_fields', 'present_fields'} and value in self.public_fields: return value
            return value if safe_text(name, value) else self.token(value)
        if isinstance(value, bytes): return self.token(value)
        if isinstance(value, list): return [self.value(name, v) for v in value]
        if isinstance(value, tuple): return tuple(self.value(name, v) for v in value)
        if isinstance(value, dict): return {k: self.value(name + '.' + k, v) for k, v in value.items()}
        return value

    def table(self, table):
        self.public_fields = {n for name in table.schema.names for n in (name, name.removeprefix('arkime.'))}
        arrays = [pa.array([self.value(field.name, v) for v in col.to_pylist()], type=field.type)
                  if has_text(field.type) else col for field, col in zip(table.schema, table.columns)]
        # Field metadata is omitted too: it can contain site-specific provenance.
        schema = pa.schema([pa.field(f.name, f.type, f.nullable) for f in table.schema])
        return pa.Table.from_arrays(arrays, schema=schema)


def restore_table(table, dictionary):
    def restore(value):
        if isinstance(value, (str, bytes)):
            token = value.decode('ascii') if isinstance(value, bytes) and value.startswith(b'anon_') else value
            if isinstance(token, str) and token.startswith('anon_'):
                if token not in dictionary: raise ValueError('missing dictionary entry')
                item = dictionary[token]
                return base64.b64decode(item['value']) if item['type'] == 'bytes' else item['value']
            return value
        if isinstance(value, list): return [restore(v) for v in value]
        if isinstance(value, tuple): return tuple(restore(v) for v in value)
        if isinstance(value, dict): return {k: restore(v) for k, v in value.items()}
        return value
    return pa.Table.from_arrays([pa.array([restore(v) for v in col.to_pylist()], type=f.type)
                                if has_text(f.type) else col for f, col in zip(table.schema, table.columns)], schema=table.schema)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dictionary', type=Path, required=True, help='locally decrypted dictionary JSON')
    p.add_argument('--input', type=Path, required=True, help='pseudonymized Parquet')
    p.add_argument('--out', type=Path, required=True, help='new private restored Parquet')
    a = p.parse_args()
    if a.out.exists(): raise FileExistsError('retain existing output')
    obj = json.loads(a.dictionary.read_text())
    restored = restore_table(pq.read_table(a.input), obj['tokens'])
    if a.input.name in obj.get('tables', {}):
        schema = pa.ipc.read_schema(pa.BufferReader(base64.b64decode(obj['tables'][a.input.name]['schema_ipc_base64'])))
        restored = pa.Table.from_arrays(restored.columns, schema=schema)
    pq.write_table(restored, a.out, compression='zstd')
    a.out.chmod(0o600)
