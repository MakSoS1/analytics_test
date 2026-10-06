import unittest
import struct
import pyarrow as pa
from pseudonymize_tables import Pseudonymizer, restore_table


class TablePrivacyTests(unittest.TestCase):
    def test_private_text_numeric_features_nested_shape_and_restore(self):
        table = pa.table({
            'source_ip': ['192.0.2.33', '192.0.2.33', None],
            'arkime.source.ip': ['192.0.2.33', None, '2001:db8::9'],
            'arkime.http.requestBody': [['credential=fixture', None], [], None],
            'arkime_present_fields': [['source.ip', 'http.requestBody'], [], None],
            'arkime.snmp.community': [['123'], None, ['123']],
            'arkime.http.hostCnt': ['3', '0', None],
            'pkt_count': [3, 0, None],
            'seq_signed_len': [[54, -1304], [], None],
            'proto': ['tcp', 'udp', None],
            'label_binary': [1, 0, None],
            'arm': ['scenario', 'control', None],
        }).replace_schema_metadata({b'private_note': b'fixture'})
        obj = Pseudonymizer(b'x' * 32)
        public = obj.table(table)
        self.assertEqual(public.schema.remove_metadata(), table.schema.remove_metadata())
        self.assertIsNone(public.schema.metadata)
        self.assertEqual(public['source_ip'][0].as_py(), public['arkime.source.ip'][0].as_py())
        self.assertTrue(public['source_ip'][0].as_py().startswith('anon_'))
        for name in ['pkt_count', 'seq_signed_len', 'label_binary', 'proto', 'arm', 'arkime.http.hostCnt', 'arkime_present_fields']:
            self.assertTrue(public[name].equals(table[name]), name)
        self.assertNotEqual(public['arkime.snmp.community'][0].as_py(), ['123'])
        self.assertEqual(public['arkime.http.requestBody'][0].as_py()[1], None)
        self.assertEqual(public['arkime.http.requestBody'][1].as_py(), [])
        self.assertTrue(restore_table(public, obj.dictionary).equals(table.replace_schema_metadata(None)))

    def test_key_changes_tokens_and_untrusted_enum_is_not_exposed(self):
        source = pa.table({'proto': ['tcp', 'secret-fixture'], 'arkime.http.hostCnt': ['3', 'secret-fixture']})
        first = Pseudonymizer(b'a' * 32).table(source)
        other = Pseudonymizer(b'b' * 32).table(source)
        self.assertEqual(first['proto'][0].as_py(), 'tcp')
        self.assertNotEqual(first['proto'][1].as_py(), 'secret-fixture')
        self.assertNotEqual(first['proto'][1].as_py(), other['proto'][1].as_py())
        self.assertNotEqual(first['arkime.http.hostCnt'][1].as_py(), 'secret-fixture')

    def test_numeric_digest_ignores_hidden_null_slot_bytes(self):
        from export_public_tables import column_digest
        left = pa.Array.from_buffers(pa.int64(), 2, [pa.py_buffer(b'\xfd'), pa.py_buffer(struct.pack('<qq', 7, 9))])
        right = pa.Array.from_buffers(pa.int64(), 2, [pa.py_buffer(b'\x01'), pa.py_buffer(struct.pack('<qq', 7, 0))])
        field = pa.field('label_binary', pa.int64())
        self.assertTrue(left.equals(right))
        self.assertEqual(column_digest(field, pa.chunked_array([left])), column_digest(field, pa.chunked_array([right])))

    def test_numeric_digest_handles_null_lists_and_nanosecond_timestamps(self):
        from export_public_tables import column_digest
        for array in [pa.array([None, [1, -2], []], type=pa.list_(pa.int64())),
                      pa.array([1, None, 999999999], type=pa.timestamp('ns'))]:
            field = pa.field('feature', array.type)
            column = pa.chunked_array([array])
            self.assertTrue(pa.array(column.to_pylist(), type=array.type).equals(array))
            self.assertEqual(column_digest(field, column), column_digest(field, column))

    def test_missing_dictionary_entry_and_short_key_fail(self):
        with self.assertRaises(ValueError): Pseudonymizer(b'short')
        obj = Pseudonymizer(b'c' * 32)
        public = obj.table(pa.table({'source_ip': ['192.0.2.33']}))
        with self.assertRaises(ValueError): restore_table(public, {})


if __name__ == '__main__': unittest.main()
