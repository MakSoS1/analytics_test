import importlib.util
from pathlib import Path
import unittest
import csv
import json
import sqlite3
import tempfile

P = Path(__file__).resolve().parents[1] / 'arkime_csv.py'


class CsvSemantics(unittest.TestCase):
    def load(self):
        spec = importlib.util.spec_from_file_location('arkime_csv', P)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_fragments_preserve_arrays_and_false_and_count_once(self):
        m = self.load()
        records = [
            {'network': {'packets': 2}, 'firstPacket': 100, 'lastPacket': 200,
             'dns': {'host': ['a', 'b'], 'hostCnt': 2}, 'flag': False, 'vary': 7},
            {'network': {'packets': 3}, 'firstPacket': 200, 'lastPacket': 300,
             'dns': {'host': ['a', 'c'], 'hostCnt': 2}, 'flag': False, 'vary': 9},
        ]
        row = m.aggregate(records)
        self.assertEqual(row['network.packets'], 5)
        self.assertEqual(row['dns.host'], ['a', 'b', 'c'])
        self.assertEqual(row['dns.hostCnt'], 3)
        self.assertIs(row['flag'], False)
        self.assertEqual(row['vary'], [7, 9])
        self.assertEqual(row['firstPacket'], 100)
        self.assertEqual(row['lastPacket'], 300)
        self.assertEqual(m.cell('a,"b\n'), '"a,\\\"b\\n"')
        self.assertEqual(m.cell(None), 'null')

    def test_entropy_uses_last_cumulative_value(self):
        m = self.load()
        row = m.aggregate([
            {'office': {'seq': 2}, 'officeEntropy': {'src': 4.0}},
            {'office': {'seq': 1}, 'officeEntropy': {'src': 3.0}},
        ])
        self.assertEqual(row['officeEntropy.src'], 4.0)

    def test_full_export_keeps_catalog_only_fields_and_raw_spi(self):
        m = self.load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db = sqlite3.connect(root / 'state.db')
            db.executescript('create table fragments(session_key,index_name,id,revision,source_json);'
                             'create table session_totals(session_key,summary_json,started,end_reason);')
            raw = json.dumps({'firstPacket': 100, 'lastPacket': 200,
                              'dns': {'host': ['a,"b\n', 'c']},
                              'network': {'packets': 2}, 'flag': False, 'explicit': None,
                              'large': 'x' * 150000})
            db.execute('insert into fragments values(?,?,?,?,?)', ('s', 'i', 'id', 'r', raw))
            db.execute('insert into session_totals values(?,?,?,?)', ('s', '{"fragments":1}', 1, 1))
            db.commit()
            db.close()
            (root / 'catalog.json').write_text(json.dumps([
                {'field_id': 'unused', 'definition': {'dbField': 'unused.field'}},
                {'field_id': 'native', 'definition': {'dbField2': 'native.field'}},
                {'field_id': 'ecs', 'definition': {'dbField2': 'srcPackets',
                                                  'fieldECS': 'source.packets'}}]))
            (root / 'provenance.json').write_text(json.dumps({'sources': [
                {'mixed_first_ms': 100, 'mixed_last_ms': 200, 'shift_ms': 0,
                 'dataset': 'office', 'label_state': 'unlabelled', 'sha256': 'x'}]}))
            report = m.export(root/'state.db', root/'catalog.json', root/'provenance.json', root/'csv')
            self.assertEqual(report['sessions'], 1)
            with (root/'csv/arkime_sessions_all_fields.csv').open(newline='') as f:
                row = next(csv.DictReader(f))
            self.assertEqual(row['arkime.unused.field'], '')
            self.assertEqual(row['arkime.native.field'], '')
            self.assertEqual(row['arkime.source.packets'], '')
            self.assertIs(json.loads(row['arkime.flag']), False)
            self.assertIsNone(json.loads(row['arkime.explicit']))
            self.assertEqual(json.loads(row['arkime.dns.host']), ['a,"b\n', 'c'])
            self.assertEqual(row['label_binary'], '')
            with (root/'csv/arkime_fragments_full_spi.csv').open(newline='') as f:
                recovered = next(csv.DictReader(f))
            self.assertEqual(json.loads(recovered['source_json']), json.loads(raw))

    def test_auxiliary_packets_never_inherit_positive_label(self):
        m = self.load()
        data = {'source.ip': '192.0.2.1', 'destination.ip': '192.0.2.2',
                'source.port': 100, 'destination.port': 200, 'ipProtocol': 6,
                'firstPacket': 1000, 'lastPacket': 2000, 'network.packets': 2}
        packets = [dict(src='192.0.2.1', dst='192.0.2.2', src_port=100,
                        dst_port=200, proto=6, timestamp=1,
                        membership_role='campaign'),
                   dict(src='192.0.2.2', dst='192.0.2.1', src_port=200,
                        dst_port=100, proto=6, timestamp=2,
                        membership_role='auxiliary_or_unassigned')]
        self.assertEqual(m.membership(data, packets, 0), (1, 1, 0))


if __name__ == '__main__':
    unittest.main()
