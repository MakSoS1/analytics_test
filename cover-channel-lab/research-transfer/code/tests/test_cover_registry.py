import json
import unittest
from pathlib import Path
from office_injection.cover_registry import discover_registry, validate_coverage

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT.parents[1] / 'docs/plans/cover_channels_source_inventory_2026-10-02.json'
if not INVENTORY.is_file():
    INVENTORY = ROOT / 'tests/fixtures/cover_channels_source_inventory_2026-10-02.json'


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.inventory = json.loads(INVENTORY.read_text())
        self.registry = discover_registry(ROOT / 'cover_runtime/upstream', self.inventory['main_commit'])

    def test_registry_contains_all_178_entries(self):
        entries = self.registry['entries']
        self.assertEqual(len(entries), 178)
        expected = {s['scenario_id'] for s in self.inventory['catalog_scenarios']} | set(self.inventory['stage_m_families'])
        self.assertEqual({e['entry_id'] for e in entries}, expected)
        self.assertEqual(len({e['entry_id'] for e in entries}), len(entries))
        stage = [e for e in entries if e['namespace'] == 'stage_m']
        self.assertEqual(sum(len(e['profiles']) for e in stage), 126)

    def test_roles_and_semantic_fidelity(self):
        entries = {e['entry_id']: e for e in self.registry['entries']}
        for e in entries.values():
            if e['family'] in ('lots', 'privacy'):
                self.assertEqual(e['dataset_role'], 'hard_negative')
        self.assertEqual(entries['CC_CONNECT_02']['source_fidelity'], 'semantic_fixture')
        self.assertEqual(entries['CC_OHTTP_01']['source_fidelity'], 'semantic_fixture')

    def test_coverage_requires_observed_evidence_and_exact_keys(self):
        report = validate_coverage(self.registry, [])
        self.assertFalse(report['complete'])
        self.assertGreater(len(report['missing']), 300)
        results = [{'entry_id': e['entry_id'], 'profile_id': p['profile_id'], 'arm': a,
                    'status': 'success'} for e in self.registry['entries'] for p in e['profiles'] for a in ('scenario','control')]
        self.assertFalse(validate_coverage(self.registry, results)['complete'])
        with self.assertRaises(ValueError):
            validate_coverage(self.registry, results + [results[0]])
        with self.assertRaises(ValueError):
            validate_coverage(self.registry, [{'entry_id':'FAKE','profile_id':'x','arm':'scenario'}])


if __name__ == '__main__': unittest.main()

class RequestedCoverage(unittest.TestCase):
    def test_declared_subset_is_explicit_and_unknown_key_rejected(self):
        registry={'sha256':'a'*64,'entries':[{'entry_id':'e','profiles':[{'profile_id':'p'},{'profile_id':'q'}]}]}
        result={'entry_id':'e','profile_id':'p','arm':'scenario','registry_sha256':'a'*64,'status':'success',
                'wire_evidence':{'capture_sha256':'b'*64,'observed_packets':1,'membership_verified':True,'dispatch_verified':True}}
        report=validate_coverage(registry,[result],requested_keys=[('e','p','scenario')])
        self.assertTrue(report['complete']);self.assertEqual(report['parent_registry_expected'],4)
        self.assertEqual(report['expected'],1)
        with self.assertRaises(ValueError):validate_coverage(registry,[result],requested_keys=[('e','unknown','scenario')])
