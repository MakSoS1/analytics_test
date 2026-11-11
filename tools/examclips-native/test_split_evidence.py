import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

class EvidencePartsTest(unittest.TestCase):
    def api(self):
        path = pathlib.Path(__file__).with_name('split_evidence.py')
        self.assertTrue(path.exists(), 'Bounded encrypted transfer implementation is required')
        spec = importlib.util.spec_from_file_location('split_evidence', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def fixture(self, directory, content):
        source = directory / 'encrypted.bin'
        source.write_bytes(content)
        metadata = directory / 'encryption.json'
        metadata.write_text(json.dumps({'context': {'runId': '123', 'caseId': 'rul01'}}))
        return source, metadata

    def test_all_ciphertext_reconstructed_across_partial_last_part(self):
        api = self.api()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source, metadata = self.fixture(root, b'0123456789abcdefg')
            manifest = api.split_evidence(source, metadata, root / 'parts', part_bytes=8)
            self.assertEqual([x['bytes'] for x in manifest['parts']], [8, 8, 1])
            self.assertEqual(manifest['sha256'], hashlib.sha256(b'0123456789abcdefg').hexdigest())
            api.join_evidence(root / 'parts', root / 'joined.enc')
            self.assertEqual((root / 'joined.enc').read_bytes(), b'0123456789abcdefg')
            for entry in manifest['parts']:
                self.assertEqual((root / 'parts' / entry['directory'] / 'encryption.json').read_bytes(), metadata.read_bytes())

    def test_exact_boundary_does_not_create_empty_part(self):
        api = self.api()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source, metadata = self.fixture(root, b'0123456789abcdef')
            manifest = api.split_evidence(source, metadata, root / 'parts', part_bytes=8)
            self.assertEqual([x['bytes'] for x in manifest['parts']], [8, 8])

    def test_tampering_rejected_and_partial_join_removed(self):
        api = self.api()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source, metadata = self.fixture(root, b'0123456789abcdefg')
            api.split_evidence(source, metadata, root / 'parts', part_bytes=8)
            (root / 'parts/part-0002/evidence.enc.part').write_bytes(b'badbytes')
            with self.assertRaisesRegex(ValueError, 'integrity'):
                api.join_evidence(root / 'parts', root / 'joined.enc')
            self.assertFalse((root / 'joined.enc').exists())

    def test_missing_part_and_overflow_fail_closed(self):
        api = self.api()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source, metadata = self.fixture(root, b'0123456789abcdefg')
            with self.assertRaisesRegex(ValueError, 'limit'):
                api.split_evidence(source, metadata, root / 'overflow', part_bytes=8, max_parts=2)
            api.split_evidence(source, metadata, root / 'parts', part_bytes=8)
            (root / 'parts/part-0002/evidence.enc.part').unlink()
            with self.assertRaises((ValueError, FileNotFoundError)):
                api.join_evidence(root / 'parts', root / 'joined.enc')
            self.assertFalse((root / 'joined.enc').exists())

if __name__ == '__main__':
    unittest.main()
