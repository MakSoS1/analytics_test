import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile


def module():
    spec = importlib.util.spec_from_file_location('extract_stand_bundle', Path(__file__).with_name('extract_stand_bundle.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class BundleExtractionTests(unittest.TestCase):
    def fixture(self, base, extra=(), corrupt=False):
        archive = base / 'fixture.zip'
        body = b'<!doctype html><title>Fixture</title>'
        with zipfile.ZipFile(archive, 'w') as out:
            out.writestr('dist/app/index.html', body)
            out.writestr('dist/site/index.html', b'unselected landing page')
            for name, value in extra:
                out.writestr(name, value)
        config = {'artifact_bytes': archive.stat().st_size,
                  'artifact_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
                  'assets': [{'archive_path': 'dist/app/index.html', 'path': 'app/index.html',
                              'bytes': len(body), 'sha256': ('0' * 64 if corrupt else hashlib.sha256(body).hexdigest())}]}
        return archive, config

    def test_extracts_only_declared_app_assets_with_private_modes(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            archive, config = self.fixture(base)
            destination = base / 'site'
            module().extract(archive, destination, config)
            self.assertEqual([p.relative_to(destination).as_posix() for p in destination.rglob('*') if p.is_file()], ['app/index.html'])
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((destination / 'app/index.html').stat().st_mode), 0o600)

    def test_rejects_traversal_backslash_absolute_and_duplicate_members(self):
        for name in ('../escape', '/absolute', 'dist\\escape', 'dist/a/../escape', 'dist//escape', 'dist/app/INDEX.HTML'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                base = Path(temp)
                archive, config = self.fixture(base, [(name, b'bad')])
                with self.assertRaises(ValueError):
                    module().extract(archive, base / 'site', config)
                self.assertFalse((base / 'site').exists())

    def test_rejects_symlinks_extra_app_files_and_bad_asset_hashes(self):
        link = zipfile.ZipInfo('dist/link')
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        for extra, corrupt in (([(link, b'outside')], False), ([('dist/app/extra.js', b'bad')], False), ([], True)):
            with self.subTest(extra=str(extra), corrupt=corrupt), tempfile.TemporaryDirectory() as temp:
                base = Path(temp)
                archive, config = self.fixture(base, extra, corrupt)
                with self.assertRaises(ValueError):
                    module().extract(archive, base / 'site', config)
                self.assertFalse((base / 'site').exists())

    def test_rejects_archive_hash_mismatch_and_existing_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            archive, config = self.fixture(base)
            changed = dict(config, artifact_sha256='0' * 64)
            with self.assertRaises(ValueError):
                module().extract(archive, base / 'site', changed)
            (base / 'site').mkdir()
            (base / 'site' / 'keep').write_text('keep')
            with self.assertRaises(ValueError):
                module().extract(archive, base / 'site', config)
            self.assertEqual((base / 'site' / 'keep').read_text(), 'keep')


if __name__ == '__main__':
    unittest.main()
