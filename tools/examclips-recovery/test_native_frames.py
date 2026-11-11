"""Only synthetic VFR media is used for supplementary frame path guards."""
import copy
import json
import pathlib
import shutil
import tempfile
import unittest

import media as recovery
import test_media as fixtures


class NativeFrameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.ActualVFRTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.ActualVFRTests.tearDownClass()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.case = self.root / 'rul01'
        self.case.mkdir()
        shutil.copyfile(fixtures.ActualVFRTests.video, self.case / 'native-clip.mp4')
        self.run = {
            'repository': 'MakSoS1/analytics_test', 'branch': 'qa/examclips-audit-2026-11-11',
            'runId': '43116421328', 'runAttempt': '1', 'caseId': 'rul01',
            'auditKind': 'native_export_probe', 'supplementary': True, 'corpusCountIncrement': 0
        }
        self.result = {'id': 'rul01', 'auditKind': 'native_export_probe',
                       'supplementary': True, 'corpusCountIncrement': 0}
        self.save()

    def save(self):
        fixtures.write_json(self.root / 'run.json', self.run)
        fixtures.write_json(self.case / 'result.json', self.result)

    def test_bound_native_frame_uses_the_actual_integer_vfr_clock(self):
        record = recovery.extract_frame(self.case, 'native-clip.mp4', '.10')
        self.assertEqual(record['actual_source_time_exact'], '4/25')
        self.assertEqual(record['media_file'], 'native-clip.mp4')
        self.assertEqual(record['media_kind'], 'supplementary_native_export')
        self.assertEqual(record['corpusCountIncrement'], 0)
        self.assertFalse(pathlib.Path(record['image_file']).is_absolute())
        self.assertTrue((self.case / record['image_file']).is_file())

    def test_primary_wrong_run_wrong_case_and_missing_supplementary_flags_reject(self):
        original_run, original_result = copy.deepcopy(self.run), copy.deepcopy(self.result)
        variants = [
            ('run', 'runId', '43090979122'),
            ('run', 'caseId', 'rul02'),
            ('run', 'branch', 'main'),
            ('run', 'auditKind', 'primary'),
            ('result', 'supplementary', False),
            ('result', 'corpusCountIncrement', 1)
        ]
        for object_name, key, value in variants:
            with self.subTest(object_name=object_name, key=key):
                self.run, self.result = copy.deepcopy(original_run), copy.deepcopy(original_result)
                getattr(self, object_name)[key] = value
                self.save()
                with self.assertRaisesRegex(ValueError, 'NATIVE_FRAME_CONTEXT_MISMATCH'):
                    recovery.extract_frame(self.case, 'native-clip.mp4', '.1')

    def test_native_media_symlink_rejects(self):
        media = self.case / 'native-clip.mp4'
        media.unlink()
        media.symlink_to(fixtures.ActualVFRTests.video)
        with self.assertRaisesRegex(ValueError, 'MEDIA_NOT_REGULAR'):
            recovery.extract_frame(self.case, 'native-clip.mp4', '.1')

    def test_native_metadata_symlink_rejects(self):
        metadata = self.case / 'result.json'
        private_copy = self.root / 'result-copy.json'
        metadata.rename(private_copy)
        metadata.symlink_to(private_copy)
        with self.assertRaisesRegex(ValueError, 'NATIVE_FRAME_METADATA_NOT_REGULAR'):
            recovery.extract_frame(self.case, 'native-clip.mp4', '.1')

    def test_no_other_native_or_arbitrary_path_is_accepted(self):
        for name in ('../native-clip.mp4', '/native-clip.mp4', 'sub/native-clip.mp4',
                     'native-other.mp4', 'private.pem'):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, 'INVALID_MEDIA_NAME'):
                    recovery.extract_frame(self.case, name, '.1')


if __name__ == '__main__':
    unittest.main()
