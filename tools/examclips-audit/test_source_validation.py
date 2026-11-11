import importlib.util
import pathlib
import unittest

class SourceDurationTest(unittest.TestCase):
    def api(self):
        path = pathlib.Path(__file__).with_name('source_validation.py')
        self.assertTrue(path.exists(), 'Actual complete-source duration admission is required')
        spec = importlib.util.spec_from_file_location('source_validation', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_source_under_two_hours_cannot_enter_long_corpus(self):
        api = self.api()
        with self.assertRaisesRegex(ValueError, 'minimum'):
            api.validate_duration(7199.9, 7200, minimum=7200)
        api.validate_duration(7200, 7200, minimum=7200)
        api.validate_duration(10800, 10800, minimum=7200)

    def test_mismatch_nonfinite_and_over_three_hours_rejected(self):
        api = self.api()
        for actual in [float('nan'), float('inf'), -1, 0, 10800.1]:
            with self.assertRaises(ValueError):
                api.validate_duration(actual, 0, minimum=7200)
        with self.assertRaisesRegex(ValueError, 'match'):
            api.validate_duration(8000, 9000, minimum=7200)
        api.validate_duration(8313.898, 8313, minimum=7200)

if __name__ == '__main__':
    unittest.main()
