"""Regression evidence must follow exact saved source ownership, never a guessed frame."""
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

MODULE = pathlib.Path(__file__).with_name('retest-review.py')


def read_module():
    if not MODULE.exists():
        return None
    spec = importlib.util.spec_from_file_location('retest_review', MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def put(path, value):
    path.write_text(json.dumps(value))


class RetestReviewTests(unittest.TestCase):
    def setUp(self):
        self.review = read_module()
        self.assertIsNotNone(self.review, 'The bounded current-app review utility is not implemented')

    def test_pre_export_clip_id_wins_over_reordered_final_project_and_result(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            put(root/'clip-001-project-before-export.json', {'clips': [
                {'id': 'other', 'start': 90, 'end': 92},
                {'id': 'selected', 'segments': [{'start': 20, 'end': 21}, {'start': 2, 'end': 4}, {'start': 20, 'end': 21}]},
            ]})
            put(root/'project-final.json', {'clips': [{'id': 'selected', 'start': 30, 'end': 34}]})
            choice = self.review.choose_edl(root, 'clip-001.mp4', [{'id': 'selected', 'index': 0, 'file': 'clip-001.mp4', 'start': 0, 'end': 4}])
            self.assertEqual(choice['selected_provenance']['file'], 'clip-001-project-before-export.json')
            self.assertEqual([float(x) for x in self.review.diag.map_source(choice['edl'], 20.5)], [0.5, 3.5])
            self.assertEqual(float(self.review.diag.map_output(choice['edl'], 1.5)['source_time']), 2.5)
            self.assertTrue(choice['edl_mismatch'])

    def test_missing_target_is_absent_and_repeated_source_target_keeps_both_occurrences(self):
        edl = self.review.diag.build_edl({'segments': [{'start': 20, 'end': 21}, {'start': 2, 'end': 4}, {'start': 20, 'end': 21}]})
        plan = self.review.plan_samples(4, edl, [
            {'id': 'repeat', 'source_seconds': 20.5, 'reason': 'test'},
            {'id': 'absent', 'source_seconds': 7, 'reason': 'test'},
        ])
        self.assertEqual(plan['targets'][0]['mapped_output_times_sec'], [0.5, 3.5])
        self.assertEqual(plan['targets'][1]['status'], 'absent_from_edl')
        self.assertEqual(plan['targets'][1]['mapped_output_times_sec'], [])
        target_times = [r['requested_output_time_sec'] for r in plan['requests'] if any('target:repeat:center' == why for why in r['reasons'])]
        self.assertEqual(target_times, [0.5, 3.5])

    def test_semantic_coverage_reports_unique_source_time_without_double_counting_repeats(self):
        edl = self.review.diag.build_edl({'segments': [{'start': 20, 'end': 21}, {'start': 2, 'end': 4}, {'start': 20, 'end': 21}]})
        report = self.review.semantic_coverage(edl, [{'id': 'some', 'start': 19, 'end': 22}, {'id': 'none', 'start': 7, 'end': 8}])
        self.assertEqual(report[0]['covered_unique_source_seconds'], 1)
        self.assertEqual(report[0]['covered_output_seconds'], 2)
        self.assertAlmostEqual(report[0]['source_coverage_fraction'], 1/3)
        self.assertEqual(report[1]['status'], 'absent_from_edl')
        self.assertIsNone(report[0]['semantic_verdict'])

    def test_boundary_sampling_cap_is_explicit_and_uniform_samples_remain(self):
        edl = self.review.diag.build_edl({'segments': [{'start': i*20, 'end': i*20+5} for i in range(80)]})
        plan = self.review.plan_samples(400, edl, [], max_boundaries=3)
        self.assertEqual(plan['boundary_selection']['total'], 79)
        self.assertEqual(plan['boundary_selection']['selected'], 3)
        self.assertEqual(plan['boundary_selection']['omitted'], 76)
        uniform = [r['requested_output_time_sec'] for r in plan['requests'] if 'uniform_60s' in r['reasons']]
        self.assertEqual(uniform, [60, 120, 180, 240, 300, 360])

    def test_zero_deadline_records_all_omissions_without_any_media_executable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            case = root/'fixture'
            case.mkdir()
            (case/'original-source.mp4').write_bytes(b'Not opened when review has no budget')
            (case/'clip-001.mp4').write_bytes(b'Not decoded when review has no budget')
            process = subprocess.run([sys.executable, str(MODULE), '--evidence', str(root), '--case', 'fixture',
                                      '--targets', str(root/'no-targets.json'), '--deadline-seconds', '0'],
                                     env={**os.environ, 'PATH': ''}, capture_output=True, text=True, timeout=10)
            self.assertEqual(process.returncode, 1)
            summary = json.loads((case/'retest-review'/'review.json').read_text())
            self.assertEqual(summary['status'], 'incomplete')
            self.assertEqual(summary['clips'], [{'file':'clip-001.mp4','status':'not_reviewed_deadline','full_decode_completed':False}])
            self.assertFalse((case/'retest-review'/'source-context.json').exists())

    @unittest.skipUnless(shutil.which('ffmpeg') and shutil.which('ffprobe'), 'Real FFmpeg is required')
    def test_real_mp4_fully_decodes_and_pairs_actual_pts_with_the_mapped_original(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            source = root/'original-source.mp4'
            subprocess.run(['ffmpeg', '-v', 'error', '-f', 'lavfi', '-i', 'testsrc2=size=240x320:rate=15',
                            '-f', 'lavfi', '-i', 'sine=frequency=440:sample_rate=48000', '-t', '2',
                            '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-c:a', 'aac', '-y', str(source)], check=True)
            shutil.copyfile(source, root/'clip-001.mp4')
            row = {'id': 'fixture', 'index': 0, 'file': 'clip-001.mp4', 'start': 0, 'end': 2, 'exportStatus': 'downloaded'}
            put(root/'result.json', {'id': 'fixture-case', 'clips': [row], 'source': {'sha256': self.review.diag.digest(source)}})
            put(root/'clip-001-project-before-export.json', {'clips': [row]})
            target = {'id': 'fixture-case', 'visual_points': [{'id': 'present', 'source_seconds': 0.4}, {'id': 'missing', 'source_seconds': 8}], 'semantic_ranges': []}
            report = self.review.review_clip(root, root/'clip-001.mp4', root/'review', target, max_source_pairs=4)
            self.assertEqual(report['full_decode']['status'], 'completed')
            self.assertEqual(report['full_av_decode_passes'], 1)
            self.assertEqual(report['source']['sha256'], report['clip_sha256'])
            self.assertEqual(report['visual_targets'][1]['status'], 'absent_from_edl')
            self.assertLessEqual(report['source_pair_selection']['attempted'], 4)
            paired = [row for row in report['samples'] if row.get('source_frame', {}).get('image_file')]
            self.assertTrue(paired)
            for sample in paired:
                self.assertIn('actual_raw_pts', sample)
                self.assertGreaterEqual(sample['source_frame']['actual_source_time_sec'] + 0.00001, sample['mapped_source_time_sec'])
            self.assertIsNone(report['quality_verdict'])


if __name__ == '__main__':
    unittest.main()
