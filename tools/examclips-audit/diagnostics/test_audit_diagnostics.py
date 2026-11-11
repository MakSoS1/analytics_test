"""Checks for timestamp/camera/audio evidence logic; fixtures are not site exports."""
import math
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import numpy as np

from audit_diagnostics import (q, build_edl, map_output, map_source, camera_at,
                               validate_camera, correlate_audio, decode_and_sample, decode_outcome)


def track(keys, **extra):
    return {'version': 9, 'source': {'width': 1920, 'height': 1080}, 'keys': keys, **extra}


def key(start, end, x=0.0, y=0.0, w=1.0, h=1.0, motion='move'):
    return {'start': start, 'end': end, 'rect': {'x': x, 'y': y, 'w': w, 'h': h}, 'motion': motion}


class MappingTests(unittest.TestCase):
    def test_order_and_repetition_are_preserved(self):
        edl = build_edl({'segments': [{'start': 40, 'end': 42}, {'start': 2, 'end': 3}, {'start': 40, 'end': 42}]})
        self.assertEqual([p['source_start'] for p in edl], [q(40), q(2), q(40)])
        self.assertEqual([p['output_start'] for p in edl], [q(0), q(2), q(3)])

    def test_cut_is_right_continuous(self):
        edl = build_edl({'segments': [{'start': 10, 'end': 11}, {'start': 90, 'end': 92}]})
        self.assertEqual(map_output(edl, q(1))['source_time'], q(90))
        self.assertEqual(map_output(edl, q('0.999'))['source_time'], q('10.999'))

    def test_decimal_boundaries_are_exact(self):
        edl = build_edl({'segments': [{'start': '0.2', 'end': '1.6'}, {'start': '3.1', 'end': '3.3'}]})
        self.assertEqual(edl[-1]['output_end'], q('1.6'))
        self.assertEqual(map_output(edl, q('1.4'))['source_time'], q('3.1'))

    def test_source_event_can_occur_twice(self):
        edl = build_edl({'segments': [{'start': 3, 'end': 5}, {'start': 3, 'end': 4}]})
        self.assertEqual(map_source(edl, q('3.5')), [q('.5'), q('2.5')])

    def test_fallback_range_and_invalid_piece_filter(self):
        edl = build_edl({'start': 4, 'end': 6})
        self.assertEqual(edl[0]['source_start'], q(4))
        self.assertIsNone(map_output(edl, q(2)))
        self.assertEqual(build_edl({'segments': [{'start': 4, 'end': 4}, {'start': 5, 'end': 6}]}), build_edl({'start': 5, 'end': 6}))


class CameraTests(unittest.TestCase):
    def test_zoom_interpolates_geometrically(self):
        t = track([key(0, 0), key(2, 4, x=.375, y=.375, w=.25, h=.25)])
        r = camera_at(t, 3)
        self.assertAlmostEqual(r['w'], .5)
        self.assertAlmostEqual(r['x'] + r['w']/2, .5)

    def test_pan_uses_linear_time(self):
        t = track([key(0, 0, w=.4, h=.4), key(2, 6, x=.6, w=.4, h=.4, motion='pan')])
        self.assertAlmostEqual(camera_at(t, 3)['x'], .15)
        t['keys'][1]['motion'] = 'move'
        self.assertAlmostEqual(camera_at(t, 3)['x'], .0375)

    def test_zero_length_key_is_instant_even_without_cut_label(self):
        t = track([key(0, 0), key(2, 2, x=.25, y=.25, w=.5, h=.5)])
        self.assertEqual(camera_at(t, 2)['w'], .5)
        self.assertGreater(camera_at(t, 1.999)['w'], .99)

    def test_text_override_uses_half_open_interval(self):
        t = track([key(0, 0)], textSegments=[{'start': 1, 'end': 2, 'rect': {'x': .1, 'y': .1, 'w': .8, 'h': .8, 'fit': 'contain'}}])
        self.assertEqual(camera_at(t, 1)['fit'], 'contain')
        self.assertEqual(camera_at(t, 2)['w'], 1)

    def test_unknown_camera_version_is_rejected(self):
        t = track([key(0, 0)])
        self.assertTrue(validate_camera(t))
        t['version'] = 99
        self.assertFalse(validate_camera(t))


class AudioTests(unittest.TestCase):
    def test_positive_offset_means_later_source_match(self):
        rng = np.random.default_rng(7)
        reference = rng.normal(0, .1, 20000).astype(np.float32)
        output = reference[4321:10321].copy()
        evidence = correlate_audio(output, reference, 100.0, 100.2, 16000)
        self.assertAlmostEqual(evidence['best_offset_sec'], 4321/16000-.2, places=6)
        self.assertGreater(evidence['best_correlation'], .99999)

    def test_silence_is_inconclusive(self):
        evidence = correlate_audio(np.zeros(4000), np.zeros(8000), 0, 0, 16000)
        self.assertEqual(evidence['status'], 'inconclusive_constant_or_silent_audio')
        self.assertIsNone(evidence['best_offset_sec'])


class DiagnosticFailureTests(unittest.TestCase):
    def test_real_filter_initialization_failure_is_not_a_media_decode_verdict(self):
        log = '[AVFilterGraph] Error initializing filters\nError parsing global options: Invalid argument\n'
        result = decode_outcome(234, False, log)
        self.assertEqual(result['status'], 'diagnostic_initialization_failed')
        self.assertIsNone(result['ok'])


@unittest.skipUnless(shutil.which('ffmpeg') and shutil.which('ffprobe'), 'FFmpeg tools required')
class DecodeTimestampTest(unittest.TestCase):
    def test_exact_eight_tenths_frame_is_not_skipped(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            video = root / 'synthetic.mp4'
            subprocess.run(['ffmpeg', '-v', 'error', '-f', 'lavfi', '-i', 'color=c=blue:s=160x90:r=10:d=1.2', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-y', str(video)], check=True)
            report = decode_and_sample(video, root / 'samples', [q('.8')])
            self.assertTrue(report['full_decode']['ok'], report['full_decode'])
            self.assertEqual(q(report['requests'][0]['actual_output_time_exact']), q('.8'))

    def test_scene_screening_finds_actual_output_cut_in_same_pass(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            video = root / 'synthetic-cut.mp4'
            subprocess.run(['ffmpeg', '-v', 'error', '-f', 'lavfi', '-i', 'color=c=blue:s=160x90:r=10:d=0.6',
                            '-f', 'lavfi', '-i', 'color=c=white:s=160x90:r=10:d=0.6',
                            '-filter_complex', '[0:v][1:v]concat=n=2:v=1:a=0[v]', '-map', '[v]',
                            '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-y', str(video)], check=True)
            report = decode_and_sample(video, root / 'samples', [q(0)])
            self.assertTrue(report['full_decode']['ok'])
            self.assertEqual(report['scene_screening']['frame_count'], 12)
            self.assertTrue(any(q(c['output_time_exact']) == q('.6') for c in report['scene_screening']['candidates']))

    def test_large_sample_plans_keep_exact_pts_and_decode_all_frames(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            video = root / 'many-requests.mp4'
            subprocess.run(['ffmpeg', '-v', 'error', '-f', 'lavfi', '-i', 'color=c=blue:s=160x90:r=10:d=1.2',
                            '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-y', str(video)], check=True)
            for count in (212, 600):
                with self.subTest(request_count=count):
                    times = [q(i)*q('1.19')/count for i in range(count)]
                    times[-1] = q('.8')
                    report = decode_and_sample(video, root/str(count), times)
                    self.assertTrue(report['full_decode']['ok'], report['full_decode']['failure_tail'])
                    self.assertEqual(report['scene_screening']['frame_count'], 12)
                    self.assertEqual(len(report['requests']), len(set(times)))
                    exact_sample = next(r for r in report['requests'] if q(r['requested_output_time_exact']) == q('.8'))
                    self.assertEqual(q(exact_sample['actual_output_time_exact']), q('.8'))


if __name__ == '__main__':
    unittest.main()
