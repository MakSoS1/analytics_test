"""Regression contracts for recovery media; all fixtures are synthetic/public.

Written before the recovery wrapper change. Run on the authorized public GHA
runner; the unavailable local executor has not run these tests.
"""
import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

import media as recovery

q = recovery.core.q


def write_json(path, value):
    data = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    path.write_bytes(data)
    return data


def camera():
    return {'version': 9, 'source': {'width': 64, 'height': 48},
            'keys': [{'start': 0, 'end': 0, 'rect': {'x': .2, 'y': 0, 'w': .8, 'h': 1}}]}


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.case = pathlib.Path(self.temp.name) / 'rul03'
        self.case.mkdir()
        self.row = {'id': 'B', 'index': 1, 'file': 'clip-002.mp4',
                    'title': 'Initial title', 'start': 0, 'end': 1,
                    'segments': [{'start': 0, 'end': 1}],
                    'exportStatus': 'downloaded', 'actualSeconds': 1.0}
        self.result = {'id': 'rul03', 'clips': [self.row]}
        self.before = {'clips': [
            {'id': 'B', 'title': 'Before export', 'start': 3, 'end': 4,
             'segments': [{'start': 3, 'end': 4}]},
            {'id': 'A', 'title': 'Wrong index', 'start': 8, 'end': 9}],
            'lectureCamera': camera(), 'chunks': [{'start': 0, 'end': 1, 'text': 'Full original chunk'}]}
        self.snapshot = self.case / 'clip-002-project-before-export.json'
        self.snapshot_bytes = write_json(self.snapshot, {'snapshot': self.before})
        self.result_bytes = write_json(self.case / 'result.json', self.result)

    def bind(self):
        return recovery.bind_clip(self.case, self.result, 'clip-002.mp4', q(10))

    def test_unique_id_wins_over_initial_segments_and_array_index(self):
        bound = self.bind()
        self.assertTrue(bound['provenance']['mapping_allowed'])
        self.assertEqual(bound['snapshot_clip_index'], 0)
        self.assertEqual(bound['derived_row']['title'], 'Before export')
        self.assertEqual(bound['derived_row']['exportStatus'], 'downloaded')
        self.assertEqual(str(recovery.core.map_output(bound['edl'], q('.2'))['source_time']), '16/5')
        self.assertEqual(bound['snapshot']['lectureCamera']['keys'][0]['rect']['x'], .2)
        self.assertFalse(bound['provenance']['initial_result_edl_matches'])
        self.assertFalse(bound['provenance']['renderer_edl_confirmed'])

    def test_raw_snapshot_and_result_bytes_remain_unchanged(self):
        bound = self.bind()
        self.assertEqual(self.snapshot.read_bytes(), self.snapshot_bytes)
        self.assertEqual((self.case / 'result.json').read_bytes(), self.result_bytes)
        self.assertEqual(bound['provenance']['snapshot_sha256'],
                         hashlib.sha256(self.snapshot_bytes).hexdigest())
        self.assertEqual(bound['provenance']['result_sha256'],
                         hashlib.sha256(self.result_bytes).hexdigest())

    def test_duplicate_snapshot_id_disables_mapping_without_index_fallback(self):
        self.before['clips'].append(dict(self.before['clips'][0]))
        write_json(self.snapshot, {'snapshot': self.before})
        bound = self.bind()
        self.assertFalse(bound['provenance']['mapping_allowed'])
        self.assertEqual(bound['edl'], [])
        self.assertEqual(recovery.core.build_edl(bound['derived_row']), [])
        self.assertEqual(bound['snapshot'], {})

    def test_missing_snapshot_disables_mapping_without_initial_fallback(self):
        self.snapshot.unlink()
        bound = self.bind()
        self.assertFalse(bound['provenance']['mapping_allowed'])
        self.assertEqual(bound['edl'], [])
        self.assertEqual(recovery.core.build_edl(bound['derived_row']), [])

    def test_duplicate_result_filename_disables_mapping(self):
        self.result['clips'].append(dict(self.row, id='A'))
        bound = self.bind()
        self.assertFalse(bound['provenance']['mapping_allowed'])
        self.assertEqual(bound['edl'], [])

    def test_failed_saved_file_binds_unique_result_index_without_claiming_download(self):
        self.row.pop('file')
        self.row['exportStatus'] = 'failed'
        self.row['exportReason'] = 'Export duration does not match the complete topic EDL'
        bound = self.bind()
        self.assertTrue(bound['provenance']['mapping_allowed'])
        self.assertEqual(bound['provenance']['result_binding'], 'unique_result_index_for_existing_file')
        self.assertEqual(bound['derived_row']['exportStatus'], 'failed')
        self.assertEqual(bound['derived_row']['file'], 'clip-002.mp4')
        self.assertEqual(str(bound['edl'][0]['source_start']), '3')

    def test_conflicting_result_filename_cannot_be_rebound_by_index(self):
        self.row['file'] = 'clip-099.mp4'
        self.assertFalse(self.bind()['provenance']['mapping_allowed'])

    def test_invalid_segment_does_not_silently_become_partial_edl(self):
        self.before['clips'][0]['segments'].append({'start': 5, 'end': 4})
        write_json(self.snapshot, self.before)
        bound = self.bind()
        self.assertFalse(bound['provenance']['mapping_allowed'])
        self.assertEqual(recovery.core.build_edl(bound['derived_row']), [])

    def test_out_of_source_segment_disables_mapping(self):
        self.before['clips'][0]['segments'] = [{'start': 9, 'end': 11}]
        write_json(self.snapshot, self.before)
        self.assertFalse(self.bind()['provenance']['mapping_allowed'])


class PlanningTests(unittest.TestCase):
    def test_title_first_second_uniform_grid_and_smooth_event_limit(self):
        track = camera()
        track['keys'] = [{'start': 2*i, 'end': 2*i+1,
                          'rect': {'x': 0, 'y': 0, 'w': 1, 'h': 1}}
                         for i in range(60)]
        edl = recovery.core.build_edl({'start': 0, 'end': 125})
        plans, events = recovery.bounded_sample_plan(q(125), edl, track)
        by_time = {p['requested_output_time_exact']: p['reasons'] for p in plans}
        self.assertIn('title_first_second', by_time['1'])
        self.assertEqual([p['requested_output_time_exact'] for p in plans
                          if 'uniform_grid' in p['reasons']], ['0', '60', '120'])
        self.assertEqual(events['optional_smooth_events_sampled'], 12)
        self.assertGreater(events['optional_smooth_events_omitted'], 0)

    def test_complement_keeps_sub_three_second_gaps_and_clips_overlaps(self):
        nav = recovery.source_complement(q(10), [(q(0), q(3)), (q(2), q(3)),
                                               (q('3.2'), q(4)), (q(6), q(8))])
        self.assertEqual([(x['start_exact'], x['end_exact']) for x in nav['gaps']],
                         [('3', '16/5'), ('4', '6'), ('8', '10')])
        self.assertEqual(nav['gap_seconds_exact'], '21/5')


class ActualVFRTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('ffmpeg') or not shutil.which('ffprobe'):
            raise RuntimeError('Real media regression requires ffmpeg and ffprobe; do not skip the gate')
        cls.temp = tempfile.TemporaryDirectory()
        cls.base = pathlib.Path(cls.temp.name)
        cls.video = cls.base / 'vfr.mp4'
        command = ['ffmpeg', '-nostdin', '-hide_banner', '-loglevel', 'error',
                   '-threads', '1', '-f', 'lavfi', '-i',
                   'testsrc2=size=64x48:rate=25:duration=0.4',
                   '-vf', "select='eq(n,0)+eq(n,1)+eq(n,4)+eq(n,9)'",
                   '-fps_mode', 'passthrough', '-c:v', 'libx264', '-threads:v', '1',
                   '-bf', '0', '-video_track_timescale', '12800', '-y', str(cls.video)]
        subprocess.run(command, check=True, capture_output=True, timeout=30)
        inspected = subprocess.run(['ffprobe', '-v', 'error', '-select_streams', 'v:0',
                                    '-show_entries', 'frame=best_effort_timestamp_time',
                                    '-of', 'json', str(cls.video)],
                                   check=True, capture_output=True, text=True, timeout=30)
        times = [q(f['best_effort_timestamp_time']) for f in json.loads(inspected.stdout)['frames']]
        if times != [q(0), q('.04'), q('.16'), q('.36')]:
            raise AssertionError('Fixture is not the required actual nonuniform VFR clock: ' + str(times))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_full_decode_and_select_use_next_actual_vfr_pts(self):
        out = self.base / 'decode'
        report = recovery.core.decode_and_sample(self.video, out,
                    [q(0), q('.04'), q('.10'), q('.16'), q('.35'), q('.36')])
        self.assertTrue(report['full_decode']['ok'], report['full_decode'])
        self.assertFalse(report['time_base_mismatch'])
        self.assertEqual([r['actual_output_time_exact'] for r in report['requests']],
                         ['0', '1/25', '4/25', '4/25', '9/25', '9/25'])
        self.assertTrue(all((out / r['image_file']).is_file() for r in report['requests']))
        self.assertEqual(report['scene_screening']['frame_count'], 4)

    def test_single_frame_operation_preserves_relative_path_and_pts(self):
        case = self.base / 'frame-case'
        case.mkdir()
        shutil.copyfile(self.video, case / 'original-source.mp4')
        record = recovery.extract_frame(case, 'original-source.mp4', '.10')
        self.assertEqual(record['actual_source_time_exact'], '4/25')
        self.assertFalse(pathlib.Path(record['image_file']).is_absolute())
        self.assertTrue((case / record['image_file']).is_file())

    def test_actual_clip_inspection_uses_preexport_and_keeps_raw_bytes(self):
        case = self.base / 'inspection-case'
        case.mkdir()
        shutil.copyfile(self.video, case / 'original-source.mp4')
        shutil.copyfile(self.video, case / 'clip-001.mp4')
        source_sha = hashlib.sha256(self.video.read_bytes()).hexdigest()
        result = {'id': 'fixture', 'source': {'sha256': source_sha},
                  'clips': [{'id': 'kept', 'index': 0, 'file': 'clip-001.mp4',
                             'title': 'Stale metadata', 'start': 5, 'end': 5.4,
                             'segments': [{'start': 5, 'end': 5.4}],
                             'exportStatus': 'downloaded'}]}
        project = {'clips': [{'id': 'kept', 'title': 'Preferred metadata',
                             'start': 0, 'end': .4,
                             'segments': [{'start': 0, 'end': .4}]}],
                   'lectureCamera': camera(), 'chunks': [{'start': 0, 'end': .4, 'text': 'Synthetic'}]}
        original_result = write_json(case / 'result.json', result)
        original_project = write_json(case / 'clip-001-project-before-export.json', project)
        summary = recovery.inspect_recovery(case)
        self.assertTrue(summary['all_downloaded_files_decoded'])
        self.assertEqual(summary['mapped_existing_clips'], 1)
        report = json.loads((case / 'recovery-diagnostics/clip-001/diagnostics.json').read_text())
        self.assertEqual(report['title'], 'Preferred metadata')
        self.assertEqual(report['edl'][0]['source_start_exact'], '0')
        self.assertTrue(report['timing_provenance']['mapping_allowed'])
        self.assertEqual(report['saved_camera']['project_file'], 'clip-001-project-before-export.json')
        self.assertEqual(report['samples'][0]['mapped_source_time_exact'], '0')
        self.assertEqual((case / 'result.json').read_bytes(), original_result)
        self.assertEqual((case / 'clip-001-project-before-export.json').read_bytes(), original_project)


if __name__ == '__main__':
    unittest.main()
