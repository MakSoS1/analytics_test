import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

MODULE=Path(__file__).with_name('media_validation.py')

class NativeMediaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name);cls.media=cls.root/'actual-fixture.mp4'
        subprocess.run(['ffmpeg','-v','error','-f','lavfi','-i','testsrc2=size=160x90:rate=15','-f','lavfi','-i','sine=frequency=440:sample_rate=48000','-t','2.4','-c:v','libx264','-threads','2','-pix_fmt','yuv420p','-c:a','aac','-movflags','+faststart',str(cls.media)],check=True,timeout=30)
        cls.vfr=cls.root/'actual-nonuniform-fixture.mp4'
        # Four EDL-like spans: .201/.907/.333/.959 seconds, whose independent
        # frame ceilings total 38 rather than 36. The first short final frame
        # is followed by the next segment only one millisecond later.
        pts='if(lt(N,4),N/15,if(lt(N,18),0.201+(N-4)/15,if(lt(N,23),1.108+(N-18)/15,1.441+(N-23)/15)))/TB'
        subprocess.run(['ffmpeg','-v','error','-f','lavfi','-i','testsrc2=size=160x90:rate=15','-f','lavfi','-i','sine=frequency=660:sample_rate=48000',
                        '-vf',"settb=expr=1/90000,setpts='"+pts+"'",'-t','2.4','-fps_mode:v','passthrough','-enc_time_base:v','1/90000',
                        '-c:v','libx264','-threads','2','-pix_fmt','yuv420p','-c:a','aac','-video_track_timescale','90000','-movflags','+faststart',str(cls.vfr)],check=True,timeout=30)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def module(self):
        self.assertTrue(MODULE.is_file(),'native MP4 validator is implemented')
        spec=importlib.util.spec_from_file_location('native_media',MODULE);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def test_decodes_an_actual_complete_mp4_and_reports_facts_without_quality_verdict(self):
        m=self.module();r=m.validate_media(self.media,2.4,expected_frames=36,timeout_seconds=30)
        self.assertTrue(r['full_decode_passed']);self.assertAlmostEqual(r['video_duration'],2.4,places=2);self.assertIsNone(r['quality_verdict'])
    def test_rejects_duration_mismatch_even_when_the_file_is_decodable(self):
        m=self.module()
        with self.assertRaisesRegex(ValueError,'DURATION_MISMATCH'):m.validate_media(self.media,8,timeout_seconds=30)
    def test_rejects_a_truncated_actual_mp4(self):
        m=self.module();truncated=self.root/'truncated.mp4';b=self.media.read_bytes();truncated.write_bytes(b[:len(b)//2])
        with self.assertRaisesRegex(ValueError,'MEDIA_(DECODE|PROBE|FRAME_COUNT)_FAILED'):m.validate_media(truncated,2.4,expected_frames=36,timeout_seconds=30)
    def test_preserves_frames_across_actual_nonuniform_edl_like_timestamps(self):
        m=self.module();r=m.validate_media(self.vfr,2.4,expected_frames=38,timeout_seconds=30)
        self.assertTrue(r['full_decode_passed']);self.assertEqual(r['container_video_frames'],38);self.assertEqual(r['decoded_video_frames'],38)

if __name__=='__main__':unittest.main()
