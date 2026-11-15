"""Catch missing/trimmed tracks and unintended lower-resolution selection in a transport-only fallback."""
import io
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from hls_mirror import mirror_vod_hls, TibRedirectHandler
import urllib.request

FFMPEG=os.environ.get('AUDIT_FFMPEG','ffmpeg')
FFPROBE=os.environ.get('AUDIT_FFPROBE','ffprobe')
BASE='https://av.tib.eu/public-fixture/'

class Response(io.BytesIO):
    status=200
    def __init__(self, data, url):
        super().__init__(data)
        self.headers={'Content-Length':str(len(data))}
        self.url=url
    def geturl(self): return self.url

class HlsMirrorTests(unittest.TestCase):
    def test_entire_higher_resolution_video_and_separate_audio_survive_offline_remux(self):
        # A wrong variant, missing audio, trimmed byterange, or changed timestamp fails this.
        with tempfile.TemporaryDirectory() as temp:
            base=pathlib.Path(temp); original=base/'original';original.mkdir()
            for name,size in [('high','320x180'),('low','160x90')]:
                subprocess.run([FFMPEG,'-v','error','-f','lavfi','-i',f'testsrc2=size={size}:rate=25:duration=4.4','-an','-c:v','libx264','-preset','ultrafast','-g','25','-f','hls','-hls_playlist_type','vod','-hls_time','1','-hls_segment_type','fmp4','-hls_flags','single_file',str(original/(name+'.m3u8'))],check=True)
            subprocess.run([FFMPEG,'-v','error','-f','lavfi','-i','sine=frequency=440:sample_rate=48000:duration=4.4','-vn','-c:a','aac','-f','hls','-hls_playlist_type','vod','-hls_time','1','-hls_segment_type','fmp4','-hls_flags','single_file',str(original/'audio.m3u8')],check=True)
            master='#EXTM3U\n#EXT-X-VERSION:6\n#EXT-X-INDEPENDENT-SEGMENTS\n#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="audio",NAME="1",AUTOSELECT=YES,URI="audio.m3u8",CHANNELS="1"\n#EXT-X-STREAM-INF:BANDWIDTH=100000,RESOLUTION=160x90,AUDIO="audio"\nlow.m3u8\n#EXT-X-STREAM-INF:BANDWIDTH=400000,RESOLUTION=320x180,AUDIO="audio"\nhigh.m3u8\n'
            (original/'master.m3u8').write_text(master)
            reference='#EXTM3U\n#EXT-X-VERSION:6\n#EXT-X-INDEPENDENT-SEGMENTS\n#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="audio",NAME="1",AUTOSELECT=YES,URI="audio.m3u8",CHANNELS="1"\n#EXT-X-STREAM-INF:BANDWIDTH=400000,RESOLUTION=320x180,AUDIO="audio"\nhigh.m3u8\n'
            (original/'reference-high-only.m3u8').write_text(reference)
            files={BASE+p.name:p.read_bytes() for p in original.iterdir()}
            downloaded=[]
            def fetch(url):
                downloaded.append(url)
                return Response(files[url],url)
            mirrored=mirror_vod_hls(BASE+'master.m3u8',base/'mirror',fetch)
            self.assertIsInstance(mirrored,pathlib.Path,'The public VOD was not mirrored into a local playlist')
            outputs=[]
            for i,playlist in enumerate([original/'reference-high-only.m3u8',mirrored]):
                output=base/f'output-{i}.mp4'
                subprocess.run([FFMPEG,'-v','error','-protocol_whitelist','file,crypto,data','-i',str(playlist),'-c','copy','-movflags','+faststart',str(output)],check=True)
                outputs.append(output)
            meta=json.loads(subprocess.check_output([FFPROBE,'-v','error','-show_streams','-show_format','-of','json',str(outputs[1])]))
            self.assertEqual({s['codec_type'] for s in meta['streams']},{'video','audio'})
            self.assertEqual(next(s['width'] for s in meta['streams'] if s['codec_type']=='video'),320)
            self.assertGreater(float(meta['format']['duration']),4.3)
            frame_count=subprocess.check_output([FFPROBE,'-v','error','-select_streams','v:0','-count_frames','-show_entries','stream=nb_read_frames','-of','csv=p=0',str(outputs[1])],text=True).strip()
            self.assertEqual(frame_count,'110','All 4.4 seconds / 110 source frames must be retained')
            for stream in ['v:0','a:0']:
                hashes=[subprocess.check_output([FFMPEG,'-v','error','-i',str(p),'-map','0:'+stream,'-f','framemd5','-']) for p in outputs]
                self.assertEqual(hashes[0],hashes[1],f'All decoded {stream} frames and timestamps must survive')
            self.assertFalse(any(url.endswith('low.m3u8') for url in downloaded),'Lower variant must not be downloaded')
            self.assertTrue(all('https://' not in p.read_text() for p in (base/'mirror').glob('*.m3u8')),'FFmpeg must need only local files')

    def test_rejects_incomplete_or_encrypted_vod_before_media_download(self):
        # A transport fallback must not silently turn a live/partial or protected playlist into a test input.
        for body in ['#EXTM3U\n#EXTINF:4,\nvideo.ts\n', '#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI="key"\n#EXTINF:4,\nvideo.ts\n#EXT-X-ENDLIST\n']:
            with self.subTest(body=body),tempfile.TemporaryDirectory() as temp:
                def fetch(url):
                    self.assertEqual(url,BASE+'media.m3u8','Media must not be fetched after a rejected playlist')
                    return Response(body.encode(),url)
                with self.assertRaisesRegex(ValueError,'(?:complete|encrypted)'):
                    mirror_vod_hls(BASE+'media.m3u8',pathlib.Path(temp)/'out',fetch)

    def test_rejects_external_media_destination(self):
        # An untrusted playlist must not send the downloader to a different origin.
        body='#EXTM3U\n#EXTINF:4,\nhttps://other.example/private.ts\n#EXT-X-ENDLIST\n'
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError,'origin'):
                mirror_vod_hls(BASE+'media.m3u8',pathlib.Path(temp)/'out',lambda url:Response(body.encode(),url))

    def test_rejects_oversized_media_and_removes_partial_track(self):
        # A network response exceeding the source budget must not remain as a plausible complete track.
        body='#EXTM3U\n#EXTINF:4,\nvideo.ts\n#EXT-X-ENDLIST\n'
        with tempfile.TemporaryDirectory() as temp:
            dest=pathlib.Path(temp)/'out'
            def fetch(url):return Response(body.encode() if url.endswith('.m3u8') else b'X'*9,url)
            with self.assertRaisesRegex(ValueError,'budget'):
                mirror_vod_hls(BASE+'media.m3u8',dest,fetch,max_bytes=8)
            self.assertFalse(any(p.suffix in {'.ts','.part'} for p in dest.glob('*')))

    def test_redirect_policy_rejects_external_origin_before_following_it(self):
        # The HTTP redirect handler must reject before urllib opens the redirected URL.
        handler=TibRedirectHandler();req=urllib.request.Request(BASE+'media.m3u8')
        with self.assertRaisesRegex(ValueError,'origin'):
            handler.redirect_request(req,None,302,'Found',{},'https://other.example/media.m3u8')
        redirected=handler.redirect_request(req,None,302,'Found',{},BASE+'next.m3u8')
        self.assertEqual(redirected.full_url,BASE+'next.m3u8')

    def test_rejects_out_of_bounds_or_unpaired_vod_segments(self):
        # ENDLIST alone must not turn a damaged playlist or a truncated byte-range track into complete media.
        bodies=[
            '#EXTM3U\n#EXT-X-MAP:URI="video.mp4",BYTERANGE="10@0"\n#EXTINF:4,\n#EXT-X-BYTERANGE:2@0\nvideo.mp4\n#EXT-X-ENDLIST\n',
            '#EXTM3U\n#EXTINF:4,\n#EXT-X-BYTERANGE:2@8\nvideo.mp4\n#EXT-X-ENDLIST\n',
            '#EXTM3U\n#EXTINF:4,\n#EXT-X-BYTERANGE:2\nvideo.mp4\n#EXT-X-ENDLIST\n',
            '#EXTM3U\n#EXTINF:4,\n#EXTINF:3,\nvideo.mp4\n#EXT-X-ENDLIST\n',
            '#EXTM3U\nvideo.mp4\n#EXTINF:4,\n#EXT-X-ENDLIST\n',
            '#EXTM3U\n#EXTINF:4,\n#EXT-X-ENDLIST\n',
        ]
        for body in bodies:
            with self.subTest(body=body),tempfile.TemporaryDirectory() as temp:
                def fetch(url):return Response(body.encode() if url.endswith('.m3u8') else b'X'*9,url)
                with self.assertRaisesRegex(ValueError,'(?:range|segment|EXTINF)'):
                    mirror_vod_hls(BASE+'media.m3u8',pathlib.Path(temp)/'out',fetch)

    def test_rejects_declared_missing_segments(self):
        # A complete-looking ENDLIST with EXT-X-GAP explicitly contains missing material.
        for tag in ['#EXT-X-GAP','#EXT-X-SKIP:SKIPPED-SEGMENTS=2','#EXT-X-I-FRAMES-ONLY']:
            body='#EXTM3U\n'+tag+'\n#EXTINF:4,\nvideo.mp4\n#EXT-X-ENDLIST\n'
            with self.subTest(tag=tag),tempfile.TemporaryDirectory() as temp:
                def fetch(url):return Response(body.encode() if url.endswith('.m3u8') else b'X'*9,url)
                with self.assertRaisesRegex(ValueError,'(?:missing|partial|GAP)'):
                    mirror_vod_hls(BASE+'media.m3u8',pathlib.Path(temp)/'out',fetch)

    def test_relative_media_uses_effective_playlist_url_after_same_origin_redirect(self):
        # A legitimate same-origin redirect to a different directory must keep relative segment resolution correct.
        old='https://av.tib.eu/old/media.m3u8';new='https://av.tib.eu/moved/media.m3u8'
        body=b'#EXTM3U\n#EXTINF:4,\ntrack.ts\n#EXT-X-ENDLIST\n';requested=[]
        def fetch(url):
            requested.append(url)
            return Response(body,new) if url==old else Response(b'X'*9,url)
        with tempfile.TemporaryDirectory() as temp:
            mirror_vod_hls(old,pathlib.Path(temp)/'out',fetch)
        self.assertEqual(requested,[old,'https://av.tib.eu/moved/track.ts'])

if __name__=='__main__':unittest.main()
