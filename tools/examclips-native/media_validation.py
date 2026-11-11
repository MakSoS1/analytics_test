#!/usr/bin/env python3
"""Report container, duration, frame-count and full-decode facts for native MP4s."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import math
from pathlib import Path
import subprocess
import time

def validate_media(path,expected_seconds,expected_frames=None,timeout_seconds=3600):
    path=Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size<1024:raise ValueError('MEDIA_PROBE_FAILED')
    if not math.isfinite(expected_seconds) or expected_seconds<=0:raise ValueError('INVALID_EXPECTED_DURATION')
    started=time.monotonic()
    probe=subprocess.run(['ffprobe','-v','error','-show_format','-show_streams','-of','json',str(path)],
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=min(60,timeout_seconds))
    if probe.returncode:raise ValueError('MEDIA_PROBE_FAILED')
    try:
        data=json.loads(probe.stdout);video=next(s for s in data['streams'] if s['codec_type']=='video');audio=next(s for s in data['streams'] if s['codec_type']=='audio')
        vd=float(video.get('duration',data['format']['duration']));ad=float(audio.get('duration',data['format']['duration']))
    except (ValueError,KeyError,StopIteration,TypeError):raise ValueError('MEDIA_PROBE_FAILED')
    if abs(vd-expected_seconds)>.2 or abs(ad-expected_seconds)>.35:raise ValueError('MEDIA_DURATION_MISMATCH')
    frames=int(video['nb_frames']) if str(video.get('nb_frames','')).isdigit() else None
    if expected_frames is not None and frames is not None and frames!=expected_frames:raise ValueError('MEDIA_FRAME_COUNT_FAILED')
    remaining=max(1,timeout_seconds-(time.monotonic()-started))
    decode=subprocess.run(['ffmpeg','-nostdin','-hide_banner','-v','error','-xerror','-err_detect','explode','-threads','2',
                           '-i',str(path),'-map','0:v:0','-map','0:a:0','-filter_threads','1',
                           '-fps_mode:v','passthrough','-enc_time_base:v','-1',
                           '-progress','pipe:1','-nostats','-f','null','-'],
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=remaining)
    if decode.returncode:raise ValueError('MEDIA_DECODE_FAILED')
    decoded_frames=[int(line.split('=',1)[1]) for line in decode.stdout.splitlines() if line.startswith('frame=') and line.split('=',1)[1].strip().isdigit()]
    final_frames=decoded_frames[-1] if decoded_frames else None
    if expected_frames is not None and final_frames!=expected_frames:raise ValueError('MEDIA_FRAME_COUNT_FAILED')
    h=hashlib.sha256()
    with path.open('rb') as incoming:
        while block:=incoming.read(1024**2):h.update(block)
    return {'checked_utc':datetime.now(timezone.utc).isoformat(),'file':path.name,'bytes':path.stat().st_size,'sha256':h.hexdigest(),
            'expected_duration':expected_seconds,'video_duration':vd,'audio_duration':ad,'container_duration':float(data['format']['duration']),
            'expected_video_frames':expected_frames,'container_video_frames':frames,'decoded_video_frames':final_frames,
            'width':video.get('width'),'height':video.get('height'),'video_codec':video.get('codec_name'),'audio_codec':audio.get('codec_name'),
            'full_decode_passed':True,'full_decode_video_and_audio':True,'decoder_threads':2,'elapsed_seconds':time.monotonic()-started,
            'decode_video_timing':'passthrough with demux time base; no CFR duplication/drop for null output',
            'quality_verdict':None,'limitation':'Container/decode/timing facts do not establish title, semantic, visual or audio quality.'}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('input',type=Path);parser.add_argument('--expected-seconds',type=float,required=True)
    parser.add_argument('--expected-frames',type=int);parser.add_argument('--report',type=Path,required=True);parser.add_argument('--timeout',type=float,default=3600);args=parser.parse_args()
    try:
        result=validate_media(args.input,args.expected_seconds,args.expected_frames,args.timeout);status=0
    except Exception as error:
        code=str(error) if isinstance(error,ValueError) else type(error).__name__
        result={'full_decode_passed':False,'failure_code':code,'quality_verdict':None};status=1
    args.report.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'full_decode_passed':result['full_decode_passed'],'failure_code':result.get('failure_code')}));return status

if __name__=='__main__':raise SystemExit(main())
