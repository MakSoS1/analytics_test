#!/usr/bin/env python3
"""Offline evidence for real ExamClips exports; no quality score or ASR.

Inputs: one case directory with result.json, project*.json and real exported
clips. Optional --source enables original-frame comparisons and --audio-check
adds bounded waveform comparisons. All media input is local. This helper
does not alter project, result, source media, application, or CI files.
"""
from __future__ import annotations

import argparse
import bisect
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import textwrap
import wave

SCHEMA_COMMIT = '5f14760735796fc58e330b3819944da1ab1865a3'
CAMERA_VERSIONS = set(range(2, 10))
LIMITATIONS = [
    'Decoded frames and bounded waveform comparisons are evidence for later human review, not full-video listening or a semantic quality verdict.',
    'The saved lectureCamera can differ from an unsaved camera generated during export. Camera measurements describe the saved track only unless separate export provenance establishes identity.',
    'Camera rectangle centers and inverse widths/heights are raw normalized geometry. Fit modes, text protection and the compositor can change effective displayed geometry.',
    'Numeric camera deltas and audio correlations are not universal defect thresholds and do not produce a quality percentage.',
    'Output-to-source mapping is exact for the selected saved EDL. A project/result mismatch is reported; it does not establish the renderer actually used that EDL.',
    'Source comparison frames are the first decoded frames at or after the mapped source time. Their actual timestamps are recorded; they need not be the same source frame selected by the browser.',
]


def q(value) -> Fraction:
    if isinstance(value, Fraction):
        return value
    if isinstance(value, bool) or value is None:
        raise ValueError('A finite numeric timestamp is required')
    answer = Fraction(str(value))
    return answer


def exact(value):
    return str(q(value))


def ceilq(value):
    value = q(value)
    return -(-value.numerator // value.denominator)


def finite(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def save_json(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False,
                                    default=lambda v: str(v) if isinstance(v, Fraction) else str(v)) + '\n', encoding='utf-8')


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def build_edl(clip):
    """Mirror the saved EDL ordering: never sort or deduplicate source spans."""
    pieces = clip.get('segments')
    if not isinstance(pieces, list) or not pieces:
        pieces = [{'start': clip.get('start'), 'end': clip.get('end')}]
    result, offset = [], q(0)
    for item in pieces:
        try:
            start, end = q(item['start']), q(item['end'])
        except (KeyError, TypeError, ValueError, ZeroDivisionError):
            continue
        if end <= start:
            continue
        result.append({'index': len(result), 'source_start': start, 'source_end': end,
                       'output_start': offset, 'output_end': offset + end - start})
        offset += end - start
    return result


def map_output(edl, time):
    time = q(time)
    for piece in edl:
        if piece['output_start'] <= time < piece['output_end']:
            return {'piece_index': piece['index'], 'source_time': piece['source_start'] + time - piece['output_start']}
    return None


def map_source(edl, time, include_ends=False):
    time = q(time)
    return [p['output_start'] + time - p['source_start'] for p in edl
            if p['source_start'] <= time and (time < p['source_end'] or (include_ends and time == p['source_end']))]


def edl_json(edl):
    return [{**{k: v for k, v in p.items() if k == 'index'},
             **{k + '_sec': float(v) for k, v in p.items() if k != 'index'},
             **{k + '_exact': str(v) for k, v in p.items() if k != 'index'}} for p in edl]


def valid_rect(rect):
    return (isinstance(rect, dict) and all(finite(rect.get(k)) for k in ('x', 'y', 'w', 'h'))
            and rect['w'] > 0 and rect['h'] > 0 and rect['x'] >= -1e-6 and rect['y'] >= -1e-6
            and rect['x'] + rect['w'] <= 1.001 and rect['y'] + rect['h'] <= 1.001)


def validate_camera(track):
    if not isinstance(track, dict) or track.get('version') not in CAMERA_VERSIONS or not isinstance(track.get('keys'), list):
        return False
    source = track.get('source', {})
    if not finite(source.get('width')) or not finite(source.get('height')) or min(source['width'], source['height']) <= 0:
        return False
    previous = -math.inf
    for item in track['keys']:
        if (not isinstance(item, dict) or not valid_rect(item.get('rect')) or item['rect'].get('fit') == 'reading'
                or not finite(item.get('start')) or not finite(item.get('end'))
                or item['end'] < item['start'] or item['start'] < previous):
            return False
        previous = item['start']
    if track.get('speaker') is not None and not valid_rect(track['speaker']):
        return False
    for key in ('textSegments', 'speakerSegments'):
        if key not in track:
            continue
        if not isinstance(track[key], list):
            return False
        previous_end = -math.inf
        for item in track[key]:
            if (not isinstance(item, dict) or not finite(item.get('start')) or not finite(item.get('end'))
                    or item['end'] <= item['start'] or item['start'] < previous_end):
                return False
            rect = item.get('rect') if key == 'textSegments' else item.get('box')
            if rect is not None and not valid_rect(rect):
                return False
            if key == 'textSegments':
                if not rect:
                    return False
                fit = rect.get('fit')
                if fit == 'reading':
                    regions = rect.get('regions')
                    if (rect.get('kind') not in ('board', 'cards', 'condition', 'prose') or not isinstance(regions, list)
                            or not 1 <= len(regions) <= 64 or not all(valid_rect(r) for r in regions)):
                        return False
                    if any(rect.get(k) is not None and not valid_rect(rect[k]) for k in ('context', 'footer')):
                        return False
                elif fit == 'bands':
                    if not all(finite(rect.get(k)) for k in ('top', 'bottom', 'focus')):
                        return False
                    if not (rect['top'] >= 0 and rect['bottom'] <= 1 and rect['bottom'] - rect['top'] >= .4 and 0 <= rect['focus'] <= 1):
                        return False
                elif fit != 'contain':
                    return False
            previous_end = item['end']
    return True


def camera_at(track, time):
    if not validate_camera(track) or not finite(float(time)):
        return None
    time = float(time)
    for segment in track.get('textSegments', []):
        if segment['start'] <= time < segment['end']:
            return dict(segment['rect'])
    keys = track['keys']
    if not keys:
        return None
    index = bisect.bisect_right([k['start'] for k in keys], time) - 1
    if index < 0:
        return dict(keys[0]['rect'])
    item = keys[index]
    if index == 0 or time >= item['end'] or item['end'] <= item['start']:
        return dict(item['rect'])
    a, b = keys[index - 1]['rect'], item['rect']
    portion = (time - item['start']) / (item['end'] - item['start'])
    if item.get('motion') != 'pan':
        portion = 4 * portion ** 3 if portion < .5 else 1 - (-2 * portion + 2) ** 3 / 2
    width, height = a['w'] * (b['w'] / a['w']) ** portion, a['h'] * (b['h'] / a['h']) ** portion
    cx = a['x'] + a['w'] / 2 + ((b['x'] + b['w'] / 2) - (a['x'] + a['w'] / 2)) * portion
    cy = a['y'] + a['h'] / 2 + ((b['y'] + b['h'] / 2) - (a['y'] + a['h'] / 2)) * portion
    result = {'x': cx - width / 2, 'y': cy - height / 2, 'w': width, 'h': height}
    if b.get('fit') or a.get('fit'):
        result['fit'] = b.get('fit') or a.get('fit')
    return result


def camera_metrics(rect):
    if not rect:
        return None
    return {'center_x': rect['x'] + rect['w'] / 2, 'center_y': rect['y'] + rect['h'] / 2,
            'inverse_rect_width': 1 / rect['w'], 'inverse_rect_height': 1 / rect['h'],
            'fit': rect.get('fit'), 'rect': rect}


def camera_delta(a, b):
    a, b = camera_metrics(a), camera_metrics(b)
    if not a or not b:
        return None
    return {'center_dx': b['center_x'] - a['center_x'], 'center_dy': b['center_y'] - a['center_y'],
            'inverse_width_ratio': b['inverse_rect_width'] / a['inverse_rect_width'],
            'inverse_height_ratio': b['inverse_rect_height'] / a['inverse_rect_height'],
            'fit_before': a['fit'], 'fit_after': b['fit'], 'visual_defect_verdict': None}


def camera_events(track):
    if not validate_camera(track):
        return []
    events = []
    for index, item in enumerate(track['keys']):
        positive = item['end'] > item['start']
        events.append({'source_time': q(item['start']), 'kind': 'interpolation_start' if positive else 'instant_key',
                       'key_index': index, 'declared_motion': item.get('motion'), 'mandatory': not positive})
        if positive:
            events.extend([{'source_time': q(item['end']), 'kind': 'interpolation_end', 'key_index': index, 'mandatory': False},
                           {'source_time': (q(item['start']) + q(item['end'])) / 2, 'kind': 'interpolation_midpoint', 'key_index': index, 'mandatory': False}])
    for name in ('textSegments', 'speakerSegments'):
        for index, item in enumerate(track.get(name, [])):
            for edge in ('start', 'end'):
                events.append({'source_time': q(item[edge]), 'kind': name + '_' + edge, 'segment_index': index, 'mandatory': True})
    epsilon = q('0.00001')
    for event in events:
        time = event['source_time']
        event['before_probe_source_time_exact'] = str(time - epsilon)
        event['at_probe_source_time_exact'] = str(time)
        event['sampled_raw_delta'] = camera_delta(camera_at(track, float(time - epsilon)), camera_at(track, float(time)))
    return events


def sample_plan(duration, edl, track, interval=q('12.5'), max_smooth_events=64, frame_interval=q('0.06666666666666667')):
    duration, interval = q(duration), q(interval)
    plans = {}

    def add(time, reason):
        time = q(time)
        if 0 <= time < duration:
            plans.setdefault(time, set()).add(reason)

    time = q(0)
    while time < duration:
        add(time, 'uniform_grid')
        time += interval
    add(max(q(0), duration - frame_interval), 'last_frame_neighborhood')
    around = max(frame_interval, q('.1'))
    for piece in edl:
        for edge in ('output_start', 'output_end'):
            point = piece[edge]
            for delta, label in ((-around, 'before'), (q(0), 'at'), (around, 'after')):
                add(point + delta, 'edl_piece_' + str(piece['index']) + '_' + edge + '_' + label)
    events = camera_events(track)
    relevant = [e for e in events if map_source(edl, e['source_time'], include_ends=True)]
    smooth = [e for e in relevant if not e['mandatory']]
    if len(smooth) > max_smooth_events:
        indexes = {round(i * (len(smooth) - 1) / max(1, max_smooth_events - 1)) for i in range(max_smooth_events)}
        selected_smooth = [smooth[i] for i in sorted(indexes)]
    else:
        selected_smooth = smooth
    selected = [e for e in relevant if e['mandatory']] + selected_smooth
    for event in selected:
        for point in map_source(edl, event['source_time'], include_ends=True):
            probes = ((-around, 'before'), (q(0), 'at'), (around, 'after')) if event['mandatory'] else ((q(0), 'at'),)
            for delta, label in probes:
                add(point + delta, 'camera_' + event['kind'] + '_' + label)
    return ([{'requested_output_time_exact': str(t), 'requested_output_time_sec': float(t), 'reasons': sorted(plans[t])} for t in sorted(plans)],
            {'events': events, 'relevant_event_count': len(relevant), 'mandatory_events_sampled': sum(e['mandatory'] for e in relevant),
             'optional_smooth_events_sampled': len(selected_smooth), 'optional_smooth_events_omitted': len(smooth) - len(selected_smooth),
             'selection_policy': 'All EDL boundaries and mandatory instant/text/presenter events; smooth events evenly sampled when their optional cap is exceeded.'})


def probe(path):
    command = ['ffprobe', '-v', 'error', '-protocol_whitelist', 'file,pipe', '-show_format', '-show_streams', '-of', 'json', str(path)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError('ffprobe failed: ' + result.stderr[-3000:])
    return json.loads(result.stdout)


def video_clock(data):
    video = next((s for s in data.get('streams', []) if s.get('codec_type') == 'video'), None)
    if not video:
        raise ValueError('No video stream available')
    origin = q(data.get('format', {}).get('start_time', video.get('start_time', 0)))
    return video, q(video['time_base']), origin


def parse_showinfo(log, fallback_time_base):
    match = re.search(r'config in time_base:\s*(\d+/\d+)', log)
    time_base = q(match.group(1)) if match else q(fallback_time_base)
    frames = []
    for line in log.splitlines():
        match = re.search(r'\bn:\s*(\d+)\s+pts:\s*(-?\d+)\s+pts_time:', line)
        if match:
            frames.append({'sequence': int(match.group(1)), 'pts': int(match.group(2)), 'time_base': str(time_base),
                           'raw_time_exact': str(int(match.group(2)) * time_base)})
    return frames, time_base


def decode_and_sample(path, outdir, requested_times, data=None, thumbnail_width=480):
    path, outdir = Path(path).resolve(), Path(outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    data = data or probe(path)
    video, time_base, origin = video_clock(data)
    requests = sorted({q(t) for t in requested_times})
    thresholds = sorted({ceilq((t + origin) / time_base) for t in requests})
    if not thresholds:
        thresholds = [ceilq(origin / time_base)]
    conditions = '+'.join('gte(pts,{0})*lt(prev_pts,{0})'.format(t) for t in thresholds)
    expression = 'if(isnan(prev_pts),gte(pts,{0}),{1})'.format(thresholds[0], conditions)
    filter_script = outdir / 'sampling-filter.ffscript'
    filter_script.write_text("[0:v:0]select='" + expression + "',showinfo,scale=w='min(" + str(thumbnail_width) + ",iw)':h=-2[samples]\n")
    log_path = outdir / 'full-decode.log'
    pattern = str(outdir / 'sample-%06d.jpg')
    command = ['ffmpeg', '-nostdin', '-hide_banner', '-loglevel', 'info', '-xerror', '-err_detect', 'explode',
               '-threads', '1', '-copyts', '-protocol_whitelist', 'file,pipe', '-i', str(path),
               '-filter_complex_script', str(filter_script), '-map', '0:v?', '-map', '0:a?',
               '-c:v', 'wrapped_avframe', '-c:a', 'pcm_s16le', '-f', 'null', '-',
               '-map', '[samples]', '-fps_mode', 'passthrough', '-c:v', 'mjpeg', '-threads:v', '1', '-q:v', '3', '-y', pattern]
    timed_out = False
    with log_path.open('w') as stream:
        try:
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=stream,
                                    timeout=max(180, float(data.get('format', {}).get('duration', 0)) * 3 + 120))
            code = result.returncode
        except subprocess.TimeoutExpired:
            code, timed_out = None, True
    log = log_path.read_text(errors='replace')
    frames, actual_base = parse_showinfo(log, time_base)
    available = []
    for frame in frames:
        image = outdir / ('sample-%06d.jpg' % (frame['sequence'] + 1))
        if not image.exists():
            continue
        frame['image_file'] = image.name
        frame['output_time_exact'] = str(q(frame['raw_time_exact']) - origin)
        frame['output_time_sec'] = float(q(frame['output_time_exact']))
        available.append(frame)
    records = []
    for time in requests:
        threshold = ceilq((time + origin) / time_base)
        found = next((f for f in available if q(f['raw_time_exact']) >= q(threshold) * time_base), None)
        record = {'requested_output_time_exact': str(time), 'requested_output_time_sec': float(time), 'requested_pts_threshold': threshold}
        if found:
            record.update(actual_output_time_exact=found['output_time_exact'], actual_output_time_sec=found['output_time_sec'],
                          actual_raw_pts=found['pts'], actual_time_base=found['time_base'], image_file=found['image_file'])
        else:
            record['sample_status'] = 'no_decoded_frame_at_or_after_request'
        records.append(record)
    return {'probe': data, 'clock_origin_sec': float(origin), 'clock_origin_exact': str(origin),
            'input_video_time_base': str(time_base), 'observed_filter_time_base': str(actual_base),
            'time_base_mismatch': actual_base != time_base,
            'full_decode': {'ok': code == 0 and not timed_out, 'returncode': code, 'timed_out': timed_out,
                            'scope': 'All video and audio streams decoded to null; sample selection is a separate output of the same full pass.',
                            'command': command, 'log_file': log_path.name,
                            'failure_tail': log[-6000:] if code != 0 or timed_out else None},
            'frames': available, 'requests': records}


def source_frame(path, outdir, source_time, data):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    video, time_base, origin = video_clock(data)
    source_time = q(source_time)
    token = hashlib.sha256(str(source_time).encode()).hexdigest()[:16]
    filename, record_file = outdir / ('source-' + token + '.jpg'), outdir / ('source-' + token + '.json')
    if filename.exists() and record_file.exists():
        return read_json(record_file)
    threshold = ceilq((source_time + origin) / time_base)
    expression = "select='gte(pts," + str(threshold) + ")',showinfo,scale=w='min(640,iw)':h=-2"
    command = ['ffmpeg', '-nostdin', '-hide_banner', '-loglevel', 'info', '-threads', '1', '-copyts',
               '-ss', '%.9f' % float(max(q(0), source_time - 1)), '-protocol_whitelist', 'file,pipe', '-i', str(path),
               '-map', '0:v:0', '-an', '-sn', '-dn', '-vf', expression, '-frames:v', '1', '-threads:v', '1', '-q:v', '3', '-y', str(filename)]
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=90)
    frames, actual_base = parse_showinfo(result.stderr, time_base)
    record = {'requested_source_time_sec': float(source_time), 'requested_source_time_exact': str(source_time),
              'source_clock_origin_exact': str(origin), 'returncode': result.returncode,
              'image_file': filename.name if filename.exists() else None,
              'selection': 'First frame at or after requested timestamp, using integer PTS threshold.'}
    if result.returncode == 0 and frames and filename.exists():
        frame = frames[0]
        record.update(actual_source_raw_pts=frame['pts'], actual_source_time_base=str(actual_base),
                      actual_source_time_exact=str(q(frame['raw_time_exact']) - origin),
                      actual_source_time_sec=float(q(frame['raw_time_exact']) - origin))
    else:
        record['error'] = result.stderr[-2000:]
    save_json(record_file, record)
    return record


def correlate_audio(output, reference, reference_start, expected_source_start, sample_rate):
    import numpy as np
    x, y = np.asarray(output, dtype=np.float64), np.asarray(reference, dtype=np.float64)
    record = {'output_samples': len(x), 'reference_samples': len(y), 'sample_rate': sample_rate,
              'output_rms': float(np.sqrt(np.mean(x*x))) if len(x) else None,
              'reference_rms': float(np.sqrt(np.mean(y*y))) if len(y) else None,
              'best_offset_sec': None, 'best_correlation': None,
              'offset_sign': 'Positive means the exported waveform best matches a later original-source position than the EDL predicts.',
              'interpretation': 'Raw waveform evidence only. Weak, silent, repetitive or music windows are inconclusive; this is not an A/V-sync verdict.'}
    if len(x) < 64 or len(y) < len(x):
        return {**record, 'status': 'inconclusive_short_window'}
    x = x - x.mean()
    energy = float(np.dot(x, x))
    if energy < 1e-16:
        return {**record, 'status': 'inconclusive_constant_or_silent_audio'}
    nfft = 1 << (len(x) + len(y) - 2).bit_length()
    numerator = np.fft.irfft(np.fft.rfft(y, nfft) * np.fft.rfft(x[::-1], nfft), nfft)[len(x)-1:len(y)]
    cumulative, cumulative2 = np.r_[0., np.cumsum(y)], np.r_[0., np.cumsum(y*y)]
    sums = cumulative[len(x):] - cumulative[:-len(x)]
    variances = cumulative2[len(x):] - cumulative2[:-len(x)] - sums*sums/len(x)
    denominators = np.sqrt(np.maximum(variances, 0) * energy)
    valid = denominators > 1e-16
    if not np.any(valid):
        return {**record, 'status': 'inconclusive_constant_or_silent_audio'}
    scores = np.zeros_like(numerator)
    scores[valid] = numerator[valid] / denominators[valid]
    index = int(np.argmax(np.abs(scores)))
    nominal = round((float(expected_source_start) - float(reference_start)) * sample_rate)
    alternatives = np.abs(scores).copy()
    exclusion = max(1, round(.02 * sample_rate))
    alternatives[max(0, index-exclusion):index+exclusion+1] = -1
    alternate_index = int(np.argmax(alternatives)) if np.any(alternatives >= 0) else None
    record.update(status='raw_measurement', best_offset_sec=float(reference_start) + index/sample_rate - float(expected_source_start),
                  best_correlation=float(scores[index]), best_reference_start_sec=float(reference_start) + index/sample_rate,
                  nominal_correlation=float(scores[nominal]) if 0 <= nominal < len(scores) else None,
                  alternative_peak_correlation=float(scores[alternate_index]) if alternate_index is not None else None,
                  alternative_peak_offset_sec=float(reference_start) + alternate_index/sample_rate - float(expected_source_start) if alternate_index is not None else None)
    return record


def pcm_window(path, start, length, sample_rate=16000):
    import numpy as np
    command = ['ffmpeg', '-nostdin', '-v', 'error', '-threads', '1', '-ss', '%.9f' % float(start),
               '-protocol_whitelist', 'file,pipe', '-i', str(path), '-t', '%.9f' % float(length),
               '-map', '0:a:0', '-vn', '-ac', '1', '-ar', str(sample_rate), '-f', 'f32le', '-']
    result = subprocess.run(command, capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors='replace')[-2000:])
    return np.frombuffer(result.stdout, dtype='<f4').copy()


def write_wav(path, pcm, sample_rate=16000):
    import numpy as np
    values = (np.clip(pcm, -1, 1) * 32767).astype('<i2')
    with wave.open(str(path), 'wb') as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(sample_rate)
        output.writeframes(values.tobytes())


def audio_evidence(export_path, source_path, edl, source_duration, outdir):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    if not edl:
        return {'status': 'no_edl', 'windows': []}
    total = edl[-1]['output_end']
    windows, seen = [], set()
    for name, fraction in [('early', q('.1')), ('middle', q('.5')), ('late', q('.9'))]:
        center = total * fraction
        mapping = map_output(edl, center)
        if not mapping:
            continue
        piece = edl[mapping['piece_index']]
        length = min(q(3), piece['output_end'] - piece['output_start'])
        if length < q('.2'):
            continue
        start = max(piece['output_start'], min(center-length/2, piece['output_end']-length))
        if (start, length) in seen:
            continue
        seen.add((start, length))
        source_start = map_output(edl, start)['source_time']
        ref_start = max(q(0), source_start-1)
        ref_end = min(q(source_duration), source_start+length+1)
        record = {'name': name, 'piece_index': piece['index'], 'output_start_exact': str(start), 'output_start_sec': float(start),
                  'window_duration_sec': float(length), 'mapped_source_start_exact': str(source_start), 'mapped_source_start_sec': float(source_start),
                  'reference_start_sec': float(ref_start), 'reference_end_sec': float(ref_end), 'requested_search_radius_sec': 1,
                  'distance_to_output_cut_before_sec': float(start-piece['output_start']),
                  'distance_to_output_cut_after_sec': float(piece['output_end']-(start+length))}
        try:
            a = pcm_window(export_path, start, length)
            b = pcm_window(source_path, ref_start, ref_end-ref_start)
            record['measurement'] = correlate_audio(a, b, ref_start, source_start, 16000)
            write_wav(outdir/(name+'-export.wav'), a)
            write_wav(outdir/(name+'-source-search-window.wav'), b)
            record['output_audio_file'] = name+'-export.wav'
            record['source_audio_file'] = name+'-source-search-window.wav'
        except Exception as exc:
            record.update(status='extraction_error', error=repr(exc))
        windows.append(record)
    return {'status': 'bounded_audio_samples', 'windows': windows, 'full_video_listened': False,
            'audio_video_sync_verdict': None, 'method': 'Mono 16 kHz PCM, normalized FFT cross-correlation; no ASR, no universal pass threshold.'}


def contact_sheets(samples, clipdir, title):
    from PIL import Image, ImageDraw, ImageFont, ImageOps
    clipdir = Path(clipdir)
    font_path = Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf')
    font = ImageFont.truetype(str(font_path), 16) if font_path.exists() else ImageFont.load_default()
    small = ImageFont.truetype(str(font_path), 13) if font_path.exists() else font
    unique, seen = [], set()
    for sample in samples:
        image_file = sample.get('image_file')
        if not image_file or image_file in seen:
            continue
        seen.add(image_file)
        unique.append(sample)
    pages = []
    cell_width, cell_height, columns, per_page = 680, 350, 2, 8
    for page_no in range(math.ceil(len(unique) / per_page)):
        page_samples = unique[page_no*per_page:(page_no+1)*per_page]
        rows = math.ceil(len(page_samples) / columns)
        sheet = Image.new('RGB', (cell_width*columns, 55+cell_height*rows), '#10151c')
        draw = ImageDraw.Draw(sheet)
        draw.text((15, 12), f'{title} | actual decoded timestamps | page {page_no+1}', fill='white', font=font)
        for position, sample in enumerate(page_samples):
            x, y = (position % columns)*cell_width, 55+(position//columns)*cell_height
            draw.rectangle((x+5, y+3, x+cell_width-5, y+cell_height-4), outline='#4b5563', width=1)
            actual = sample.get('actual_output_time_sec')
            draw.text((x+12, y+8), f'Export {actual:.6f} s' if actual is not None else 'Export timestamp unavailable', fill='white', font=font)
            source = sample.get('source_frame') or {}
            mapped = sample.get('mapped_source_time_sec')
            source_label = f'Source target {mapped:.6f} s' if mapped is not None else 'Source mapping unavailable'
            draw.text((x+250, y+8), source_label, fill='white', font=font)
            slots = [(sample.get('image_file'), (x+12, y+34, 220, 265)),
                     (source.get('image_file'), (x+250, y+34, 416, 265))]
            for image_file, (sx, sy, sw, sh) in slots:
                if not image_file or not (clipdir/image_file).is_file():
                    draw.text((sx+4, sy+25), 'No image', fill='#9ca3af', font=small)
                    continue
                with Image.open(clipdir/image_file) as opened:
                    thumbnail = ImageOps.contain(opened.convert('RGB'), (sw, sh))
                    sheet.paste(thumbnail, (sx+(sw-thumbnail.width)//2, sy+(sh-thumbnail.height)//2))
            if source.get('actual_source_time_sec') is not None:
                draw.text((x+250, y+302), f"Actual source {source['actual_source_time_sec']:.6f} s", fill='#d1d5db', font=small)
            why = ', '.join(sample.get('reasons', []))
            draw.text((x+12, y+324), textwrap.shorten(why, width=92, placeholder='...'), fill='#a7c7e7', font=small)
        name = f'contact-sheet-{page_no+1:03d}.jpg'
        sheet.save(clipdir/name, quality=88)
        pages.append({'file': name, 'samples': [{'actual_output_time_exact': s.get('actual_output_time_exact'),
                                                'image_file': s.get('image_file'), 'mapped_source_time_exact': s.get('mapped_source_time_exact')}
                                               for s in page_samples]})
    return pages


def project_snapshot(raw):
    if isinstance(raw, dict) and isinstance(raw.get('snapshot'), dict):
        return raw['snapshot']
    return raw if isinstance(raw, dict) else {}


def project_clip(project, row, filename):
    clips = project.get('clips', [])
    if not isinstance(clips, list):
        return None, 'no_project_clip_array'
    if row.get('id') is not None:
        matches = [c for c in clips if c.get('id') == row['id']]
        if len(matches) == 1:
            return matches[0], 'unique_clip_id'
    index = row.get('index')
    if isinstance(index, int) and 0 <= index < len(clips):
        return clips[index], 'result_zero_based_index'
    match = re.fullmatch(r'clip-(\d+)\.mp4', filename)
    if match:
        index = int(match.group(1))-1
        if 0 <= index < len(clips):
            return clips[index], 'filename_index_fallback_unconfirmed'
    return None, 'not_bound_to_project'


def inspect_case(case_dir, source_path=None, interval=12.5, audio_check=False, outdir=None):
    case_dir = Path(case_dir).resolve()
    if not case_dir.is_dir():
        raise ValueError('Case directory does not exist: ' + str(case_dir))
    outdir = Path(outdir).resolve() if outdir else case_dir/'diagnostics'
    outdir.mkdir(parents=True, exist_ok=True)
    result_path = case_dir/'result.json'
    result = read_json(result_path) if result_path.is_file() else {}
    projects = []
    for filename in ('project-final.json', 'project.json', 'project-partial.json'):
        path = case_dir/filename
        if path.is_file():
            projects.append({'file': filename, 'data': project_snapshot(read_json(path)), 'sha256': digest(path)})
    project = projects[0]['data'] if projects else {}
    track = project.get('lectureCamera')
    valid_track = validate_camera(track)
    if source_path is None and (case_dir/'original-source.mp4').is_file():
        source_path = case_dir/'original-source.mp4'
    source_path = Path(source_path).resolve() if source_path else None
    source_data, source_record = None, {'status': 'not_supplied'}
    if source_path:
        if not source_path.is_file():
            raise ValueError('Original source file does not exist: ' + str(source_path))
        source_data = probe(source_path)
        source_digest = digest(source_path)
        expected_digest = result.get('source', {}).get('sha256')
        source_record = {'status': 'available', 'path': str(source_path), 'sha256': source_digest, 'probe': source_data,
                         'matches_result_source_sha256': source_digest == expected_digest if expected_digest else None,
                         'expected_sha256': expected_digest,
                         'scope': 'Metadata and selected frames/audio windows only; the entire original was not decoded by this helper.'}
    rows = result.get('clips', []) if isinstance(result.get('clips'), list) else []
    files = sorted(case_dir.glob('clip-*.mp4'))
    by_name = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get('file')
        if name and Path(name).name == name:
            by_name.setdefault(name, []).append(row)
    missing = [{'index': r.get('index'), 'id': r.get('id'), 'file': r.get('file'), 'exportStatus': r.get('exportStatus')}
               for r in rows if isinstance(r, dict) and r.get('exportStatus') == 'downloaded'
               and (not r.get('file') or Path(r['file']).name != r['file'] or not (case_dir/r['file']).is_file())]
    unexported = [{'index': r.get('index'), 'id': r.get('id'), 'title': r.get('title'),
                  'exportStatus': r.get('exportStatus'), 'exportReason': r.get('exportReason')}
                 for r in rows if isinstance(r, dict) and r.get('exportStatus') != 'downloaded']
    summary = {'schema_version': 2, 'generated_utc': datetime.now(timezone.utc).isoformat(),
               'case_directory': str(case_dir), 'application_schema_commit': SCHEMA_COMMIT,
               'helper_sha256': digest(__file__), 'python_version': sys.version,
               'result_file': str(result_path) if result_path.is_file() else None,
               'project_files': [{k:v for k,v in p.items() if k != 'data'} for p in projects],
               'source': source_record, 'sampling_interval_sec': interval,
               'missing_claimed_downloads': missing, 'not_exported_rows': unexported,
               'limitations': LIMITATIONS, 'clips': [], 'quality_score': None}
    for path in files:
        clipdir = outdir/path.stem
        clipdir.mkdir(parents=True, exist_ok=True)
        bound_rows = by_name.get(path.name, [])
        row = bound_rows[0] if len(bound_rows) == 1 else {}
        clip, binding = project_clip(project, row, path.name)
        primary_edl = build_edl(row) or build_edl(clip or {})
        primary_origin = 'result.clips row' if build_edl(row) else ('preferred project clip' if clip else 'unavailable')
        alternatives = []
        for p in projects:
            other, how = project_clip(p['data'], row, path.name)
            if other is not None:
                alternatives.append({'project_file': p['file'], 'binding': how, 'edl': edl_json(build_edl(other)),
                                     'matches_selected_edl': build_edl(other) == primary_edl})
        report = {'schema_version': 2, 'file': str(path), 'bytes': path.stat().st_size, 'sha256': digest(path),
                  'title': row.get('title') or (clip or {}).get('title'), 'result_row': row or None,
                  'binding': {'result_rows_with_same_filename': len(bound_rows), 'project_binding': binding},
                  'selected_edl_provenance': primary_origin, 'edl': edl_json(primary_edl),
                  'edl_duration_sec': float(primary_edl[-1]['output_end']) if primary_edl else None,
                  'edl_alternatives': alternatives, 'edl_mismatch': any(not a['matches_selected_edl'] for a in alternatives),
                  'saved_camera': {'status': 'supported_saved_track' if valid_track else ('absent' if track is None else 'unsupported_or_invalid_track'),
                                   'project_file': projects[0]['file'] if projects else None,
                                   'version': track.get('version') if isinstance(track, dict) else None,
                                   'confirmed_renderer_track': False}, 'limitations': LIMITATIONS, 'samples': []}
        try:
            data = probe(path)
            video, _, _ = video_clock(data)
            duration = q(data['format']['duration'])
            frame_rate = q(video.get('avg_frame_rate', '0/1'))
            frame_interval = 1/frame_rate if frame_rate > 0 else q('0.06666666666666667')
            plans, events = sample_plan(duration, primary_edl, track, q(interval), frame_interval=frame_interval)
            decoded = decode_and_sample(path, clipdir/'frames', [q(p['requested_output_time_exact']) for p in plans], data)
            report.update(probe=data, output_clock_origin_exact=decoded['clock_origin_exact'],
                          full_decode=decoded['full_decode'], frame_clock={'input_time_base': decoded['input_video_time_base'],
                                                                       'observed_time_base': decoded['observed_filter_time_base'],
                                                                       'mismatch': decoded['time_base_mismatch']})
            report['full_decode']['log_file'] = 'frames/' + report['full_decode']['log_file']
            report['saved_camera']['event_measurements'] = events
            plan_by_time = {p['requested_output_time_exact']: p for p in plans}
            for sample in decoded['requests']:
                sample['reasons'] = plan_by_time[sample['requested_output_time_exact']]['reasons']
                if sample.get('image_file'):
                    sample['image_file'] = 'frames/' + sample['image_file']
                requested_mapping = map_output(primary_edl, q(sample['requested_output_time_exact']))
                if requested_mapping:
                    sample['requested_mapped_source_time_exact'] = str(requested_mapping['source_time'])
                actual = sample.get('actual_output_time_exact')
                mapping = map_output(primary_edl, q(actual)) if actual is not None else None
                if mapping:
                    sample.update(piece_index=mapping['piece_index'], mapped_source_time_exact=str(mapping['source_time']),
                                  mapped_source_time_sec=float(mapping['source_time']))
                    if valid_track:
                        sample['saved_camera_raw'] = camera_metrics(camera_at(track, float(mapping['source_time'])))
                    if source_data:
                        original = source_frame(source_path, outdir/'source-frames', mapping['source_time'], source_data)
                        if original.get('image_file'):
                            original = {**original, 'image_file': '../source-frames/' + original['image_file']}
                        sample['source_frame'] = original
                report['samples'].append(sample)
            cut_measurements = []
            for before, after in zip(primary_edl, primary_edl[1:]):
                epsilon = min(q('0.00001'), (before['source_end']-before['source_start'])/2)
                cut_measurements.append({'output_time_exact': str(after['output_start']),
                                         'source_before_probe_exact': str(before['source_end']-epsilon),
                                         'source_after_exact': str(after['source_start']),
                                         'raw_camera_delta': camera_delta(camera_at(track, float(before['source_end']-epsilon)),
                                                                          camera_at(track, float(after['source_start']))) if valid_track else None,
                                         'classification': 'EDL cut, not continuous camera movement'})
            report['edl_cut_measurements'] = cut_measurements
            report['contact_sheets'] = contact_sheets(report['samples'], clipdir, path.name)
            if audio_check and source_data:
                has_audio = lambda item: any(s.get('codec_type') == 'audio' for s in item.get('streams', []))
                if has_audio(data) and has_audio(source_data):
                    report['audio_comparison'] = audio_evidence(path, source_path, primary_edl, source_data['format']['duration'], clipdir/'audio')
                    for window in report['audio_comparison']['windows']:
                        for field in ('output_audio_file', 'source_audio_file'):
                            if window.get(field):
                                window[field] = 'audio/' + window[field]
                else:
                    report['audio_comparison'] = {'status': 'missing_audio_stream', 'full_video_listened': False}
            else:
                report['audio_comparison'] = {'status': 'not_requested' if not audio_check else 'source_not_supplied', 'full_video_listened': False}
        except Exception as exc:
            report['diagnostic_error'] = repr(exc)
        save_json(clipdir/'diagnostics.json', report)
        summary['clips'].append({'file': path.name, 'diagnostics_file': path.stem+'/diagnostics.json',
                                 'full_decode_ok': report.get('full_decode', {}).get('ok'),
                                 'diagnostic_error': report.get('diagnostic_error'),
                                 'sample_requests': len(report['samples']),
                                 'distinct_output_frames': len({s.get('image_file') for s in report['samples'] if s.get('image_file')}),
                                 'contact_sheet_files': [path.stem+'/'+s['file'] for s in report.get('contact_sheets', [])],
                                 'edl_mismatch': report['edl_mismatch']})
        print(json.dumps({'file': path.name, 'decoded': summary['clips'][-1]['full_decode_ok'],
                          'samples': len(report['samples']), 'diagnostic_error': report.get('diagnostic_error')}, ensure_ascii=False), flush=True)
    summary['status'] = 'inspected_actual_exports' if files else 'no_actual_export_files'
    summary['all_downloaded_files_decoded'] = bool(files) and all(c['full_decode_ok'] is True for c in summary['clips']) and not missing
    save_json(outdir/'diagnostics.json', summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('case_dir', type=Path, help='Case directory containing actual exported MP4s and saved project/result JSON.')
    parser.add_argument('--source', type=Path, help='Complete local original. If omitted, CASE/original-source.mp4 is used when present.')
    parser.add_argument('--interval', type=float, default=12.5, help='Uniform output sample spacing in seconds; allowed range 10–15, default 12.5.')
    parser.add_argument('--audio-check', action='store_true', help='Compare bounded early/middle/late audio windows with exact EDL source positions.')
    parser.add_argument('--outdir', type=Path, help='Evidence output directory; default CASE/diagnostics.')
    args = parser.parse_args()
    if not 10 <= args.interval <= 15:
        parser.error('--interval must be between 10 and 15 seconds')
    try:
        summary = inspect_case(args.case_dir, args.source, args.interval, args.audio_check, args.outdir)
    except Exception as exc:
        print('Diagnostic input failure: ' + repr(exc), file=sys.stderr)
        return 2
    failed = summary['missing_claimed_downloads'] or any(c['full_decode_ok'] is not True or c['diagnostic_error'] for c in summary['clips'])
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
