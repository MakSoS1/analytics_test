#!/usr/bin/env python3
"""Bounded review of actual exports, with exact saved EDL and decoded frame timestamps.

This never interprets a camera-track schema. It fully decodes each exported MP4 once,
then takes a bounded number of short frame seeks for source comparisons and scene peaks.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('retest_diagnostics', HERE/'diagnostics'/'audit_diagnostics.py')
diag = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(diag)
q = diag.q

LIMITATIONS = [
    'Full video and audio decode is a technical integrity check, not a visual, pedagogical or semantic quality verdict.',
    'No saved camera coordinates or camera-track version are interpreted; only actual decoded output frames are compared.',
    'The selected pre-export clip-ID EDL is the strongest available saved provenance, not instrumentation of the renderer.',
    'Output samples and source comparisons use their actual decoded PTS. The source comparison is the first frame at or after the mapped source time.',
    'Semantic-range coverage measures retained source seconds only; it cannot establish whether an explanation remains understandable.',
    'Uniform frames, target neighborhoods, EDL-cut neighborhoods and three ranked scene peaks are bounded samples, not continuous full-video viewing.',
    'Scene scores only prioritize review; source cuts, subtitles, compression and app motion can all contribute.',
]


def now():
    return datetime.now(timezone.utc).isoformat()


def choose_edl(case_dir, filename, rows):
    """Bind by unique recorded clip ID; never infer a different clip from array position."""
    case_dir = Path(case_dir)
    bound = [row for row in rows if isinstance(row, dict) and row.get('file') == filename]
    binding = 'unique_result_filename'
    if not bound:
        match = re.fullmatch(r'clip-(\d+)\.mp4', filename)
        index = int(match.group(1))-1 if match else None
        bound = [row for row in rows if isinstance(row, dict) and row.get('index') == index] if index is not None else []
        binding = 'unique_result_index_for_partial_export'
    row = bound[0] if len(bound) == 1 else {}
    clip_id = row.get('id')
    stem = Path(filename).stem
    candidates = []
    names = [stem+'-project-before-export.json', 'project.json', 'project-final.json', 'project-partial.json']
    for name in names:
        path = case_dir/name
        if not path.is_file() or clip_id is None:
            continue
        project = diag.project_snapshot(diag.read_json(path))
        matches = [clip for clip in project.get('clips', []) if isinstance(clip, dict) and str(clip.get('id')) == str(clip_id)]
        if len(matches) == 1:
            candidates.append({'file': name, 'sha256': diag.digest(path), 'binding': 'unique_clip_id',
                               'clip_id': str(clip_id), 'title': matches[0].get('title'), 'edl': diag.build_edl(matches[0])})
    if row:
        candidates.append({'file': 'result.json', 'binding': binding, 'clip_id': str(clip_id) if clip_id is not None else None,
                           'title': row.get('title'), 'edl': diag.build_edl(row)})
    priority = {names[0]: 0, 'result.json': 1, 'project.json': 2, 'project-final.json': 3, 'project-partial.json': 4}
    viable = sorted((item for item in candidates if item['edl']), key=lambda item: priority[item['file']])
    selected = viable[0] if viable else None
    edl = selected['edl'] if selected else []
    return {'edl': edl, 'result_row': row or None, 'result_row_matches': len(bound),
            'selected_provenance': {k:v for k,v in selected.items() if k != 'edl'} if selected else {'binding': 'unavailable'},
            'alternatives': [{**{k:v for k,v in item.items() if k != 'edl'}, 'edl': diag.edl_json(item['edl']),
                              'matches_selected_edl': item['edl'] == edl} for item in candidates],
            'edl_mismatch': any(item['edl'] != edl for item in candidates)}


def evenly_selected(items, limit):
    if len(items) <= limit:
        return list(items)
    if limit <= 0:
        return []
    if limit == 1:
        return [items[len(items)//2]]
    return [items[round(i*(len(items)-1)/(limit-1))] for i in range(limit)]


def sample_priority(reasons):
    if any(reason.startswith('target:') for reason in reasons):
        return 0
    if any(reason in ('first', 'middle', 'last') for reason in reasons):
        return 1
    if any(reason.startswith('scene_peak:') for reason in reasons):
        return 2
    if any(reason.startswith('edl_cut:') for reason in reasons):
        return 3
    return 4


def plan_samples(duration, edl, visual_points, max_boundaries=30, frame_interval=q('0.06666666666666667')):
    duration = q(duration)
    if duration <= 0:
        raise ValueError('Positive output duration is required')
    last = max(q(0), duration-min(q(frame_interval), duration/2))
    requests = {}
    def add(at, reason):
        at = q(at)
        if 0 <= at < duration:
            requests.setdefault(at, set()).add(reason)
    add(0, 'first')
    add(duration/2, 'middle')
    add(last, 'last')
    for second in range(60, math.ceil(float(duration)), 60):
        add(second, 'uniform_60s')
    targets = []
    for position, point in enumerate(visual_points):
        entry = {'id': str(point.get('id', position)), 'reason': point.get('reason'), 'source_seconds': point.get('source_seconds')}
        try:
            mapped = diag.map_source(edl, q(point['source_seconds']))
            entry.update(status='present_in_edl' if mapped else 'absent_from_edl',
                         mapped_output_times_sec=[float(at) for at in mapped], mapped_output_times_exact=[str(at) for at in mapped])
            for at in mapped:
                for label, delta in [('before', q('-0.07')), ('center', q(0)), ('after', q('0.07'))]:
                    add(at+delta, 'target:'+entry['id']+':'+label)
        except (KeyError, TypeError, ValueError, ZeroDivisionError):
            entry.update(status='invalid_target', mapped_output_times_sec=[], mapped_output_times_exact=[])
        targets.append(entry)
    cuts = [{'piece_index': after['index'], 'output_time_exact': str(after['output_start']),
             'source_before_end_exact': str(before['source_end']), 'source_after_start_exact': str(after['source_start'])}
            for before, after in zip(edl, edl[1:])]
    chosen = evenly_selected(cuts, max_boundaries)
    for cut in chosen:
        for label, delta in [('before', q('-0.07')), ('center', q(0)), ('after', q('0.07'))]:
            add(q(cut['output_time_exact'])+delta, 'edl_cut:'+str(cut['piece_index'])+':'+label)
    items = [{'requested_output_time_exact': str(at), 'requested_output_time_sec': float(at), 'reasons': sorted(reasons)}
             for at, reasons in sorted(requests.items())]
    omitted = []
    if len(items) > 512:
        ranked = sorted(items, key=lambda item: (sample_priority(item['reasons']), q(item['requested_output_time_exact'])))
        omitted, items = ranked[512:], sorted(ranked[:512], key=lambda item:q(item['requested_output_time_exact']))
    return {'requests': items, 'targets': targets, 'boundary_selection': {'total': len(cuts), 'selected': len(chosen),
            'omitted': len(cuts)-len(chosen), 'maximum': max_boundaries, 'policy': 'Evenly distributed cuts in exact saved EDL order',
            'cuts': chosen}, 'request_limit': {'maximum': 512, 'omitted': len(omitted), 'omitted_requests': omitted},
            'neighborhood_offset_seconds': 0.07, 'uniform_interval_seconds': 60}


def semantic_coverage(edl, ranges):
    report = []
    for position, row in enumerate(ranges):
        entry = {'id': str(row.get('id', position)), 'reason': row.get('reason'), 'start': row.get('start'),
                 'end': row.get('end'), 'semantic_verdict': None}
        try:
            start, end = q(row['start']), q(row['end'])
            if end <= start:
                raise ValueError('Invalid range')
            intersections = []
            for piece in edl:
                left, right = max(start, piece['source_start']), min(end, piece['source_end'])
                if right > left:
                    intersections.append({'piece_index': piece['index'], 'source_start_exact': str(left), 'source_end_exact': str(right),
                       'output_start_exact': str(piece['output_start']+left-piece['source_start']),
                       'output_end_exact': str(piece['output_start']+right-piece['source_start'])})
            spans = sorted((q(item['source_start_exact']), q(item['source_end_exact'])) for item in intersections)
            merged = []
            for left, right in spans:
                if merged and left <= merged[-1][1]:
                    merged[-1] = (merged[-1][0], max(merged[-1][1], right))
                else:
                    merged.append((left, right))
            unique = sum((right-left for left,right in merged), q(0))
            occurrences = sum((right-left for left,right in spans), q(0))
            entry.update(status='absent_from_edl' if unique == 0 else 'fully_covered' if unique == end-start else 'partially_covered',
                         covered_unique_source_seconds=float(unique), covered_output_seconds=float(occurrences),
                         source_coverage_fraction=float(unique/(end-start)), intersections=intersections)
        except (KeyError, TypeError, ValueError, ZeroDivisionError):
            entry['status'] = 'invalid_range'
        report.append(entry)
    return report


def source_context(case_dir):
    source = Path(case_dir)/'original-source.mp4'
    if not source.is_file():
        return {'status': 'not_retained', 'scope': 'No source-frame comparison possible'}
    result = diag.read_json(Path(case_dir)/'result.json') if (Path(case_dir)/'result.json').is_file() else {}
    fingerprint = diag.digest(source)
    expected = result.get('source', {}).get('sha256')
    return {'status': 'available', 'path': str(source.resolve()), 'sha256': fingerprint, 'bytes': source.stat().st_size,
            'mtime_ns': source.stat().st_mtime_ns, 'probe': diag.probe(source), 'expected_sha256': expected,
            'matches_result_sha256': fingerprint == expected if expected else None,
            'scope': 'Full-file SHA256 and selected decoded frames; no full decode of the entire original'}


def actual_sample(sample, edl):
    actual = sample.get('actual_output_time_exact')
    mapping = diag.map_output(edl, q(actual)) if actual is not None else None
    if mapping:
        sample.update(mapping_status='mapped_actual_output_pts', piece_index=mapping['piece_index'],
                      mapped_source_time_exact=str(mapping['source_time']), mapped_source_time_sec=float(mapping['source_time']))
    else:
        sample['mapping_status'] = 'actual_output_time_outside_saved_edl' if actual is not None else 'output_frame_not_captured'
    return sample


def scene_neighbors(path, clip_dir, decoded, data, edl):
    """Capture actual adjacent output PTS around three ranked peaks via bounded seeks."""
    peaks = decoded['scene_screening'].get('candidates', [])[:3]
    wanted = {peak['frame_index']+delta for peak in peaks for delta in (-1,0,1) if peak['frame_index']+delta >= 0}
    records = {}
    scores = clip_dir/'frames'/decoded['scene_screening']['all_frame_scores_file']
    if scores.is_file():
        with scores.open() as stream:
            for line in stream:
                row = json.loads(line)
                if row['frame_index'] in wanted:
                    records[row['frame_index']] = row
    samples, errors = [], []
    for peak in peaks:
        rank = peak['review_priority_rank']
        for label, delta in [('before',-1),('center',0),('after',1)]:
            record = records.get(peak['frame_index']+delta)
            if record is None:
                continue
            try:
                frame = diag.source_frame(path, clip_dir/'scene-peaks', q(record['output_time_exact']), data)
                sample = {'requested_output_time_exact': record['output_time_exact'], 'requested_output_time_sec': record['output_time_sec'],
                          'reasons': ['scene_peak:'+str(rank)+':'+label], 'scene_frame_index': record['frame_index'],
                          'capture_kind': 'bounded_seek_to_adjacent_actual_output_pts'}
                if frame.get('image_file'):
                    sample.update(image_file='scene-peaks/'+frame['image_file'], actual_output_time_exact=frame['actual_source_time_exact'],
                                  actual_output_time_sec=frame['actual_source_time_sec'], actual_raw_pts=frame['actual_source_raw_pts'],
                                  actual_time_base=frame['actual_source_time_base'])
                else:
                    sample['sample_status'] = 'bounded_scene_frame_capture_failed'
                samples.append(actual_sample(sample, edl))
            except Exception as error:
                errors.append({'peak_rank':rank,'neighbor':label,'error':str(error)[:2000]})
    return samples, {'selected_peaks': peaks, 'bounded_output_frame_seeks': len(samples)+len(errors), 'errors': errors,
                     'quality_verdict': None, 'policy': 'First three peaks in descending diagnostic review-priority rank; previous/current/next actual decoded output frame'}


def review_clip(case_dir, path, outdir, targets, max_source_pairs=50, prepared_source=None):
    case_dir, path, outdir = Path(case_dir).resolve(), Path(path).resolve(), Path(outdir).resolve()
    clip_dir = outdir/path.stem
    clip_dir.mkdir(parents=True, exist_ok=True)
    result = diag.read_json(case_dir/'result.json') if (case_dir/'result.json').is_file() else {}
    choice = choose_edl(case_dir, path.name, result.get('clips', []))
    edl = choice.pop('edl')
    source = prepared_source or source_context(case_dir)
    if source.get('status') == 'available':
        current = Path(source['path']).stat()
        if current.st_size != source['bytes'] or current.st_mtime_ns != source['mtime_ns']:
            raise ValueError('Source file changed after its SHA256 was recorded')
    report = {'schema': 1, 'generated_at': now(), 'clip': path.name, 'clip_sha256': diag.digest(path), 'clip_bytes': path.stat().st_size,
              'source': source, 'edl': diag.edl_json(edl), **choice, 'full_av_decode_passes': 0,
              'camera_track_interpretation': 'not_performed', 'quality_verdict': None, 'limitations': LIMITATIONS,
              'stage': 'before_full_decode', 'samples': []}
    save = lambda: diag.save_json(clip_dir/'review.json', report)
    save()
    data = diag.probe(path)
    video, _, _ = diag.video_clock(data)
    duration = q(data['format']['duration'])
    rate = q(video.get('avg_frame_rate', '0/1'))
    frame_interval = 1/rate if rate > 0 else q('0.06666666666666667')
    plan = plan_samples(duration, edl, targets.get('visual_points', []), frame_interval=frame_interval)
    report.update(visual_targets=plan['targets'], semantic_ranges=semantic_coverage(edl, targets.get('semantic_ranges', [])),
                  boundary_selection=plan['boundary_selection'], request_limit=plan['request_limit'],
                  sampling={'uniform_interval_seconds':60,'neighborhood_offset_seconds':0.07,'maximum_source_pairs':max_source_pairs})
    report['stage'] = 'full_decode'
    save()
    decoded = diag.decode_and_sample(path, clip_dir/'frames', [q(item['requested_output_time_exact']) for item in plan['requests']], data)
    report.update(full_av_decode_passes=1, full_decode=decoded['full_decode'], probe=data,
                  frame_clock={'origin_exact':decoded['clock_origin_exact'],'input_time_base':decoded['input_video_time_base'],
                               'observed_filter_time_base':decoded['observed_filter_time_base'],'time_base_mismatch':decoded['time_base_mismatch']},
                  scene_screening=decoded['scene_screening'],
                  streams={'video':sum(row.get('codec_type')=='video' for row in data['streams']),
                           'audio':sum(row.get('codec_type')=='audio' for row in data['streams'])})
    report['full_decode']['log_file'] = 'frames/'+report['full_decode']['log_file']
    log = (clip_dir/'frames'/'full-decode.log').read_text(errors='replace')
    warnings = [line for line in log.splitlines() if re.search(r'warn|deprecated|non.?monoton|corrupt|invalid|error',line,re.I)]
    report['decode_warnings'] = {'count':len(warnings),'first_lines':warnings[:30],
                                 'interpretation':'Warnings are separate from decode completion and require inspection'}
    by_time = {row['requested_output_time_exact']:row for row in plan['requests']}
    for sample in decoded['requests']:
        sample['reasons'] = by_time[sample['requested_output_time_exact']]['reasons']
        if sample.get('image_file'):
            sample['image_file'] = 'frames/'+sample['image_file']
        report['samples'].append(actual_sample(sample, edl))
    report['stage'] = 'bounded_scene_frames'
    save()
    extra, scene_report = scene_neighbors(path, clip_dir, decoded, data, edl)
    report['samples'].extend(extra)
    report['scene_peak_neighbors'] = scene_report
    report['stage'] = 'source_pairs'
    save()
    ranked = sorted(enumerate(report['samples']), key=lambda pair:(sample_priority(pair[1].get('reasons',[])), pair[0]))
    attempted, cache, omitted = 0, {}, 0
    eligible = {row.get('image_file') for row in report['samples'] if row.get('image_file') and row.get('mapped_source_time_exact') is not None}
    for index, sample in ranked:
        mapped = sample.get('mapped_source_time_exact')
        if mapped is None or not sample.get('image_file'):
            continue
        if source.get('status') != 'available':
            sample['source_frame_status'] = 'original_not_available'
            continue
        if mapped in cache:
            sample['source_frame'] = cache[mapped]
            sample['source_frame_status'] = 'reused_exact_mapped_time'
            continue
        if attempted >= max_source_pairs:
            sample['source_frame_status'] = 'omitted_at_source_pair_cap'
            omitted += 1
            continue
        attempted += 1
        try:
            frame = diag.source_frame(source['path'], outdir/'source-frames', q(mapped), source['probe'])
            if frame.get('image_file'):
                frame = {**frame, 'image_file':'../source-frames/'+frame['image_file']}
            cache[mapped] = frame
            sample['source_frame'] = frame
            sample['source_frame_status'] = 'captured' if frame.get('image_file') else 'capture_failed'
        except Exception as error:
            sample['source_frame_status'] = 'capture_failed'
            sample['source_frame_error'] = str(error)[:2000]
        report['source_pair_selection'] = {'maximum':max_source_pairs,'attempted':attempted,'eligible_distinct_output_frames':len(eligible),
                                           'omitted_sample_requests':omitted,'priority':'regression targets; first/middle/last; scene peaks; EDL cuts; uniform samples'}
        if attempted % 5 == 0:
            save()
    report['source_pair_selection'] = {'maximum':max_source_pairs,'attempted':attempted,'eligible_distinct_output_frames':len(eligible),
                                       'omitted_sample_requests':omitted,'priority':'regression targets; first/middle/last; scene peaks; EDL cuts; uniform samples'}
    for field in ('all_frame_scores_file','raw_metadata_file'):
        report['scene_screening'][field] = 'frames/'+report['scene_screening'][field]
    report['stage'] = 'completed'
    report['finished_at'] = now()
    save()
    return report


def terminate_process_group(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    except ProcessLookupError:
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, default=Path(os.environ.get('AUDIT_OUT','audit-evidence')))
    parser.add_argument('--case', default=os.environ.get('AUDIT_CASE_ID'))
    parser.add_argument('--targets', type=Path, default=HERE/'regression-targets.json')
    parser.add_argument('--deadline-seconds', type=float, default=1980)
    parser.add_argument('--max-source-pairs', type=int, default=50)
    parser.add_argument('--review-one', type=Path)
    parser.add_argument('--source-context', type=Path)
    args = parser.parse_args()
    if not args.case or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', args.case):
        parser.error('An exact safe corpus case ID is required')
    if not 1 <= args.max_source_pairs <= 50:
        parser.error('Source pair cap must be between one and fifty')
    case_dir = args.evidence.resolve()/args.case
    outdir = case_dir/'retest-review'
    outdir.mkdir(parents=True, exist_ok=True)
    all_targets = diag.read_json(args.targets) if args.targets.is_file() else {'cases':[]}
    targets = next((row for row in all_targets.get('cases',[]) if row.get('id') == args.case), {'id':args.case,'visual_points':[],'semantic_ranges':[]})
    if args.review_one:
        if args.review_one.resolve().parent != case_dir or not re.fullmatch(r'clip-\d+\.mp4', args.review_one.name):
            raise ValueError('Worker input must be an actual clip in this case directory')
        prepared = diag.read_json(args.source_context) if args.source_context else None
        report = review_clip(case_dir,args.review_one,outdir,targets,args.max_source_pairs,prepared)
        return 0 if report['full_decode']['ok'] is True else 1
    seconds = max(0,args.deadline_seconds)
    job_start = os.environ.get('AUDIT_JOB_STARTED_UNIX')
    if job_start:
        # Six-hour job ceiling, retaining fifteen minutes for encrypted packaging/uploads.
        seconds = min(seconds,max(0,float(job_start)+360*60-time.time()-15*60))
    deadline = time.monotonic()+seconds
    files = sorted(case_dir.glob('clip-*.mp4'))
    summary = {'schema':1,'case_id':args.case,'started_at':now(),'status':'running','deadline_seconds':seconds,
               'target_file':args.targets.name,'target_case_present':any(row.get('id') == args.case for row in all_targets.get('cases',[])),
               'visual_targets':targets.get('visual_points',[]),'semantic_ranges':targets.get('semantic_ranges',[]),
               'actual_mp4_count':len(files),'clips':[],'limitations':LIMITATIONS,'quality_verdict':None}
    save = lambda:diag.save_json(outdir/'review.json',summary)
    save()
    if not files or deadline-time.monotonic() < 15:
        summary['clips'] = [{'file':path.name,'status':'not_reviewed_deadline','full_decode_completed':False} for path in files]
        summary.update(status='incomplete' if files else 'no_exports', finished_at=now(), full_decodes_completed=0)
        save()
        return 1 if files else 0
    context_file = outdir/'source-context.json'
    diag.save_json(context_file, source_context(case_dir))
    for path in files:
        left = deadline-time.monotonic()
        if left < 15:
            summary['clips'].append({'file':path.name,'status':'not_reviewed_deadline','full_decode_completed':False})
            save()
            continue
        command = [sys.executable,str(Path(__file__).resolve()),'--evidence',str(args.evidence.resolve()),'--case',args.case,
                   '--targets',str(args.targets.resolve()),'--max-source-pairs',str(args.max_source_pairs),'--review-one',str(path),
                   '--source-context',str(context_file)]
        log = outdir/(path.stem+'-worker.log')
        timed_out = False
        with log.open('w') as stream:
            process = subprocess.Popen(command,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
            try:
                code = process.wait(timeout=left)
            except subprocess.TimeoutExpired:
                timed_out = True
                terminate_process_group(process)
                code = process.returncode
        report_path = outdir/path.stem/'review.json'
        report = diag.read_json(report_path) if report_path.is_file() else {}
        entry = {'file':path.name,'status':'incomplete_deadline' if timed_out else 'completed' if code == 0 else 'review_failed',
                 'returncode':code,'report':path.stem+'/review.json','worker_log':log.name,
                 'full_decode_completed':report.get('full_decode',{}).get('ok') is True,
                 'stage':report.get('stage'),'clip_sha256':report.get('clip_sha256')}
        summary['clips'].append(entry)
        save()
        print(json.dumps({'case':args.case,**entry},ensure_ascii=False),flush=True)
    summary.update(status='completed' if files and all(row['status']=='completed' for row in summary['clips']) else 'no_exports' if not files else 'incomplete',
                   finished_at=now(),full_decodes_completed=sum(row['full_decode_completed'] for row in summary['clips']))
    save()
    return 0 if summary['status'] in ('completed','no_exports') else 1


if __name__ == '__main__':
    raise SystemExit(main())
