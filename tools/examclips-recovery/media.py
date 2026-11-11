"""Bounded recovery diagnostics using each clip's authenticated pre-export view.

Raw result/project/media files are never changed. An absent or ambiguous
pre-export binding permits output-only decoding, never mapped source claims.
"""
import contextlib
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('recovery_media_core', HERE / 'media_core.py')
core = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(core)
_base_sample_plan = core.sample_plan
CLIP_NAME = re.compile(r'clip-(\d+)\.mp4')


def bounded_sample_plan(duration, edl, track, interval=core.q(60),
                        max_smooth_events=12, frame_interval=core.q('0.06666666666666667')):
    plans, events = _base_sample_plan(duration, edl, track, interval=core.q(60),
                                     max_smooth_events=12, frame_interval=frame_interval)
    if core.q(duration) > 1:
        found = next((p for p in plans if core.q(p['requested_output_time_exact']) == 1), None)
        if found:
            found['reasons'] = sorted(set(found['reasons']) | {'title_first_second'})
        else:
            plans.append({'requested_output_time_exact': '1', 'requested_output_time_sec': 1.0,
                          'reasons': ['title_first_second']})
        plans.sort(key=lambda p: core.q(p['requested_output_time_exact']))
    return plans, events


core.sample_plan = bounded_sample_plan


@contextlib.contextmanager
def cpu_bound():
    original = os.sched_getaffinity(0) if hasattr(os, 'sched_getaffinity') else None
    if original and len(original) > 2:
        os.sched_setaffinity(0, set(sorted(original)[:2]))
    try:
        yield
    finally:
        if original:
            os.sched_setaffinity(0, original)


def strict_edl(clip, duration=None):
    pieces = clip.get('segments')
    if pieces is not None and not isinstance(pieces, list):
        raise ValueError('INVALID_PRE_EXPORT_SEGMENTS')
    pieces = pieces or [{'start': clip.get('start'), 'end': clip.get('end')}]
    for piece in pieces:
        start, end = core.q(piece['start']), core.q(piece['end'])
        if start < 0 or end <= start or (duration is not None and end > duration):
            raise ValueError('INVALID_PRE_EXPORT_INTERVAL')
    edl = core.build_edl(clip)
    if len(edl) != len(pieces):
        raise ValueError('INCOMPLETE_PRE_EXPORT_EDL')
    return edl


def bind_clip(case, result, filename, duration=None, result_sha256=None):
    """Select by actual filename/producer index, then unique saved clip ID."""
    case = pathlib.Path(case)
    if not CLIP_NAME.fullmatch(filename):
        raise ValueError('INVALID_ACTUAL_CLIP_FILENAME')
    rows = [(i, r) for i, r in enumerate(result.get('clips', [])) if isinstance(r, dict)]
    matches = [(i, r) for i, r in rows if r.get('file') == filename]
    result_binding = 'exact_result_filename'
    if not matches:
        producer_index = int(CLIP_NAME.fullmatch(filename).group(1)) - 1
        matches = [(i, r) for i, r in rows
                   if type(r.get('index')) is int and r['index'] == producer_index
                   and not r.get('file')]
        result_binding = 'unique_result_index_for_existing_file'
    row_index, row = matches[0] if len(matches) == 1 else (None, {})
    raw_row = copy.deepcopy(row)
    derived = copy.deepcopy(row)
    derived['file'] = filename
    for key in ('start', 'end', 'segments'):
        derived.pop(key, None)
    snapshot_path = case / (pathlib.Path(filename).stem + '-project-before-export.json')
    provenance = {
        'mapping_allowed': False, 'renderer_edl_confirmed': False,
        'result_file': 'result.json',
        'result_sha256': result_sha256 or core.digest(case / 'result.json'),
        'result_row_index': row_index, 'result_binding': result_binding if len(matches) == 1 else None,
        'result_row_pointer': '/clips/' + str(row_index) if row_index is not None else None,
        'initial_result_output_seconds': row.get('outputSeconds'),
        'snapshot_file': snapshot_path.name, 'snapshot_sha256': None,
        'titles_are_metadata_only': True,
        'limitation': 'Saved pre-export EDL/camera evidence; identity with the renderer remains unconfirmed.',
    }
    answer = {'row': raw_row, 'derived_row': derived, 'snapshot': {}, 'snapshot_bytes': None,
              'snapshot_path': snapshot_path, 'snapshot_clip_index': None, 'edl': [],
              'provenance': provenance}
    if len(matches) != 1:
        provenance['status'] = 'missing_or_ambiguous_result_row'
        return answer
    clip_id = row.get('id')
    if not isinstance(clip_id, (str, int)) or isinstance(clip_id, bool) or str(clip_id) == '':
        provenance['status'] = 'missing_result_clip_id'
        return answer
    if not snapshot_path.is_file() or snapshot_path.is_symlink():
        provenance['status'] = 'missing_pre_export_snapshot'
        return answer
    try:
        raw = snapshot_path.read_bytes()
        provenance['snapshot_sha256'] = hashlib.sha256(raw).hexdigest()
        parsed = json.loads(raw)
        project = core.project_snapshot(parsed)
        clips = project.get('clips', [])
        if not isinstance(clips, list):
            raise ValueError('INVALID_PRE_EXPORT_CLIP_ARRAY')
        selected = [(i, c) for i, c in enumerate(clips)
                    if isinstance(c, dict) and c.get('id') is not None and str(c['id']) == str(clip_id)]
        if len(selected) != 1:
            provenance['status'] = 'missing_or_ambiguous_pre_export_clip_id'
            return answer
        clip_index, clip = selected[0]
        edl = strict_edl(clip, duration)
        merged = {**copy.deepcopy(clip), **copy.deepcopy(row)}
        for key in ('id', 'title', 'start', 'end', 'segments'):
            merged.pop(key, None)
            if key in clip:
                merged[key] = copy.deepcopy(clip[key])
        merged['file'] = filename
        merged['outputSeconds'] = float(edl[-1]['output_end'])
        provenance.update(
            status='unique_pre_export_clip_id', mapping_allowed=True,
            clip_id=str(clip_id), snapshot_clip_index=clip_index,
            snapshot_clip_pointer=('/snapshot' if isinstance(parsed.get('snapshot'), dict) else '') + '/clips/' + str(clip_index),
            initial_result_edl=core.edl_json(core.build_edl(row)),
            initial_result_edl_matches=core.build_edl(row) == edl,
            snapshot_camera_present='lectureCamera' in project,
            snapshot_copied_byte_for_byte=True,
        )
        answer.update(derived_row=merged, snapshot=project, snapshot_bytes=raw,
                      snapshot_clip_index=clip_index, edl=edl)
    except (ValueError, TypeError, KeyError, ZeroDivisionError, OSError) as error:
        provenance.update(status='invalid_pre_export_snapshot', error=type(error).__name__)
    return answer


def source_complement(duration, spans):
    """Exact union/complement of saved source spans; gaps are not loss verdicts."""
    duration = core.q(duration)
    union = []
    for start, end in sorted((core.q(a), core.q(b)) for a, b in spans):
        start, end = max(core.q(0), start), min(duration, end)
        if end <= start:
            continue
        if union and start <= union[-1][1]:
            union[-1][1] = max(union[-1][1], end)
        else:
            union.append([start, end])
    gaps, position = [], core.q(0)
    for start, end in union:
        if start > position:
            gaps.append([position, start])
        position = max(position, end)
    if position < duration:
        gaps.append([position, duration])
    def records(intervals):
        return [{'start_exact': str(a), 'end_exact': str(b), 'seconds_exact': str(b-a),
                 'start_sec': float(a), 'end_sec': float(b), 'seconds': float(b-a)}
                for a, b in intervals]
    return {'duration_exact': str(duration), 'union': records(union), 'gaps': records(gaps),
            'gap_seconds_exact': str(sum((b-a for a, b in gaps), core.q(0)))}


def require_native_frame_context(case):
    # The encrypted ingest already binds this case to the selected native job.
    # Recheck its unchanged authenticated metadata before opening a new filename.
    metadata = {}
    for name, path in (('run', case.parent / 'run.json'), ('result', case / 'result.json')):
        if not path.is_file() or path.is_symlink():
            raise ValueError('NATIVE_FRAME_METADATA_NOT_REGULAR')
        metadata[name] = core.read_json(path)
    run, result = metadata['run'], metadata['result']
    expected = {'repository': 'MakSoS1/analytics_test', 'branch': 'qa/examclips-audit-2026-11-11',
                'runId': '43116421328', 'runAttempt': '1', 'caseId': 'rul01'}
    if any(str(run.get(key, '')) != value for key, value in expected.items()):
        raise ValueError('NATIVE_FRAME_CONTEXT_MISMATCH')
    if result.get('id') != 'rul01':
        raise ValueError('NATIVE_FRAME_CONTEXT_MISMATCH')
    for record in (run, result):
        if (record.get('auditKind') != 'native_export_probe'
                or record.get('supplementary') is not True
                or record.get('corpusCountIncrement') != 0):
            raise ValueError('NATIVE_FRAME_CONTEXT_MISMATCH')


def extract_frame(case, name, seconds):
    case = pathlib.Path(case).resolve()
    if name == 'native-clip.mp4':
        require_native_frame_context(case)
    elif not re.fullmatch(r'(?:original-source|clip-\d+)\.mp4', name):
        raise ValueError('INVALID_MEDIA_NAME')
    seconds = core.q(seconds)
    if not 0 <= seconds <= 10800:
        raise ValueError('INVALID_MEDIA_TIME')
    media = case / name
    if not media.is_file() or media.is_symlink():
        raise ValueError('MEDIA_NOT_REGULAR')
    out = case / 'recovery-frames' / pathlib.Path(name).stem
    with cpu_bound():
        result = core.source_frame(media, out, seconds, core.probe(media))
    if result.get('returncode') != 0 or not result.get('image_file') or result.get('actual_source_time_exact') is None:
        raise ValueError('NO_FRAME_AT_REQUESTED_TIME')
    result['image_file'] = str((out / result['image_file']).relative_to(case))
    result['media_file'] = name
    if name == 'native-clip.mp4':
        result['media_kind'] = 'supplementary_native_export'
        result['corpusCountIncrement'] = 0
    return result


def inspect_recovery(case, outdir=None):
    case = pathlib.Path(case).resolve()
    outdir = pathlib.Path(outdir).resolve() if outdir else case / 'recovery-diagnostics'
    outdir.mkdir(parents=True, exist_ok=True)
    result_path = case / 'result.json'
    result = core.read_json(result_path)
    result_hash = core.digest(result_path)
    rows = result.get('clips', [])
    if not isinstance(rows, list):
        raise ValueError('INVALID_RESULT_CLIPS')
    files = sorted(p for p in case.glob('clip-*.mp4') if CLIP_NAME.fullmatch(p.name))
    if any(p.is_symlink() or not p.is_file() for p in files):
        raise ValueError('ACTUAL_CLIP_NOT_REGULAR')
    source = case / 'original-source.mp4'
    if source.is_symlink():
        raise ValueError('SOURCE_NOT_REGULAR')
    source_data = core.probe(source) if source.is_file() else None
    duration = core.q(source_data['format']['duration']) if source_data else None
    source_clock = None
    if source_data:
        _, time_base, origin = core.video_clock(source_data)
        source_clock = {'time_base_exact': str(time_base), 'clock_origin_exact': str(origin),
                        'duration_exact': str(duration), 'probe': source_data}
    missing = [dict(index=r.get('index'), id=r.get('id'), file=r.get('file'))
               for r in rows if isinstance(r, dict) and r.get('exportStatus') == 'downloaded'
               and (not isinstance(r.get('file'), str) or not CLIP_NAME.fullmatch(r['file'])
                    or not (case / r['file']).is_file())]
    summary = {
        'schema_version': 1, 'status': 'in_progress',
        'generated_utc': datetime.now(timezone.utc).isoformat(), 'case_directory': str(case),
        'result_file': 'result.json', 'result_sha256': result_hash,
        'wrapper_sha256': core.digest(__file__), 'core_sha256': core.digest(HERE / 'media_core.py'),
        'core_upstream_git_blob': 'd94a43b0174c413d415d5dac8e10960361a30369',
        'core_modification': 'Only both enc_time_base arguments change from filter to -1.',
        'source_clock': source_clock, 'source': None, 'clips': [],
        'missing_claimed_downloads': missing,
        'not_exported_rows': [{k: r.get(k) for k in ('index', 'id', 'file', 'title', 'exportStatus', 'exportReason')}
                              for r in rows if isinstance(r, dict) and r.get('exportStatus') != 'downloaded'],
        'full_project_files': [{'path': name, 'bytes': (case/name).stat().st_size, 'sha256': core.digest(case/name)}
                               for name in ('project.json', 'project-final.json', 'project-partial.json')
                               if (case/name).is_file()],
        'recovery_scope': {'uniform_seconds': 60, 'title_probe_seconds': 1,
                           'max_saved_smooth_camera_events_per_clip': 12,
                           'all_mandatory_edl_camera_boundaries_retained': True,
                           'max_decode_cpus': 2, 'continuous_manual_viewing': False,
                           'continuous_manual_listening': False, 'quality_verdict': None},
        'quality_verdict': None,
    }
    downloaded_spans, unresolved_downloaded, other_existing = [], [], []
    with cpu_bound():
        for media in files:
            bound = bind_clip(case, result, media.name, duration, result_hash)
            provenance = bound['provenance']
            clipdir = outdir / media.stem
            clipdir.mkdir(parents=True, exist_ok=True)
            report_path = clipdir / 'diagnostics.json'
            entry = {'file': media.name, 'diagnostics_file': str(report_path.relative_to(outdir)),
                     'export_status_recorded': bound['row'].get('exportStatus'),
                     'timing_provenance': provenance, 'full_decode_ok': None}
            if bound['row'].get('exportStatus') == 'downloaded':
                if provenance['mapping_allowed']:
                    downloaded_spans.extend((p['source_start'], p['source_end']) for p in bound['edl'])
                else:
                    unresolved_downloaded.append(media.name)
            else:
                other_existing.append({'file': media.name, 'export_status_recorded': bound['row'].get('exportStatus'),
                                       'mapping_allowed': provenance['mapping_allowed'],
                                       'edl': core.edl_json(bound['edl'])})
            try:
                with tempfile.TemporaryDirectory(prefix='examclips-media-view-', dir=case.parent.parent) as temporary:
                    work = pathlib.Path(temporary)
                    (work / media.name).symlink_to(media)
                    if source_data:
                        (work / 'original-source.mp4').symlink_to(source)
                    if provenance['mapping_allowed']:
                        (work / 'project.json').write_bytes(bound['snapshot_bytes'])
                    else:
                        core.save_json(work / 'project.json', {})
                    derived = {'id': result.get('id'), 'source': result.get('source') or {},
                               'clips': [bound['derived_row']]}
                    core.save_json(work / 'result.json', derived)
                    child = core.inspect_case(work, interval=60, audio_check=False, outdir=outdir, reuse_completed=False)
                    report = core.read_json(report_path)
                    report['file'] = str(media)
                    report['timing_provenance'] = provenance
                    report['selected_edl_provenance'] = (
                        provenance['snapshot_file'] + ' unique clip ID' if provenance['mapping_allowed']
                        else 'unavailable: output-only decode; no source EDL/camera mapping')
                    report['saved_camera']['project_file'] = provenance['snapshot_file'] if provenance['mapping_allowed'] else None
                    report['edl_alternatives'] = [{'project_file': provenance['snapshot_file'],
                                                  'binding': provenance['status'], 'edl': core.edl_json(bound['edl']),
                                                  'matches_selected_edl': provenance['mapping_allowed']}]
                    actual = report.get('probe', {}).get('format', {}).get('duration')
                    report['duration_comparison'] = {
                        'actual_mp4_seconds_exact': str(core.q(actual)) if actual is not None else None,
                        'pre_export_edl_seconds_exact': str(bound['edl'][-1]['output_end']) if bound['edl'] else None,
                        'initial_result_output_seconds': bound['row'].get('outputSeconds'),
                        'actual_minus_pre_export_seconds_exact':
                            str(core.q(actual)-bound['edl'][-1]['output_end']) if actual is not None and bound['edl'] else None,
                        'quality_verdict': None,
                    }
                    core.save_json(report_path, report)
                    child_entry = child['clips'][0]
                    entry.update({k: v for k, v in child_entry.items() if k not in ('file', 'diagnostics_file')})
                    entry['full_decode_ok'] = report.get('full_decode', {}).get('ok')
                    entry['timing_provenance'] = provenance
                    if child.get('source', {}).get('status') == 'available':
                        summary['source'] = {**child['source'], 'path': str(source)}
            except Exception as error:
                entry['diagnostic_error'] = repr(error)
                core.save_json(report_path, {'file': str(media), 'timing_provenance': provenance,
                                            'diagnostic_error': repr(error), 'quality_verdict': None})
            summary['clips'].append(entry)
            core.save_json(outdir / 'diagnostics.json', summary)
    decoded = {e['file']: e.get('full_decode_ok') is True and not e.get('diagnostic_error') for e in summary['clips']}
    downloaded = [r for r in rows if isinstance(r, dict) and r.get('exportStatus') == 'downloaded']
    summary.update(
        status='inspected_actual_exports' if files else 'no_actual_export_files',
        finished_utc=datetime.now(timezone.utc).isoformat(),
        mapped_existing_clips=sum(e['timing_provenance']['mapping_allowed'] for e in summary['clips']),
        all_existing_files_decoded=bool(files) and all(decoded.values()),
        all_downloaded_files_decoded=bool(downloaded) and not missing and all(decoded.get(r.get('file'), False) for r in downloaded),
    )
    navigation = source_complement(duration, downloaded_spans) if duration is not None else {}
    navigation.update(
        status=('complete_saved_edl_complement' if not missing and not unresolved_downloaded else 'partial_saved_edl_complement')
               if duration is not None else 'source_duration_unavailable',
        scope='Only existing files recorded as downloaded contribute to this source union.',
        unresolved_downloaded_files=unresolved_downloaded, missing_claimed_downloads=missing,
        other_existing_files_not_in_downloaded_union=other_existing,
        source_clock=source_clock, quality_verdict=None,
        limitation='All gap lengths, including under 3 seconds, are navigation candidates; none establishes omitted teaching without source/output review.',
    )
    core.save_json(outdir / 'source-navigation.json', navigation)
    summary['source_navigation_file'] = 'source-navigation.json'
    core.save_json(outdir / 'diagnostics.json', summary)
    return summary


def main():
    import sys
    mode, case = sys.argv[1:3]
    if mode == 'frame':
        print(json.dumps(extract_frame(case, sys.argv[3], sys.argv[4])))
        return 0
    if mode != 'diagnostics':
        raise ValueError('UNSUPPORTED_MEDIA_OPERATION')
    summary = inspect_recovery(case)
    print(json.dumps({'status': summary['status'], 'clips': len(summary['clips']),
                      'all_decoded': summary['all_existing_files_decoded'],
                      'all_downloaded_decoded': summary['all_downloaded_files_decoded'],
                      'mapped_existing_clips': summary['mapped_existing_clips']}))
    return 0 if summary['all_existing_files_decoded'] and not summary['missing_claimed_downloads'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
