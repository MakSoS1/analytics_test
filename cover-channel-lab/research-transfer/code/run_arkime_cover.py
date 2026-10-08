"""Run a prepared cover corpus on VM; retain all inputs, never publish."""
import argparse
import bisect
import contextlib
import csv
import hashlib
import json
from pathlib import Path
import sqlite3
import struct


def execute(prepared, out):
    from prepare_arkime_cover import packets, sha
    from run_local import run, guard
    from pipeline import OpenSearch, flatten
    from arkime_csv import export
    guard(prepared)
    out.mkdir(parents=True, exist_ok=False)
    provenance = json.loads((prepared / 'PROVENANCE_ISOLATED.json'
                            if (prepared / 'PROVENANCE_ISOLATED.json').exists()
                            else prepared / 'PROVENANCE.json').read_text())
    sources = provenance['sources']
    starts = [source['mixed_first_ms'] for source in sources]
    isolated = []
    for index, source in enumerate(sources):
        if not source.get('observation_path'):
            continue
        observation = json.loads(Path(source['observation_path']).read_text())
        if any(packet.get('proto') not in (6, 17) for packet in observation['packets']):
            isolated.append(index)
    groups = out / 'inputs'
    groups.mkdir()
    handles = {}
    try:
        for name in ['main'] + [str(index) for index in isolated]:
            handle = (groups / (name + '.pcap')).open('wb')
            handle.write(struct.pack('<IHHIIII', 0xa1b23c4d, 2, 4, 0, 0, 262144, 1))
            handles[name] = handle
        for stamp, frame in packets(prepared / 'source_isolated_mix.pcap'):
            index = bisect.bisect_right(starts, stamp // 10**6) - 1
            name = str(index) if index in isolated else 'main'
            seconds, ns = divmod(stamp, 10**9)
            handles[name].write(struct.pack('<IIII', seconds, ns, len(frame), len(frame)))
            handles[name].write(frame)
    finally:
        for handle in handles.values():
            handle.close()
    api = OpenSearch()
    definitions = [{'field_id': hit['_id'], 'definition': hit['_source']}
                   for hit in api.hits('office_arkime_fields')]
    if any(str(record['definition'].get('disabled', 'false')).lower() == 'true'
           for record in definitions):
        raise ValueError('disabled Arkime field; refuse incomplete full-feature run')
    (out / 'catalog.json').write_text(json.dumps(definitions, indent=2) + '\n')
    (out / 'PROVENANCE.json').write_text(json.dumps(provenance, indent=2) + '\n')
    results, states = [], []
    for path in sorted(groups.glob('*.pcap')):
        destination = out / ('run_' + path.stem)
        with (out / (path.stem + '.stdout')).open('w') as log, contextlib.redirect_stdout(log):
            result = run([path], destination)
        results.append(result)
        states.append(destination / 'state.db')
        print(json.dumps({key: result[key] for key in
              ('frames', 'status', 'pcaps_deleted', 'cosmolake_uploads')}), flush=True)
    if sum(result['frames'] for result in results) != provenance['input_packets']:
        raise ValueError('input packet accounting mismatch')
    combined = sqlite3.connect(out / 'state.db')
    first = sqlite3.connect(states[0])
    first.backup(combined)
    first.close()
    for path in states[1:]:
        combined.execute('attach database ? as incoming', (str(path),))
        with combined:
            for table in ('fragments', 'revisions', 'feature_atoms', 'session_totals', 'chunks'):
                combined.execute('insert into ' + table + ' select * from incoming.' + table)
        combined.execute('detach database incoming')
    # This combined DB is an export snapshot; seq numbers are per capture epoch.
    # It is deliberately never passed back into the capture/sync lifecycle.
    combined.close()
    report = export(out/'state.db', out/'catalog.json', out/'PROVENANCE.json', out/'csv')
    observed = set()
    db = sqlite3.connect(f'file:{out / "state.db"}?mode=ro', uri=True)
    for (raw,) in db.execute('select source_json from fragments'):
        observed.update(path for path, value in flatten(json.loads(raw)))
    verified_fragments = 0
    with (out/'csv/arkime_fragments_full_spi.csv').open(newline='') as handle:
        for row in csv.DictReader(handle):
            if hashlib.sha256(row['source_json'].encode()).hexdigest() != row['revision']:
                raise ValueError('raw SPI changed in CSV')
            verified_fragments += 1
    if verified_fragments != report['fragments']:
        raise ValueError('raw SPI CSV count mismatch')
    unchanged = sum(sha(Path(source['path'])) == source['sha256'] for source in sources)
    if unchanged != len(sources):
        raise ValueError('original source changed')
    references = {row['global_segment_uid'] for source in sources
                  for row in source['original_contexts']}
    if len(references) != provenance['original_labelled_segments']:
        raise ValueError('original segment provenance coverage mismatch')
    report.update(input_packets=provenance['input_packets'], original_sources_verified=unchanged,
                  original_segment_references=len(references), populated_spi_fields=len(observed),
                  disabled_catalog_fields=0, separate_protocol_capture_processes=len(isolated),
                  csv_raw_spi_verified=verified_fragments, independent_capture_crossings=0)
    (out/'RUNS.json').write_text(json.dumps(results, indent=2) + '\n')
    (out/'csv/COMPLETE.json').write_text(json.dumps(report, indent=2) + '\n')
    db.close()
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    execute(args.prepared, args.out)
