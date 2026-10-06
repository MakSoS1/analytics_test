"""Regression test for the 2026-09-28 zero-admitted-feature export defect.

pyarrow round-trips a zero-column table's row count as 0 through Parquet
(confirmed by direct reproduction), so `dataset.export` must never write a
features.parquet when nothing is admitted -- labels.parquet is the record.
Caught by an external review reading files directly on the deployment host;
the earlier claim "features/labels row counts agree across all eight" had
only compared column names, never features.parquet's own row count.
"""
import json
import tempfile
import unittest
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from office_injection.dataset import export


def build_run(root, admitted_features, extra_feature_value=7):
    root = Path(root)
    (root / 'validated.json').write_text(json.dumps({'run_id': 'r', 'source_role': 'x'}))
    (root / 'positive_registry.json').write_text('[]')
    (root / 'naturalness.json').write_text(json.dumps({
        'gate': 'passed' if admitted_features else 'failed',
        'decision': 'clean_candidate' if admitted_features else 'no_signal_in_current_features',
        'admitted_features': admitted_features,
        'confirmation': {'joint_domain_auc_on_technique_markers': {'auc': 0.5},
                         'B_scenario_vs_control_on_technique_markers': {'auc': 0.9 if admitted_features else None}},
    }))
    batch = root / 'batches' / 'b00000' / 'parquet'; batch.mkdir(parents=True)
    n = 25
    cols = {'global_session_uid': [f's{i}' for i in range(n)],
            'global_segment_uid': [f'g{i}' for i in range(n)],
            'segment_start_ts': [pa.scalar(1790000000 + i, type=pa.timestamp('us', tz='UTC')).as_py() for i in range(n)],
            'tls_sni_len': [extra_feature_value] * n}  # a real pinned feature column
    pq.write_table(pa.table(cols), batch / 'office_sessions.parquet')
    # No positives in this fixture: segment_gt.parquet is left absent, so
    # export's glob for it finds nothing and every row stays office_unlabelled.
    return n


class DatasetZeroFeatureExportTests(unittest.TestCase):
    def test_no_features_parquet_when_nothing_admitted_but_labels_keep_every_row(self):
        with tempfile.TemporaryDirectory() as d:
            run = Path(d) / 'run'; run.mkdir()
            n = build_run(run, admitted_features=[])
            manifest = export(run, Path(d) / 'out')
            b = manifest['batches'][0]
            self.assertEqual(b['features'], [])
            self.assertIsNone(b['features_file'])
            self.assertEqual(b['rows'], n)
            out_batch = Path(d) / 'out' / 'b00000'
            self.assertFalse((out_batch / 'features.parquet').exists())
            labels = pq.read_table(out_batch / 'labels.parquet')
            self.assertEqual(labels.num_rows, n)  # the bug this guards: it silently read back 0

    def test_features_parquet_written_and_row_count_matches_labels_when_something_is_admitted(self):
        with tempfile.TemporaryDirectory() as d:
            run = Path(d) / 'run'; run.mkdir()
            n = build_run(run, admitted_features=['tls_sni_len'])
            manifest = export(run, Path(d) / 'out')
            b = manifest['batches'][0]
            self.assertEqual(b['features'], ['tls_sni_len'])
            self.assertEqual(b['features_file'], 'features.parquet')
            out_batch = Path(d) / 'out' / 'b00000'
            features = pq.read_table(out_batch / 'features.parquet')
            labels = pq.read_table(out_batch / 'labels.parquet')
            self.assertEqual(features.num_rows, n)
            self.assertEqual(features.num_rows, labels.num_rows)
            self.assertEqual(features.column('tls_sni_len').to_pylist(), [7] * n)


if __name__ == '__main__':unittest.main()
