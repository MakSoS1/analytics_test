"""Unsupervised K-means exploration of a challenge-clustering export.

Labels and techniques are read only after fitting, for post-hoc interpretation.
This is exploratory clustering, not a supervised validation or office-transfer test.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.impute import SimpleImputer
from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score, silhouette_score
from sklearn.preprocessing import QuantileTransformer

from . import training_contract as contract
from .pipeline import dump


def _metrics(reference, predicted, matrix):
    return {
        'adjusted_rand_index': round(float(adjusted_rand_score(reference, predicted)), 4),
        'normalized_mutual_information': round(float(normalized_mutual_info_score(reference, predicted)), 4),
        'silhouette': round(float(silhouette_score(matrix, predicted)), 4),
    }


def analyze(source, out, *, seed=1701):
    source, out = Path(source), Path(out)
    if out.exists():
        raise FileExistsError('cluster analysis output must be a new directory')
    source_manifest = json.loads((source / 'manifest.json').read_text())
    if source_manifest.get('status') != 'exploratory_clustering_ready':
        raise ValueError('input is not a verified challenge clustering export')
    feature_path, metadata_path = source / 'features.parquet', source / 'metadata.parquet'
    feature_table = pq.read_table(feature_path)
    metadata_table = pq.read_table(metadata_path)
    feature_names = feature_table.column_names
    if feature_names != source_manifest.get('feature_order') or feature_names != list(contract.SESSION_FEATURES):
        raise ValueError('feature matrix differs from pinned X contract')
    n = feature_table.num_rows
    metadata = metadata_table.to_pydict()
    if metadata_table.num_rows != n or metadata.get('row_index') != list(range(n)):
        raise ValueError('metadata and feature rows do not align')
    techniques = np.asarray(metadata['technique'], dtype=object)
    arms = np.asarray(metadata['arm'], dtype=object)
    labels = np.asarray(metadata['label_binary'], dtype=int)
    if set(arms) != {'scenario', 'control'} or set(labels) != {0, 1}:
        raise ValueError('cluster interpretation metadata lacks both verified arms')
    if any((arm == 'scenario') != (label == 1) for arm, label in zip(arms, labels)):
        raise ValueError('arm and verified binary label disagree')

    raw = feature_table.to_pandas().replace([np.inf, -np.inf], np.nan)
    usable = [name for name in feature_names if not raw[name].isna().all() and raw[name].nunique(dropna=True) > 1]
    if len(usable) < 2:
        raise ValueError('fewer than two varying numeric features')
    raw = raw[usable]
    imputed = SimpleImputer(strategy='median').fit_transform(raw)
    transformed = QuantileTransformer(
        n_quantiles=min(100, n), output_distribution='normal', random_state=seed,
        subsample=max(10000, n),
    ).fit_transform(imputed)
    n_components = min(20, transformed.shape[1], transformed.shape[0] - 1)
    projected = PCA(n_components=n_components, random_state=seed).fit_transform(transformed)

    technique_names = sorted(set(techniques.tolist()))
    if len(technique_names) < 2 or n < max(20, len(technique_names) * 2):
        raise ValueError('insufficient sessions/techniques to compare clusters')
    k_tech = len(technique_names)
    all_tech = KMeans(n_clusters=k_tech, n_init=50, random_state=seed).fit_predict(projected)
    all_arm = KMeans(n_clusters=2, n_init=50, random_state=seed).fit_predict(projected)
    scenario_mask = arms == 'scenario'
    scenario_x = projected[scenario_mask]
    scenario_tech = techniques[scenario_mask]
    scenario_clusters = KMeans(n_clusters=k_tech, n_init=50, random_state=seed).fit_predict(scenario_x)
    metrics = {
        'all_sessions_kmeans_k_techniques_vs_technique': _metrics(techniques, all_tech, projected),
        'all_sessions_kmeans_k_2_vs_scenario_control': _metrics(labels, all_arm, projected),
        'scenario_only_kmeans_k_techniques_vs_technique': _metrics(scenario_tech, scenario_clusters, scenario_x),
    }
    contingency = defaultdict(Counter)
    for cluster, technique, arm in zip(all_tech, techniques, arms):
        contingency[str(int(cluster))][f'{technique}|{arm}'] += 1
    scenario_contingency = defaultdict(Counter)
    for cluster, technique in zip(scenario_clusters, scenario_tech):
        scenario_contingency[str(int(cluster))][str(technique)] += 1
    assignments = []
    scenario_iter = iter(scenario_clusters.tolist())
    for i, (technique, arm, label) in enumerate(zip(techniques.tolist(), arms.tolist(), labels.tolist())):
        assignments.append({
            'row_index': i, 'technique': technique, 'arm': arm, 'label_binary': label,
            'cluster_k_techniques_all': int(all_tech[i]), 'cluster_k2_arm_all': int(all_arm[i]),
            'cluster_k_techniques_scenario_only': int(next(scenario_iter)) if arm == 'scenario' else None,
        })

    out.mkdir(parents=True)
    assign_path = out / 'cluster_assignments.parquet'
    pq.write_table(pa.Table.from_pylist(assignments), assign_path, compression='zstd')
    report = {
        'status': 'exploratory_clustered', 'source_manifest': str(source / 'manifest.json'),
        'rows': n, 'features_input': len(feature_names), 'features_varying': len(usable),
        'features_dropped_constant_or_all_missing': sorted(set(feature_names) - set(usable)),
        'preprocessing': {'missing': 'median imputation', 'scale': 'per-feature empirical quantile to normal',
                          'projection': f'PCA {n_components} components', 'seed': seed},
        'models': {'algorithm': 'KMeans', 'n_init': 50,
                   'all_sessions_technique_k': k_tech, 'scenario_control_k': 2,
                   'scenario_only_technique_k': k_tech},
        'metrics': metrics,
        'all_sessions_technique_cluster_composition': {k: dict(v) for k, v in sorted(contingency.items())},
        'scenario_only_technique_cluster_composition': {k: dict(v) for k, v in sorted(scenario_contingency.items())},
        'interpretation_limits': [
            'No train/test split was requested; these are in-sample unsupervised partitions.',
            'Technique and arm labels were excluded from X and used only after fitting for interpretation.',
            'The generated template pool covers one source day; this does not establish day or office transfer.',
            'Application messages are documented fixtures; this does not establish full native campaign mechanics.',
        ],
        'production_training_ready': False,
    }
    dump(out / 'report.json', report)
    report_path = out / 'report.json'
    dump(out / 'COMPLETE.json', {
        'report_sha256': hashlib.sha256(report_path.read_bytes()).hexdigest(),
        'files': {'cluster_assignments.parquet': hashlib.sha256(assign_path.read_bytes()).hexdigest(),
                  'report.json': hashlib.sha256(report_path.read_bytes()).hexdigest()},
    })
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--seed', type=int, default=1701)
    args = parser.parse_args()
    result = analyze(args.source, args.out, seed=args.seed)
    print(json.dumps({'status': result['status'], 'rows': result['rows'],
                      'features_input': result['features_input'], 'features_varying': result['features_varying'],
                      'metrics': result['metrics'],
                      'cluster_count': len(result['all_sessions_technique_cluster_composition'])}, indent=2))


if __name__ == '__main__':
    main()
