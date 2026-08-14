import numpy as np
import pandas as pd

from adminlab.modeling import evaluate_deterministic, train_benign_only, train_supervised


def matrix() -> pd.DataFrame:
    rng=np.random.default_rng(7)
    rows=[]
    splits=(['train']*160)+(['validation']*60)+(['test']*40)+(['challenge']*40)
    for i,split in enumerate(splits):
        label=i%4==0
        rows.append({
            'flow_count': float(1 + label*4 + rng.normal(0,.2)),
            'duration': float(10 + label*3 + rng.normal(0,1)),
            'connections_1m': float(label*5 + rng.integers(0,2)),
            'connections_15m': float(label*8 + rng.integers(0,3)),
            'new_dst_for_src': int(label),
            'new_src_dst_pair': int(label),
            'src_out_degree_1h': float(label*4 + rng.integers(0,2)),
            'app_proto': 'ssh' if i%2 else 'smb',
            'label_binary': int(label),
            'split': split,
        })
    return pd.DataFrame(rows)


def test_supervised_baseline_trains_and_reports_validation():
    model,report=train_supervised(matrix(),seed=3)
    assert report['model']=='LightGBM'
    assert 'validation' in report['splits']
    assert 0 <= report['splits']['validation']['fpr'] <= .05
    assert hasattr(model,'predict_proba')


def test_benign_only_model_uses_only_numeric_production_features():
    model,report=train_benign_only(matrix(),seed=3)
    assert report['model']=='IsolationForest-benign-only'
    assert 'app_proto' not in model.columns
    assert 'label_binary' not in model.columns
    assert 'split' not in model.columns


def test_deterministic_baseline_is_explicitly_reported():
    report=evaluate_deterministic(matrix())
    assert report['model']=='deterministic-behavior-baseline'
    assert 'validation' in report['splits']
