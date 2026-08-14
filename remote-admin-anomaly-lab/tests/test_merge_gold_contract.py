from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MERGE=ROOT/'scripts/merge_gold.py'


def test_global_merge_reassigns_splits_after_all_shards_exist():
    text=MERGE.read_text(encoding='utf-8')
    assert "assign_grouped_splits(sessions" in text
    assert "audit_leakage(sessions" in text
    assert "global_split_report.json" in text
    assert "global_leakage_checks.json" in text
    assert "coverage<.95" in text


def test_global_model_matrix_does_not_reuse_per_shard_split_column():
    text=MERGE.read_text(encoding='utf-8')
    assert "model_matrix.parquet" in text
    assert "matrix['split']=aligned['split']" in text
    assert "gold/'splits.parquet'" in text
