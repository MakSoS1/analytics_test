import pandas as pd

from adminlab.reference_validation import compare_reference_distributions


def test_reference_validation_reports_ks_wasserstein_and_ci():
    generated = pd.DataFrame({"duration": [1, 2, 3, 4, 5], "bytes_total": [10, 20, 30, 40, 50]})
    reference = pd.DataFrame({"duration": [1, 2, 2, 4, 6], "bytes_total": [11, 19, 29, 42, 55]})
    report = compare_reference_distributions(generated, reference, columns=["duration", "bytes_total"], bootstrap=100, seed=1)
    assert report["reference_available"] is True
    assert set(report["features"]) == {"duration", "bytes_total"}
    for item in report["features"].values():
        assert "ks_statistic" in item
        assert "ks_pvalue" in item
        assert "wasserstein" in item
        assert len(item["mean_difference_ci95"]) == 2


def test_reference_validation_explicitly_reports_missing_reference():
    report = compare_reference_distributions(pd.DataFrame({"x": [1, 2]}), None, columns=["x"])
    assert report["reference_available"] is False
    assert report["status"] == "not_evaluated"
