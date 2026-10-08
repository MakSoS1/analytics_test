import unittest
import numpy as np
import pandas as pd

from natural_traffic.office_feature_baseline import (
    fit_numeric_office_copula, numeric_feature_columns, office_feature_baseline,
)


class OfficeFeatureBaselineTests(unittest.TestCase):
    def test_deterministic_sampling_does_not_carry_identifiers(self):
        rng=np.random.default_rng(4)
        n=120
        frame=pd.DataFrame({
            "bytes":rng.lognormal(size=n)*250,
            "pkts":rng.integers(2,40,size=n),
            "host_key":[f"private-{i}" for i in range(n)],
        })
        model=fit_numeric_office_copula(frame,["bytes","pkts"])
        left=model.sample(50,seed=17)
        right=model.sample(50,seed=17)
        pd.testing.assert_frame_equal(left,right)
        self.assertEqual(list(left),["bytes","pkts"])
        self.assertTrue(np.array_equal(left["pkts"].to_numpy(),np.rint(left["pkts"].to_numpy())))

    def test_missingness_and_constant_columns_are_supported(self):
        frame=pd.DataFrame({
            "x":[None if i%7==0 else i for i in range(120)],
            "constant":[0]*120,
        })
        model=fit_numeric_office_copula(frame,["x","constant"])
        sampled=model.sample(200,seed=9)
        self.assertTrue(sampled["x"].isna().any())
        self.assertTrue((sampled["constant"]==0).all())

    def test_declared_numeric_features_only(self):
        frame=pd.DataFrame({
            "x":[1,2],
            "url":["anon_x","anon_y"],
            "label":[0,1],
            "flow_id":["abc","def"],
        })
        dictionary=[
            {"column":"x","kind":"feature"},
            {"column":"url","kind":"feature"},
            {"column":"label","kind":"label"},
            {"column":"flow_id","kind":"metadata"},
        ]
        self.assertEqual(numeric_feature_columns(frame,dictionary),["x"])

    def test_report_excludes_host_ids_generated_rows_and_false_pass(self):
        n=160
        frame=pd.DataFrame({
            "host_key":[f"host-{i}" for i in range(n)],
            "ip_protocol":[6]*n,
            "destination_port":[443]*n,
            "pkt_count":np.arange(n,dtype=float)%20 + 4,
            "up_bytes":np.arange(n,dtype=float)*3 + 200,
        })
        dictionary=[{"column":"pkt_count","kind":"feature"},
                    {"column":"up_bytes","kind":"feature"}]
        report=office_feature_baseline(
            frame,dictionary,seed=99,bootstrap_reps=3,max_evaluation_rows=80
        )
        self.assertEqual(report["status"],"evaluated")
        self.assertEqual(report["numeric_features"],2)
        self.assertIn("office_to_office_grouped_negative_control", report)
        self.assertIn("max_auc", report["office_to_office_grouped_negative_control"])

        self.assertFalse(report["policy"]["packet_level_fidelity"])
        self.assertFalse(report["policy"]["training_eligible"])
        self.assertFalse(report["policy"]["production_ready"])
        self.assertNotIn("generated_rows",report)
        self.assertNotIn("host-0",str(report))
        self.assertNotIn("host-159",str(report))


if __name__=="__main__":
    unittest.main()