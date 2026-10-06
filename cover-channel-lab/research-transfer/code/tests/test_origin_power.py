import unittest
import numpy as np
import pandas as pd

class OriginPowerTests(unittest.TestCase):
    def test_rare_known_artifact_is_detected_and_all_columns_retained(self):
        from demo.audit_origin_power import score_models
        rng=np.random.default_rng(53);train=pd.DataFrame(rng.normal(size=(1006,3)),columns=['artifact','noise','empty']);test=pd.DataFrame(rng.normal(size=(220,3)),columns=train.columns)
        yt=np.r_[np.zeros(6),np.ones(1000)];yv=np.r_[np.zeros(20),np.ones(200)];train.loc[:5,'artifact']=-50;test.loc[:19,'artifact']=-50;train['empty']=np.nan
        report=score_models(train,yt,test,yv)
        self.assertGreater(report['balanced_extra_trees']['auc'],.95)
        self.assertGreater(report['balanced_logistic']['auc'],.95)
        self.assertEqual(report['feature_order'],list(train.columns))
        self.assertEqual(report['support_status'],'insufficient_generated_train')

    def test_missing_class_abstains_instead_of_reporting_random_auc(self):
        from demo.audit_origin_power import score_models
        x=pd.DataFrame({'x':[1,2,3]});r=score_models(x,[1,1,1],x,[0,0,0])
        self.assertEqual(r['support_status'],'missing_class');self.assertIsNone(r['balanced_extra_trees']['auc'])

class NativeMissingnessTests(unittest.TestCase):
    def test_histogram_model_preserves_missingness_as_observed_source_signal(self):
        from demo.audit_origin_power import score_models
        train=pd.DataFrame({'observed':[np.nan]*20+[0.0]*1000});test=pd.DataFrame({'observed':[np.nan]*20+[0.0]*200})
        r=score_models(train,np.r_[np.zeros(20),np.ones(1000)],test,np.r_[np.zeros(20),np.ones(200)])
        self.assertGreater(r['balanced_hgb']['auc'],.95)
