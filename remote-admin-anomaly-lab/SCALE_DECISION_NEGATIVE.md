# Remote Admin Anomaly V1 — Scale Decision

- Decision: **STOP_AT_1K**
- Allow scale: **false**
- Next sessions: **0**
- Reason: `MODEL_QUALITY_REJECTED_AND_LEARNING_CURVE_SATURATED`
- Validation PR-AUC: `0.5074707204051365`
- Test PR-AUC: `0.5137590769069873`
- Challenge PR-AUC: `0.42228392985541374`
- Last grouped learning-curve delta PR-AUC: `-0.013807526011478721`
- Recommendation: `prefer_diversity_or_holdout_analysis`

The next experiment must change the **feature/data hypothesis**, not merely multiply rows from the same generator distribution.
