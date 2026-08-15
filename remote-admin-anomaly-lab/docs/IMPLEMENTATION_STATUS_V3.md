# Remote Admin Anomaly V3 — Final Status

- Dataset release: **READY**
- Research status: **FAIL**
- Scale decision: **STOP_AT_1K**
- HF verified: **True** at `v3/final/run-31885392045`
- GitHub artifact verified: **True**, artifact ID `9247494536`
- Cleanup policy B: **PASS**; deleted Remote Admin runs `797`, deleted HF objects `279`.
- Post-cleanup verification: **PASS**; retained HF payload files `1563`.

## V3 corpus

- 1000 real-wire sessions; 500 benign / 500 suspicious; 250 each SSH/SMB/RDP/VNC.
- 200 exact current-session counterfactual pairs with time matching; discriminative signal is prior history/graph/sequence.
- Session PCAP coverage: `1.0`; campaign PCAP coverage: `1.0`.
- Bronze is browsable: per-session PCAPs, per-campaign PCAPs, full raw chunks and pcap_index; no persisted merged giant PCAP.
- Session mapping coverage: `0.997`; per protocol: `{'rdp': 1.0, 'smb': 0.988, 'ssh': 1.0, 'vnc': 1.0}`.

## Model evidence

```json
{
  "external_holdouts_used_for_training": false,
  "primary_view": "session-primary",
  "schema_version": 3,
  "shortcut_audit": {
    "baselines": {
      "bytes_packets_only": {
        "columns": [
          "session_total_bytes",
          "session_total_packets",
          "session_src_bytes",
          "session_dst_bytes",
          "flow_bytes_mean",
          "flow_bytes_max"
        ],
        "status": "ok",
        "train_rows": 323,
        "validation_pr_auc": 0.49274927121277445,
        "validation_rows": 173
      },
      "current_session_only": {
        "columns": [
          "flow_count",
          "session_duration_s",
          "session_total_bytes",
          "session_total_packets",
          "session_src_bytes",
          "session_dst_bytes",
          "flow_duration_mean",
          "flow_duration_max",
          "flow_bytes_mean",
          "flow_bytes_max",
          "hour_sin",
          "hour_cos",
          "is_weekend"
        ],
        "status": "ok",
        "train_rows": 323,
        "validation_pr_auc": 0.4668488083834658,
        "validation_rows": 173
      },
      "duration_rate_only": {
        "columns": [
          "session_duration_s",
          "flow_duration_mean",
          "flow_duration_max",
          "flow_count"
        ],
        "status": "ok",
        "train_rows": 323,
        "validation_pr_auc": 0.5299716244511707,
        "validation_rows": 173
      },
      "history_only": {
        "columns": [
          "src_distinct_dst_24h_prior",
          "src_distinct_dst_7d_prior",
          "src_distinct_dst_30d_prior",
          "pair_seen_count_prior",
          "time_since_pair_seen_seconds_prior",
          "new_destination_for_source",
          "new_protocol_for_source",
          "src_protocol_diversity_7d_prior",
          "src_new_target_count_1h_prior",
          "src_new_target_count_24h_prior",
          "src_graph_expansion_rate_24h_prior",
          "recent_protocol_switch_count_prior",
          "recent_remote_admin_attempt_count_prior"
        ],
        "status": "ok",
        "train_rows": 323,
        "validation_pr_auc": 0.44334163319963,
        "validation_rows": 173
      },
      "time_only": {
        "columns": [
          "hour_sin",
          "hour_cos",
          "is_weekend"
        ],
        "status": "ok",
        "train_rows": 323,
        "validation_pr_auc": 0.41055230241055063,
        "validation_rows": 173
      }
    },
    "best_nuisance_pr_auc": 0.5299716244511707,
    "current_session_only_pr_auc": 0.4668488083834658,
    "full_model_pr_auc": 0.42500245440557627,
    "full_over_best_nuisance_margin": -0.10496917004559447,
    "full_over_current_session_margin": -0.04184635397788955,
    "policy": "V3 full session model must beat current-session and all nuisance-only views; history-only is reported as intended-signal ablation",
    "schema_version": 3,
    "time_only_pr_auc": 0.41055230241055063
  },
  "training_environment": "linux_v3_only",
  "views": {
    "campaign-primary": {
      "challenge_pr_auc": 0.5177531974953729,
      "test_pr_auc": 0.5349278480734634,
      "validation_pr_auc": 0.4805202660899723
    },
    "flow-baseline": {
      "challenge_pr_auc": 0.48780539484770763,
      "test_pr_auc": 0.38389214832444873,
      "validation_pr_auc": 0.3879008421312685
    },
    "session-primary": {
      "challenge_pr_auc": 0.5229509654776262,
      "test_pr_auc": 0.5166915947724884,
      "validation_pr_auc": 0.42500245440557627
    }
  }
}
```

Dataset technical completeness is independent of scientific promotion. This V3 remains STOP_AT_1K unless the committed research decision says ALLOW_4K.
