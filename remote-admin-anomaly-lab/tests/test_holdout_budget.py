from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd

from adminlab.splits import assign_grouped_splits


def test_source_host_holdout_never_falls_back_above_eight_percent_group_impact():
    base=datetime(2026,8,1,tzinfo=timezone.utc)
    rows=[]
    # Every whole-host holdout necessarily consumes 20% of the corpus because
    # each source owns four complete campaign groups. The declared max budget is
    # 8%, so the correct result is to skip this holdout dimension rather than
    # silently convert one fifth of the corpus into challenge data.
    for campaign in range(20):
        src=f"src-{campaign % 5}"
        for offset in range(5):
            i=campaign*5+offset
            rows.append({
                "session_id":f"s-{i:03d}",
                "campaign_id":f"c-{campaign:02d}",
                "pair_id":"",
                "src_host_id":src,
                "dst_host_id":f"dst-{(campaign+offset)%11}",
                "start_ts":(base+timedelta(hours=i)).isoformat(),
                "label_binary":campaign % 2,
            })
    sessions=pd.DataFrame(rows)

    splits,report=assign_grouped_splits(sessions,seed=20260814)

    assert report["heldout_src_hosts"] == [], report
    assert report["holdout_availability"]["unseen_src_host"] == "skipped_no_candidate_within_impact_budget"
    # Temporal and other possible holdouts are independent; specifically there
    # must be no source-host challenge reason when the budget cannot be met.
    assert not splits["challenge_reason"].fillna("").str.contains("unseen_src_host").any()

# Regression target: never violate a declared holdout budget just to force coverage.
