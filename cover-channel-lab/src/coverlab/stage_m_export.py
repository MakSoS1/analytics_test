from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_m_catalog import FAMILY_SPECS, build_split_summary, iter_campaigns, validate_plan


def main():
    ap=argparse.ArgumentParser();ap.add_argument("--out",required=True);a=ap.parse_args();out=Path(a.out);out.mkdir(parents=True,exist_ok=True)
    plans=list(iter_campaigns());validation=validate_plan(plans);splits=build_split_summary(plans)
    if not validation["passed"]: raise SystemExit(json.dumps(validation))
    (out/"catalog.jsonl").write_text("".join(json.dumps(x.to_dict(),separators=(",",":"),sort_keys=True)+"\n" for x in plans))
    (out/"split_index.jsonl").write_text("".join(json.dumps({"campaign_id":x.campaign_id,"family_id":x.family_id,"primary_split":x.primary_split,"implementation_id":x.implementation_id,"network_profile":x.network_profile,"payload_style":x.payload_style,"nominal_interval_seconds":x.nominal_interval_seconds},separators=(",",":"),sort_keys=True)+"\n" for x in plans))
    (out/"leave_one_out.json").write_text(json.dumps(splits,indent=2,sort_keys=True)+"\n")
    (out/"validation.json").write_text(json.dumps(validation,indent=2,sort_keys=True)+"\n")
    (out/"family_summary.json").write_text(json.dumps({"positive_only":True,"total_campaigns":len(plans),"families":[{"family_id":s.family_id,"protocol":s.protocol,"core":s.core_count,"diversity":s.diversity_count,"holdout":s.holdout_count,"total":s.total_count,"implementations":list(s.implementations),"primary_holdout_impl":s.primary_holdout_impl} for s in FAMILY_SPECS]},indent=2,sort_keys=True)+"\n")
    print(json.dumps({"out":str(out),"campaigns":len(plans),"families":len(FAMILY_SPECS),"positive_only":True}))

if __name__=="__main__":main()
