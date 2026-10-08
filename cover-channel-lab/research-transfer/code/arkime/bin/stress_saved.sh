#!/bin/bash
set -u
R=$(cd "$(dirname "$0")/.." && pwd)
"$R/../.venv/bin/python" - "$R" <<'PY' > "$R/reports/saved-final.log" 2>&1
from pathlib import Path
import sys
r=Path(sys.argv[1]);sys.path.insert(0,str(r/'bin'));from run_local import run;from pipeline import compact
files=sorted((r.parent/'check-pcaps-check10m-20260923T161229Z').glob('*.pcap'))[:4]
assert len(files)==4
print(compact(run(files,r/'reports/saved-final-01')))
PY
rc=$?
printf '%s\n' "$rc" > "$R/reports/saved-final.rc"
exit "$rc"
