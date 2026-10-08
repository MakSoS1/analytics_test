#!/bin/bash
set -u
R=$(cd "$(dirname "$0")/.." && pwd)
"$R/../.venv/bin/python" -m unittest discover -s "$R/tests" > "$R/reports/tests-final.log" 2>&1
rc=$?
printf '%s\n' "$rc" > "$R/reports/tests-final.rc"
exit "$rc"
