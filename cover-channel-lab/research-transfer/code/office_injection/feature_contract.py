"""Pinned feature admission shared by challenge export and dataset audits."""
import json
from pathlib import Path
import office_dictionary as dictionary

_SCHEMA=Path(__file__).resolve().parents[1]/'office_sessions.schema.json'
_PINNED=frozenset(name for name,_ in json.loads(_SCHEMA.read_text())['columns'])

def is_feature(name):
    # Unknown annotations cannot become features just because their values are
    # numeric. Semantic names such as dns_label_entropy remain valid features.
    return (name in _PINNED and dictionary.entry(name)['kind']=='feature'
            and not name.startswith(('label_','y_','schema_','injection_','campaign_','source_'))
            and not name.endswith(('schema_version','_uid')))
