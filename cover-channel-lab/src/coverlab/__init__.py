"""Safe network-only covert-channel traffic generation lab."""

__version__ = "1.1.0"

# Keep the original source-plan catalog readable while extending it with the
# transport-future challenge corpus. Importing the package happens before any
# submodule imports, so existing `from .scenarios import SCENARIOS/BY_ID`
# consumers automatically receive the extended immutable tuple/map.
from . import scenarios as _base_scenarios
from .scenarios_extra import EXTRA_SCENARIOS as _extra_scenarios

if not any(s.scenario_id == "CC_H3_01" for s in _base_scenarios.SCENARIOS):
    _base_scenarios.SCENARIOS = _base_scenarios.SCENARIOS + _extra_scenarios
    _base_scenarios.BY_ID.update({s.scenario_id: s for s in _extra_scenarios})
