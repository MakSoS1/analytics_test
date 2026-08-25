from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "dpi-max100" / "rules" / "dpi_max100.rules"
INVENTORY = ROOT / "dpi-max100" / "inventory.json"

EXPECTED_SOURCE_LABELS = {
    "MEK-60870-5-104",
    "bgp-igp-open-adv-custom",
    "bt-dht",
    "bt-enterprise",
    "dns",
    "exchange-outlook",
    "facebook-ios-chat-session",
    "ftp",
    "google-mail",
    "http",
    "imapv4",
    "ldap",
    "microsoft-azure-signup",
    "microsoft-update",
    "mqtt",
    "netflix-get",
    "netflix-player",
    "ntpv4",
    "opc",
    "openvpn-ixia",
    "pop3",
    "postgresql",
    "radius",
    "rdp",
    "rtsp",
    "sap",
    "sip",
    "skype",
    "snmp",
    "syslog",
    "teamviewer",
    "telnet",
    "tls",
    "webex",
    "youtube",
    "quic",
    "stun",
    "dtls",
    "ssh",
}


def active_rules() -> list[str]:
    assert RULES.exists(), f"missing production ruleset: {RULES.relative_to(ROOT)}"
    result: list[str] = []
    for raw in RULES.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("alert ", "pass ", "drop ", "reject ")):
            result.append(line)
    return result


def load_inventory() -> dict:
    assert INVENTORY.exists(), f"missing inventory: {INVENTORY.relative_to(ROOT)}"
    return json.loads(INVENTORY.read_text(encoding="utf-8"))


def test_inventory_has_exactly_the_39_historical_labels() -> None:
    inventory = load_inventory()
    source_labels = inventory["source_labels"]
    assert len(source_labels) == 39
    labels = {item["label"] for item in source_labels}
    assert labels == EXPECTED_SOURCE_LABELS
    assert all(item.get("detector") for item in source_labels)


def test_ruleset_is_bounded_and_sids_are_unique_local_ids() -> None:
    rules = active_rules()
    assert 1 <= len(rules) <= 100
    sids = []
    for rule in rules:
        match = re.search(r"(?:^|;)\s*sid:(\d+)\s*;", rule)
        assert match, f"rule without sid: {rule}"
        sid = int(match.group(1))
        assert 9_500_001 <= sid <= 9_500_999, f"sid outside local DPI range: {sid}"
        sids.append(sid)
    assert len(sids) == len(set(sids)), "duplicate SID found"


def test_every_inventory_detector_has_an_alerting_rule() -> None:
    inventory = load_inventory()
    detectors = {item["detector"] for item in inventory["source_labels"]}
    rule_text = "\n".join(active_rules())
    for detector in detectors:
        assert f'DPI|{detector}|' in rule_text, f"detector has no rule: {detector}"


def test_messages_use_machine_readable_protocol_or_service_kind() -> None:
    for rule in active_rules():
        if "flowbits:" in rule and "noalert" in rule:
            continue
        match = re.search(r'msg:"(DPI\|[^"|]+\|(protocol|service))";', rule)
        assert match, f"non-standard DPI message: {rule}"


def test_rules_do_not_leak_lab_specific_addresses_dates_or_weak_tls_prefixes() -> None:
    rules = active_rules()
    forbidden_literals = ("10.1.", "192.168.", "2025-", "2026-", "NSI-")
    for rule in rules:
        for forbidden in forbidden_literals:
            assert forbidden not in rule, f"lab-specific literal {forbidden!r} in rule"
        if "|16 03" in rule or "|17 03" in rule:
            assert "|service" not in rule, "service detector must not use generic TLS record bytes"
