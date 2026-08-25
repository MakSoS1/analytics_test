from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "dpi-max100" / "rules" / "dpi_max100.rules"


def active_rules() -> list[str]:
    return [
        line.strip()
        for line in RULES.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#") and line.strip().startswith(("alert ", "pass ", "drop ", "reject "))
    ]


def text() -> str:
    return "\n".join(active_rules())


def test_expanded_ruleset_stays_below_200_but_uses_new_budget() -> None:
    rules = active_rules()
    assert 100 <= len(rules) < 200, f"expected 100..199 active rules, got {len(rules)}"


def test_ech_is_detected_as_encryption_state_not_falsely_attributed_service() -> None:
    rules = text()
    assert 'DPI|tls-ech|protocol' in rules
    assert 'content:"|FE 0D|"' in rules
    ech_lines = [line for line in active_rules() if 'DPI|tls-ech|protocol' in line]
    assert ech_lines
    assert all('|service' not in line for line in ech_lines)


def test_upgrade_to_tls_variants_are_covered_before_encryption() -> None:
    rules = text()
    for marker in (
        'AUTH TLS',
        'STARTTLS',
        'STLS',
        '|04 D2 16 2F|',
        '1.3.6.1.4.1.1466.20037',
    ):
        assert marker in rules, f"missing encrypted-upgrade marker {marker}"


def test_major_protocol_families_have_multiple_structural_variants() -> None:
    rules = text()
    minimums = {
        "sip": 6,
        "rtsp": 4,
        "bgp": 5,
        "iec104": 6,
        "radius": 5,
        "openvpn": 8,
        "opc": 4,
        "dtls": 4,
    }
    for detector, minimum in minimums.items():
        count = sum(1 for line in active_rules() if f'DPI|{detector}|protocol' in line or f'DPIHELPER|{detector}|' in line)
        assert count >= minimum, f"{detector}: expected >= {minimum} rules, got {count}"


def test_service_families_include_additional_precise_domains_and_plain_http_host_fallbacks() -> None:
    rules = text()
    for domain in (
        "imap.gmail.com",
        "smtp.gmail.com",
        "download.windowsupdate.com",
        "dl.delivery.mp.microsoft.com",
        "nflxso.net",
        "nflxext.com",
        "youtube-nocookie.com",
        "ciscospark.com",
    ):
        assert domain in rules, f"missing service endpoint family {domain}"
    for detector in ("outlook", "gmail", "microsoft-update", "netflix", "skype", "teamviewer", "webex", "youtube"):
        assert any(f'DPI|{detector}|service' in line and 'http.host' in line for line in active_rules()), detector


def test_no_service_rule_uses_generic_tls_record_bytes_or_only_ports() -> None:
    for rule in active_rules():
        if '|service' not in rule:
            continue
        assert '|16 03' not in rule and '|17 03' not in rule
        # Requiring content/sticky buffers prevents a service label based only on destination port.
        assert any(token in rule for token in ('tls.sni', 'http.host', 'content:', 'pcre:')), rule


def test_local_sids_remain_unique() -> None:
    sids: list[int] = []
    for rule in active_rules():
        match = re.search(r"(?:^|;)\s*sid:(\d+)\s*;", rule)
        assert match, rule
        sids.append(int(match.group(1)))
    assert len(sids) == len(set(sids))
