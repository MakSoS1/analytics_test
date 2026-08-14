from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/setup_topology.sh"


def test_topology_script_is_fail_closed_and_idempotent():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "set -euo pipefail" in text
    assert "up)" in text
    assert "verify)" in text
    assert "down)" in text
    assert "external_routing" in text


def test_topology_verify_rejects_default_routes():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "ip route show default" in text
    assert "unexpected default route" in text


def test_topology_does_not_enable_nat_or_forwarding():
    text = SCRIPT.read_text(encoding="utf-8").lower()
    forbidden = ["masquerade", "snat", "dnat", "net.ipv4.ip_forward=1", "--dport 22 -j accept"]
    assert all(token not in text for token in forbidden)
