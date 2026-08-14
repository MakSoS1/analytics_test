from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "scripts/install_runner.sh"
SERVICES = ROOT / "scripts/start_services.sh"
RUNNER = ROOT / "scripts/run_scenarios.py"


def test_install_runner_installs_real_protocol_tools():
    text = INSTALL.read_text(encoding="utf-8").lower()
    assert "openssh-server" in text
    assert "samba" in text
    assert "smbclient" in text
    assert "tcpdump" in text
    assert "suricata" in text
    assert "zstd" in text


def test_service_script_binds_ssh_and_smb_inside_namespaces():
    text = SERVICES.read_text(encoding="utf-8")
    assert "ip netns exec ra-linux01" in text
    assert "ip netns exec ra-linux02" in text
    assert "/usr/sbin/sshd" in text
    assert "ip netns exec ra-file01" in text
    assert "smbd" in text
    assert "10.77.0.21" in text
    assert "10.77.0.23" in text


def test_scenario_runner_is_lab_only_and_uses_real_clients():
    text = RUNNER.read_text(encoding="utf-8").lower()
    assert "ip netns exec" in text
    assert "ssh" in text
    assert "smbclient" in text
    assert "10.77.0.0/24" in text
    forbidden = [
        "sliver",
        "mythic",
        "havoc",
        "cobalt strike",
        "metasploit",
        "msfconsole",
        "meterpreter",
        "nmap",
        "masscan",
        "proxychains",
    ]
    assert all(token not in text for token in forbidden)


def test_smb_suspicious_fixture_is_inert_and_never_executes_payload():
    text = RUNNER.read_text(encoding="utf-8").lower()
    assert "inert" in text
    assert "marker" in text
    forbidden_execution = ["chmod +x", "subprocess.run([marker", "./marker", "wine "]
    assert all(token not in text for token in forbidden_execution)
