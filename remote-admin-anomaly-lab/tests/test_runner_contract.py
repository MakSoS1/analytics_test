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
    assert 'ip netns exec "$ns" /usr/sbin/sshd' in text
    assert 'ip netns exec "$ns" /usr/sbin/smbd' in text
    for expected in (
        "start_ssh ra-linux01 10.77.0.21 linux01",
        "start_ssh ra-linux02 10.77.0.22 linux02",
        "start_ssh ra-linux03 10.77.0.60 linux03",
        "start_ssh ra-linux04 10.77.0.61 linux04",
        "start_samba ra-file01 10.77.0.23 file01",
        "start_samba ra-file02 10.77.0.62 file02",
        "start_samba ra-file03 10.77.0.63 file03",
        "start_samba ra-file04 10.77.0.64 file04",
    ):
        assert expected in text
    assert "AdminlabSMB-2026!" in text
    assert "authenticated SMB fixture unexpectedly allowed guest access" in text


def test_service_process_groups_are_isolated_and_cleanup_is_narrow():
    text = SERVICES.read_text(encoding="utf-8")
    assert "setsid ip netns exec" in text
    assert 'kill -TERM -- "-$pgid"' in text
    assert 'kill -KILL -- "-$pgid"' in text
    assert 'kill -0 -- "-$pgid"' in text
    assert 'for pid in $(ip netns pids' not in text


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
