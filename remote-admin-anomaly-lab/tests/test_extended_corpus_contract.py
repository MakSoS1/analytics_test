from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/run_scenarios_extended.py"
CAPTURE = ROOT / "scripts/capture_shard_extended.sh"
SERVICES = ROOT / "scripts/start_extended_services.py"
WIRE = ROOT / "src/adminlab/extended_wire.py"


def test_train_protocols_exclude_partial_dcom_and_winrm():
    text = RUNNER.read_text(encoding="utf-8")
    assert 'TRAIN_PROTOCOLS = {"ssh", "smb", "rdp", "vnc"}' in text
    assert 'CHALLENGE_PROTOCOLS = TRAIN_PROTOCOLS | {"winrm"}' in text
    assert 'dcerpc_train_included": False' in text
    assert 'args.stage != "H"' in text


def test_extended_capture_retains_full_pcap_and_never_drops_dce_rpc_into_train():
    text = CAPTURE.read_text(encoding="utf-8")
    assert "tcpdump -i br-adminlab" in text
    assert ".pcap.zst" in text
    assert "start_extended_services.py" in text
    assert "run_scenarios_extended.py" in text
    assert 'if [[ "$STAGE" == "H" ]]' in text
    assert "dcerpc_train_included" in text


def test_extended_services_are_bound_only_inside_lab_namespaces():
    text = SERVICES.read_text(encoding="utf-8")
    assert '"ra-vnc01"' in text
    assert '"ra-rdp01"' in text
    assert '"ra-mgmt01"' in text
    assert "10.77.0.27" in text
    assert "5985" in text
    assert "wait_listener" in text


def test_extended_wire_adapters_are_bounded_and_non_executing():
    text = WIRE.read_text(encoding="utf-8").lower()
    assert "run_rdp_session" in text
    assert "run_vnc_session" in text
    assert "run_winrm_session" in text
    assert "auth-only" in text
    assert "identifyresponse" in text
    forbidden = ["sliver", "mythic", "havoc", "cobalt strike", "meterpreter", "powershell -enc", "cmd.exe /c"]
    assert all(token not in text for token in forbidden)
