from adminlab.lanl_reference import parse_netflow_lines, parse_wls_lines


def test_lanl_filter_keeps_remote_admin_well_known_port():
    lines = ["761,4434,Comp1,Comp2,6,Port12597,22,10,8,1000,900"]
    frame = parse_netflow_lines(lines, {22, 135, 445, 3389, 5985, 5986}, max_rows=100)
    assert len(frame) == 1
    assert int(frame.iloc[0]["dst_port"]) == 22
    assert "label_binary" not in frame.columns


def test_lanl_filter_accepts_remote_admin_source_port_and_normalizes_port_prefix():
    lines = ["762,5,Comp2,Comp1,6,Port445,Port55555,4,3,200,100"]
    frame = parse_netflow_lines(lines, {445}, max_rows=100)
    assert len(frame) == 1
    assert int(frame.iloc[0]["src_port"]) == 445


def test_wls_parser_keeps_normalized_network_logon_context_without_synthetic_label():
    lines = ["1000,User1,Comp1,Comp2,Network,Kerberos,Success"]
    frame = parse_wls_lines(lines, max_rows=100)
    assert len(frame) == 1
    assert frame.iloc[0]["logon_type"] == "Network"
    assert "label_binary" not in frame.columns


def test_wls_parser_accepts_official_lanl_jsonl_network_logon():
    lines = [
        '{"EventID":4624,"UserName":"User380010","LogonID":"0x9f17415","DomainName":"Domain002","LogonTypeDescription":"Network","Computer":"Comp966305","Source":"Comp123","AuthenticationPackage":"Kerberos","Status":"0x0","Time":2}'
    ]
    frame = parse_wls_lines(lines, max_rows=100)
    assert len(frame) == 1
    row = frame.iloc[0]
    assert int(row["event_id"]) == 4624
    assert row["src_device"] == "Comp123"
    assert row["dst_device"] == "Comp966305"
    assert row["logon_type"] == "Network"
    assert row["status"] == "0x0"
    assert "label_binary" not in frame.columns


def test_wls_parser_filters_non_network_logon_json():
    lines = [
        '{"EventID":4624,"UserName":"User1","LogonTypeDescription":"Interactive","Computer":"Comp1","AuthenticationPackage":"Negotiate","Status":"0x0","Time":3}'
    ]
    frame = parse_wls_lines(lines, max_rows=100)
    assert frame.empty


def test_wls_parser_accepts_rocketgraph_auth_event_csv_mirror():
    # Rocketgraph xGT AuthEvents order from its published LANL mirror schema:
    # epoch_time,event_id,log_host,logon_type,logon_type_description,username,
    # domain_name,logon_id,subject_username,subject_domain_name,subject_logon_id,
    # status,source,service_name,destination,authentication_package,
    # failure_reason,process_name,process_id,parent_process_name,parent_process_id
    lines = [
        '1001,4624,Comp9,3,Network,User1,Domain1,123,Subject1,Domain1,99,0x0,Comp1,cifs,Comp9,Kerberos,,C:\\Windows\\System32\\svchost.exe,321,,0'
    ]
    frame = parse_wls_lines(lines, max_rows=100)
    assert len(frame) == 1
    row = frame.iloc[0]
    assert int(row["event_id"]) == 4624
    assert row["src_device"] == "Comp1"
    assert row["dst_device"] == "Comp9"
    assert row["logon_type"] == "Network"
    assert row["auth_package"] == "Kerberos"
