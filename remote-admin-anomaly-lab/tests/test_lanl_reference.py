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


def test_wls_parser_keeps_network_logon_context_without_synthetic_label():
    lines = ["1000,User1,Comp1,Comp2,Network,Kerberos,Success"]
    frame = parse_wls_lines(lines, max_rows=100)
    assert len(frame) == 1
    assert frame.iloc[0]["logon_type"] == "Network"
    assert "label_binary" not in frame.columns
