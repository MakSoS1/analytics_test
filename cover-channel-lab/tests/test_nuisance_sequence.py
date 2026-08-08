from coverlab.nuisance import infer
from coverlab.sequence_campaign import PHASES
from coverlab.scenarios import select


def test_stage_nuisance_matches_orchestrator_formulas():
    core_len = len(select("core"))

    a = infer("a-00-00000-4-1")
    assert a["transform_chain"] == ["zlib_base64"]
    assert a["timing_profile"] == "fixed"
    assert a["payload_size_class"] == "tiny"

    cfg = min(215, core_len * 2 + 17)
    b = infer(f"b-{cfg:03d}-00")
    transforms = ["raw_utf8", "base64", "base64url", "hex", "zlib_base64", "semantic_uuid"]
    timings = ["fixed", "low_jitter", "medium_jitter", "burst"]
    sizes = ["tiny", "small", "medium", "large"]
    assert b["transform_chain"] == [transforms[(cfg // core_len) % 6]]
    assert b["timing_profile"] == timings[(cfg // 7) % 4]
    assert b["payload_size_class"] == sizes[(cfg // 13) % 4]

    c = infer("c-17-03")
    assert c["transform_chain"] == [transforms[17 % 6]]
    assert c["timing_profile"] == timings[17 % 4]
    assert c["payload_size_class"] == sizes[17 % 4]

    f = infer("f-017-03")
    assert f["transform_chain"] == [transforms[(17 + 3) % 6]]
    assert f["timing_profile"] == timings[(17 + 3) % 4]
    assert f["payload_size_class"] == sizes[(17 + 3) % 4]

    g = infer("g-017-03-2")
    assert g["transform_chain"] == [transforms[(17 + 3) % 6]]
    assert g["timing_profile"] == timings[(17 + 3) % 4]
    assert g["payload_size_class"] == sizes[(17 + 3) % 4]

    d = infer("d-12-00137")
    assert d["transform_chain"] == [transforms[(12 + 137) % 6]]
    assert d["timing_profile"] == timings[(12 + 137) % 4]
    assert d["payload_size_class"] == sizes[(12 + 137) % 4]


def test_sequence_profile_is_exactly_sixty_wire_transactions():
    names = [name for name, _ in PHASES]
    assert len(PHASES) == 10
    assert len(PHASES) * 6 == 60
    for required in {
        "registration",
        "heartbeat",
        "noop_poll",
        "command_poll",
        "result_upload",
        "retry_backoff",
        "reconnect",
        "sleep_change",
    }:
        assert required in names
