import dns.message
import dns.rcode
import dns.rdatatype

from coverlab.stage_m_dns_server import _authoritative_answer


def query(name: str, kind: str = "A"):
    return dns.message.make_query(name, dns.rdatatype.from_text(kind))


def rcode(name: str, kind: str = "A") -> int:
    wire = _authoritative_answer(query(name, kind).to_wire())
    return dns.message.from_wire(wire).rcode()


def test_stage_m_dns_is_synthetic_zone_only():
    assert rcode("x.stage-m.test.") == dns.rcode.NOERROR
    assert rcode("x.example.com.") == dns.rcode.REFUSED
    assert rcode("nx-test.stage-m.test.") == dns.rcode.NXDOMAIN
