import hashlib
import tempfile
import unittest
from pathlib import Path
import struct
from office_injection.source import write_pcap
from office_injection.wire_observation import observe_capture, convert_supported_rows


def frame(proto, payload=b'', ident=42):
    tcp=struct.pack('!HHIIBBHHH',1234,443,100,0,0x50,0x18,1000,0,0)
    udp=struct.pack('!HHHH',1234,53,len(payload)+8,0)
    icmp=struct.pack('!BBHHH',8,0,0,55,12)
    l4={6:tcp,17:udp,1:icmp}[proto]+payload
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,len(l4)+20,ident,0,64,proto,0,b'\x0a\x14\0\x0b',b'\x0a\x14\0\x14')
    return b'\0'*12+b'\x08\0'+ip+l4


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.pcap=self.root/'test.pcap'
        write_pcap(self.pcap,[(10+i*.1,frame(p,b'abc')) for i,p in enumerate((6,17,1))])
        self.campaign={'campaign_id':'a','source_ip':'10.20.0.11','started_at':10.,'ended_at':11.,
                       'capture_sha256':hashlib.sha256(self.pcap.read_bytes()).hexdigest()}

    def test_all_frames_accounted_without_losing_icmp_header(self):
        obs=observe_capture(self.pcap,self.campaign,self.root/'observe')
        self.assertEqual(obs['observed_packets'],3)
        self.assertEqual(obs['packets'][2]['icmp_id'],55)
        self.assertEqual(obs['packets'][2]['icmp_sequence'],12)
        self.assertEqual(obs['packets'][0]['tcp_sequence'],100)
        self.assertEqual(obs['packets'][0]['ipv4_id'],42)
        converted=convert_supported_rows(obs,self.root/'converted')
        self.assertEqual(converted['supported_rows'],2)
        self.assertEqual(converted['separate_observation_rows'],1)
        self.assertEqual(converted['packet_ordinals'],[0,1])

    def test_hash_and_overlap_rejected_before_labels(self):
        with self.assertRaises(ValueError):observe_capture(self.pcap,{**self.campaign,'capture_sha256':'0'*64},self.root/'bad')
        with self.assertRaises(ValueError):observe_capture(self.pcap,[self.campaign,{**self.campaign,'campaign_id':'b'}],self.root/'overlap')

    def test_setup_not_automatically_labelled_positive(self):
        obs=observe_capture(self.pcap,{**self.campaign,'started_at':10.1},self.root/'observe')
        self.assertEqual(obs['packets'][0]['membership_role'],'auxiliary_or_unassigned')
        self.assertIsNone(obs['packets'][0]['campaign_id'])

    def test_retransmission_and_l2_padding_agree_with_existing_sidecar(self):
        import payload_sidecar
        write_pcap(self.pcap,[(10,frame(6,b'abc')+b'\0'*12),(10.1,frame(6,b'abc')+b'\0'*12)])
        self.campaign['capture_sha256']=hashlib.sha256(self.pcap.read_bytes()).hexdigest()
        obs=observe_capture(self.pcap,self.campaign,self.root/'retx')
        self.assertEqual(obs['packets'][0]['tcp_payload_bytes'],3)
        result=convert_supported_rows(obs,self.root/'converted')
        facts=next(payload_sidecar.read_sidecar(Path(result['pay_path'])))
        self.assertEqual(facts['retx_pkts_a2b']+facts['retx_pkts_b2a'],1)
        self.assertEqual(facts['retx_bytes_a2b']+facts['retx_bytes_b2a'],3)


if __name__=='__main__':unittest.main()

class CaptureOrderTests(unittest.TestCase):
    def test_bounded_capture_reordering_keeps_original_ordinals(self):
        from office_injection.cover_source import ordered_frames
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'wire.pcap'
            write_pcap(p,[(10.000005,frame(17)),(10.,frame(17)),(10.1,frame(17))])
            frames,evidence=ordered_frames(p)
            self.assertEqual([i for i,t,f in frames],[1,0,2])
            self.assertLessEqual(evidence['maximum_regression_seconds'],.00001)
            write_pcap(p,[(10.1,frame(17)),(10.,frame(17))])
            with self.assertRaises(ValueError):ordered_frames(p)
