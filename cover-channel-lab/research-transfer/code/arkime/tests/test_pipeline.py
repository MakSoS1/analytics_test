import sys, tempfile, unittest, json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"bin"))
try:
    from pipeline import Store, flatten, reduce_fragments
except ImportError:
    Store=flatten=reduce_fragments=None

class PipelineTests(unittest.TestCase):
    def test_transaction_replay_is_idempotent(self):
        self.assertIsNotNone(Store, "durable local store missing")
        with tempfile.TemporaryDirectory() as d:
            s=Store(Path(d)/"state.db")
            hit={"_index":"sessions3-260101","_id":"x","_source":{"rootId":"r","source":{"ip":"1.2.3.4","packets":2},"destination":{"packets":3},"network":{"packets":5}}}
            self.assertEqual(s.put_fragment(hit),True)
            self.assertEqual(s.put_fragment(hit),False)
            self.assertEqual(s.db.execute("select count(*) from fragments").fetchone()[0],1)
            s.close()
    def test_nested_fields_and_struct_arrays_are_lossless(self):
        self.assertIsNotNone(flatten,"all-field extraction missing")
        d={"tls":{"cert":[{"subject":"one","alt":["two"]}]},"dns":{"host":["a","b"]},"odd.new":False}
        fields=dict(flatten(d))
        self.assertEqual(fields["tls.cert"],d["tls"]["cert"])
        self.assertEqual(fields["dns.host"],["a","b"])
        self.assertEqual(fields["odd.new"],False)
    def test_long_session_fragment_counters_not_averaged(self):
        self.assertIsNotNone(reduce_fragments,"whole-session reducer missing")
        fs=[{"firstPacket":1000,"lastPacket":2000,"network":{"packets":4,"bytes":200},"source":{"packets":3,"bytes":150},"destination":{"packets":1,"bytes":50},"protocol":["tcp","tls"]},{"firstPacket":1000,"lastPacket":8000,"network":{"packets":6,"bytes":300},"source":{"packets":4,"bytes":200},"destination":{"packets":2,"bytes":100},"protocol":["tcp","http"]}]
        r=reduce_fragments(fs)
        self.assertEqual(r["packets"],10)
        self.assertEqual(r["bytes"],500)
        self.assertEqual(r["duration_ms"],7000)
        self.assertEqual(r["src_packets"],7)
    def test_failed_chunk_is_never_deletable(self):
        self.assertIsNotNone(Store)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"a.pcap";p.write_bytes(b"abc")
            s=Store(Path(d)/"state.db")
            s.register_chunk(p,"abc",3)
            self.assertFalse(s.can_delete(p))
            s.commit_chunk(p,3,True,False)
            self.assertFalse(s.can_delete(p))
            s.commit_chunk(p,3,True,True)
            self.assertTrue(s.can_delete(p))
            s.close()
    def test_restart_does_not_claim_complete(self):
        self.assertIsNotNone(Store)
        with tempfile.TemporaryDirectory() as d:
            s=Store(Path(d)/"state.db")
            self.assertEqual(s.new_generation(),1)
            self.assertEqual(s.new_generation(),2)
            self.assertEqual(s.generation,2)
            s.close()
if __name__=="__main__":unittest.main()
