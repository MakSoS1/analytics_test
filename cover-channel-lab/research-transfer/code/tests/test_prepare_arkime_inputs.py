import hashlib,json,struct,tempfile,unittest
from pathlib import Path

class GenericArkimeInputsTests(unittest.TestCase):
    def fixture(self,root,name,base):
        p=root/name
        frames=[(base,b'\0'*60),(base+1234,b'\1'*60)]
        with p.open('wb') as f:
            f.write(struct.pack('<IHHIIII',0xa1b23c4d,2,4,0,0,262144,1))
            for ts,b in frames:
                sec,ns=divmod(ts,10**9);f.write(struct.pack('<IIII',sec,ns,len(b),len(b)));f.write(b)
        return p,frames
    def test_arbitrary_technique_preserves_packet_bytes_and_nanosecond_deltas(self):
        from prepare_arkime_inputs import prepare
        from prepare_arkime_cover import packets
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);a,af=self.fixture(root,'office.pcap',10**9);b,bf=self.fixture(root,'tech.pcap',3*10**9)
            spec={'sources':[{'pcap':a.name,'sha256':hashlib.sha256(a.read_bytes()).hexdigest(),'dataset':'office_background','label_state':'unlabelled_office','label_binary':None}, {'pcap':b.name,'sha256':hashlib.sha256(b.read_bytes()).hexdigest(),'dataset':'generated_activity','technique':'T9999_custom','label_state':'operator_asserted','label_binary':None}]}
            path=root/'sources.json';path.write_text(json.dumps(spec));r=prepare(path,root/'out')
            actual=list(packets(root/'out/source_isolated_mix.pcap'))
            self.assertEqual([x[1] for x in actual],[x[1] for x in af+bf])
            self.assertEqual(actual[1][0]-actual[0][0],1234);self.assertEqual(actual[3][0]-actual[2][0],1234)
            self.assertGreaterEqual(actual[2][0]-actual[1][0],1201*10**9)
            self.assertIsNone(r['sources'][0]['label_binary']);self.assertEqual(r['sources'][1]['technique'],'T9999_custom')
            self.assertFalse(r['production_ready']);self.assertFalse(r['naturalness_established'])
    def test_hash_mismatch_and_duplicate_inputs_refused_before_output_creation(self):
        from prepare_arkime_inputs import prepare
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);a,_=self.fixture(root,'a.pcap',10**9);row={'pcap':a.name,'sha256':'0'*64,'dataset':'office_background','label_state':'unlabelled_office','label_binary':None};spec=root/'sources.json'
            spec.write_text(json.dumps({'sources':[row]}))
            with self.assertRaises(ValueError):prepare(spec,root/'bad')
            self.assertFalse((root/'bad').exists())
            row['sha256']=hashlib.sha256(a.read_bytes()).hexdigest();spec.write_text(json.dumps({'sources':[row,row]}))
            with self.assertRaises(ValueError):prepare(spec,root/'dup')
            self.assertFalse((root/'dup').exists())
    def test_office_cannot_be_silently_declared_benign(self):
        from prepare_arkime_inputs import prepare
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);a,_=self.fixture(root,'a.pcap',10**9);spec=root/'sources.json'
            spec.write_text(json.dumps({'sources':[{'pcap':a.name,'sha256':hashlib.sha256(a.read_bytes()).hexdigest(),'dataset':'office_background','label_state':'unlabelled_office','label_binary':0}]}))
            with self.assertRaises(ValueError):prepare(spec,root/'bad')
