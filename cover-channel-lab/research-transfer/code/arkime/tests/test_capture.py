import json, os, subprocess, sys, tempfile, time, unittest, uuid
from pathlib import Path
R=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'bin'));sys.path.insert(0,str(R/'tests'))
from pipeline import OpenSearch,reduce_fragments
from fixtures import long_session,reused
API=OpenSearch()
def capture(files,node,extra=None):
    binary=os.environ.get('ARKIME_TEST_BINARY',str(R/'downloads/arkime-6.8.0/capture/capture'))
    tag='test-'+uuid.uuid4().hex
    args=[binary,'-c',str(R/'config/office.ini'),'-n',node,'-t',tag,'--host','localhost',*(extra or []),*files]
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180)
    if p.returncode:raise AssertionError('capture failed: '+p.stdout[-2000:])
    API.call('POST','/office_arkime_sessions3-*/_refresh')
    return list(API.hits('office_arkime_sessions3-*',{'term':{'tags':tag}}))

class CaptureTests(unittest.TestCase):
    def test_long_session_survives_121_pcap_boundaries(self):
        root=R/'tests/generated/long'
        if not (root/'expected.json').exists():long_session(root)
        expected=json.loads((root/'expected.json').read_text())
        split=capture(['-F',str(root/'files.txt')],'test-long-split')
        whole=capture(['-r',str(root/'whole.pcap')],'test-long-whole')
        roots=lambda hits:{h['_source'].get('rootId') or h['_id'] for h in hits}
        self.assertEqual(len(roots(split)),1)
        self.assertEqual(len(roots(whole)),1)
        rs=reduce_fragments(h['_source'] for h in split);rw=reduce_fragments(h['_source'] for h in whole)
        self.assertEqual(rs['packets'],expected['packets'])
        self.assertEqual(rs['duration_ms'],1200001)
        self.assertGreater(rs.pop("fragments"),rw.pop("fragments"));self.assertEqual(rs,rw)
    def test_one_direction_tcp_reused_after_70s_is_two_instances(self):
        with tempfile.TemporaryDirectory() as d:
            hits=capture(['-r',str(reused(d))],'test-timeout')
        self.assertEqual(len({h['_source'].get('rootId') or h['_id'] for h in hits}),2)
if __name__=='__main__':unittest.main()
