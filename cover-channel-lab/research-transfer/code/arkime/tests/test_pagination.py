import unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"bin"))
from pipeline import OpenSearch
class Pagination(unittest.TestCase):
    def test_real_snapshot_multiple_pages_no_duplicates(self):
        api=OpenSearch();query={"prefix":{"tags":"test-"}}
        expected=api.call("POST","/office_arkime_sessions3-*/_count",{"query":query})["count"]
        hits=list(api.hits("office_arkime_sessions3-*",query,size=3))
        self.assertGreater(expected,3)
        self.assertEqual(len(hits),expected)
        self.assertEqual(len({(x["_index"],x["_id"]) for x in hits}),expected)
