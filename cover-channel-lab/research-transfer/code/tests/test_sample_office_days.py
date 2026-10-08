import unittest
from sample_office_days import select_session_ids

class OfficeSamplingTests(unittest.TestCase):
    def row(self, uid, **kwargs):
        return dict(global_session_uid=uid, host_key='host', proto='tcp', dest_port=443, pkt_count=12, **kwargs)
    def test_order_independent_and_bounded(self):
        rows=[self.row(str(i)) for i in range(30)]
        a=select_session_ids(rows,7)
        self.assertEqual(a,select_session_ids(list(reversed(rows)),7))
        self.assertEqual(len(a),7)
    def test_session_selected_once_with_segments(self):
        a=self.row('a'); b=self.row('a'); b['pkt_count']=1
        self.assertEqual(select_session_ids([a,b],10),{'a'})
    def test_not_udp_or_nonweb_or_tiny(self):
        a=self.row('a'); a['proto']='udp'
        b=self.row('b'); b['dest_port']=22
        c=self.row('c'); c['pkt_count']=5
        self.assertEqual(select_session_ids([a,b,c],10),set())
    def test_unknown_host_not_given_fake_independence(self):
        a=self.row('a'); a['host_key']=None
        with self.assertRaises(ValueError): select_session_ids([a],10)
    def test_reject_invalid_limit(self):
        with self.assertRaises(ValueError): select_session_ids([],0)
