import sys,tempfile,unittest,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
from pipeline import Store,export_tables
class Fields(unittest.TestCase):
 def test_session_header_union_count_not_fragment_count_sum(self):
  import pyarrow.parquet as pq
  with tempfile.TemporaryDirectory() as d:
   s=Store(Path(d)/'db')
   for n,headers in enumerate([['host'],['host','cookie','x-custom']]):
    s.put_fragment({'_index':'x','_id':str(n),'_source':{'node':'n','office':{'instance':1,'seq':n+1,'final':n==1},'http':{'requestHeader':headers,'requestHeaderCnt':len(headers)}}})
   export_tables(s,Path(d)/'out')
   rows=pq.read_table(Path(d)/'out/arkime_session_field_values.parquet').to_pylist()
   union={json.loads(x['value_json']) for x in rows if x['field_path']=='http.requestHeader'}
   self.assertEqual(union,{'host','cookie','x-custom'})
   count=[json.loads(x['value_json']) for x in rows if x['field_path']=='http.requestHeaderCnt' and x['aggregation']=='unique_count']
   self.assertEqual(count,[3])
 def test_structured_certificate_arrays_preserve_each_object(self):
  with tempfile.TemporaryDirectory() as d:
   s=Store(Path(d)/'db');cert={'subject':'fixture','alt':['a','b']}
   s.put_fragment({'_index':'x','_id':'1','_source':{'tls':{'cert':[cert]}}})
   value=s.db.execute("select value_json from feature_atoms where field_path='tls.cert'").fetchone()[0]
   self.assertEqual(json.loads(value),cert)

 def test_tcp_and_payload_delta_counters_sum_across_checkpoints(self):
  import pyarrow.parquet as pq
  with tempfile.TemporaryDirectory() as d:
   s=Store(Path(d)/'db')
   for n in range(2):s.put_fragment({'_index':'x','_id':str(n),'_source':{'node':'n','office':{'instance':1,'seq':n+1,'final':n==1},'tcpflags':{'ack':1},'client':{'bytes':10},'totDataBytes':10}})
   export_tables(s,Path(d)/'out')
   rows=pq.read_table(Path(d)/'out/arkime_session_field_values.parquet').to_pylist()
   sums={x['field_path']:json.loads(x['value_json']) for x in rows if x['aggregation']=='sum'}
   self.assertEqual(sums['tcpflags.ack'],2);self.assertEqual(sums['client.bytes'],20);self.assertEqual(sums['totDataBytes'],20)
