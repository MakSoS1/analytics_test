"""Lossless local Arkime SPI store; no Cosmolake publishing."""
import argparse, hashlib, json, os, sqlite3, uuid, shutil, contextlib
from pathlib import Path
import urllib.request

def compact(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)
def flatten(v,prefix=''):
    for k,x in v.items():
        path=f'{prefix}.{k}' if prefix else k
        if isinstance(x,dict) and x:yield from flatten(x,path)
        else:yield path,x

def value_at(d,path,default=0):
    for p in path.split('.'):
        if not isinstance(d,dict):return default
        d=d.get(p,default)
    return d

# Native db.c exports these as per-checkpoint deltas; session.c resets them.
SUM_FIELDS={'network.packets','network.bytes','source.packets','destination.packets','source.bytes','destination.bytes','client.bytes','server.bytes','totDataBytes'}|{'tcpflags.'+k for k in ('syn','syn-ack','ack','psh','fin','rst','urg','ece','cwr','ae','srcZero','dstZero')}

def reduce_fragments(fragments):
    out=dict(fragments=0,packets=0,bytes=0,src_packets=0,dst_packets=0,src_bytes=0,dst_bytes=0,first_packet_ms=None,last_packet_ms=None,duration_ms=0,entropy_src=None,entropy_dst=None,scalar_sums={})
    latest=-1
    for f in fragments:
        out['fragments']+=1
        seq=value_at(f,'office.seq',0)
        if seq>=latest and 'officeEntropy' in f:
            latest=seq;out['entropy_src']=value_at(f,'officeEntropy.src',None);out['entropy_dst']=value_at(f,'officeEntropy.dst',None)
        for target,path in [('packets','network.packets'),('bytes','network.bytes'),('src_packets','source.packets'),('dst_packets','destination.packets'),('src_bytes','source.bytes'),('dst_bytes','destination.bytes')]:out[target]+=int(value_at(f,path,0) or 0)
        for path,value in flatten(f):
            if path in SUM_FIELDS and isinstance(value,int) and not isinstance(value,bool):out['scalar_sums'][path]=out['scalar_sums'].get(path,0)+value
        first=f.get('firstPacket');last=f.get('lastPacket')
        if first is not None:out['first_packet_ms']=min(first,out['first_packet_ms'] if out['first_packet_ms'] is not None else first)
        if last is not None:out['last_packet_ms']=max(last,out['last_packet_ms'] if out['last_packet_ms'] is not None else last)
    if out['first_packet_ms'] is not None and out['last_packet_ms'] is not None:out['duration_ms']=out['last_packet_ms']-out['first_packet_ms']
    return out

class Store:
    def __init__(self,path):
        Path(path).parent.mkdir(parents=True,exist_ok=True)
        self.db=sqlite3.connect(path,timeout=30)
        self.db.execute('pragma journal_mode=WAL');self.db.execute('pragma synchronous=FULL')
        self.db.execute('pragma cache_size=-16384');self.db.execute('pragma temp_store=FILE')
        self.db.executescript('''
        create table if not exists meta(key text primary key,value integer);
        create table if not exists fragments(index_name text,id text,revision text,session_key text,generation integer,source_json text,primary key(index_name,id));
        create index if not exists fragment_session on fragments(session_key);
        create index if not exists fragment_seq on fragments(json_extract(source_json,'$.office.seq'));
        create table if not exists chunks(path text primary key,sha256 text,bytes integer,packets integer,rows_ok integer default 0,arkime_ok integer default 0);
        create table if not exists revisions(index_name text,id text,revision text,source_json text,primary key(index_name,id,revision));
        create table if not exists feature_atoms(index_name text,id text,session_key text,field_path text,value_json text,shape text,primary key(index_name,id,field_path,value_json));
        create index if not exists feature_atom_session on feature_atoms(session_key,field_path);
        create table if not exists loads(id text primary key,manifest text,committed_at real);
        create table if not exists session_totals(session_key text primary key,generation integer,summary_json text,latest_seq integer,ended integer,started integer,end_reason integer);
        ''')
        if 'ordinal' not in [row[1] for row in self.db.execute('pragma table_info(chunks)')]:
            self.db.execute('alter table chunks add column ordinal integer')
        self.generation=self.db.execute("select coalesce((select value from meta where key='generation'),0)").fetchone()[0]
        if self.db.execute('select count(*) from session_totals').fetchone()[0]==0:
            with self.db:
                for (key,) in self.db.execute('select distinct session_key from fragments'):self.update_totals(key,{},rebuild=True)
        if self.db.execute("select coalesce((select value from meta where key='aggregation_version'),0)").fetchone()[0]<2:
            with self.db:
                for (key,) in self.db.execute('select distinct session_key from fragments'):self.update_totals(key,{},rebuild=True)
                self.db.execute("insert or replace into meta values('aggregation_version',2)")
    def packet_total(self):
        return self.db.execute("select coalesce((select value from meta where key='packet_total'),0)").fetchone()[0]
    def update_totals(self,key,source,rebuild=False):
        row=self.db.execute('select generation,summary_json,latest_seq,ended,started,end_reason from session_totals where session_key=?',(key,)).fetchone()
        if rebuild or row is None:
            sources=(json.loads(r[0]) for r in self.db.execute('select source_json from fragments where session_key=?',(key,)))
            summary=reduce_fragments([]);latest=-1;ended=started=reason=0;gen=self.generation
        else:
            gen,raw,latest,ended,started,reason=row;summary=json.loads(raw);sources=iter([source])
        for f in sources:
            part=reduce_fragments([f]);q=f.get('office',{});seq=q.get('seq',0)
            for k in ('fragments','packets','bytes','src_packets','dst_packets','src_bytes','dst_bytes'):summary[k]+=part[k]
            sums=summary.setdefault('scalar_sums',{})
            for path,value in part['scalar_sums'].items():sums[path]=sums.get(path,0)+value
            for k,fn in [('first_packet_ms',min),('last_packet_ms',max)]:
                if part[k] is not None:summary[k]=part[k] if summary[k] is None else fn(summary[k],part[k])
            if seq>=latest and 'officeEntropy' in f:latest=seq;summary['entropy_src']=part['entropy_src'];summary['entropy_dst']=part['entropy_dst']
            ended|=bool(q.get('final'));started|=bool(q.get('startObserved'));reason|=bool(q.get('endReason'))
        if summary['first_packet_ms'] is not None and summary['last_packet_ms'] is not None:summary['duration_ms']=summary['last_packet_ms']-summary['first_packet_ms']
        previous=json.loads(row[1])['packets'] if row else 0
        self.db.execute("insert into meta values('packet_total',?) on conflict(key) do update set value=value+excluded.value",(summary['packets']-previous,))
        self.db.execute('insert or replace into session_totals values(?,?,?,?,?,?,?)',(key,gen,compact(summary),latest,int(ended),int(started),int(reason)))
    def new_generation(self):
        with self.db:
            self.generation+=1;self.db.execute("insert into meta values('generation',?) on conflict(key) do update set value=excluded.value",(self.generation,))
        return self.generation
    def put_fragment(self,hit,commit=True):
        raw=compact(hit['_source']);rev=hashlib.sha256(raw.encode()).hexdigest();key=hit['_source'].get('rootId') or hit['_id']
        office=hit['_source'].get('office',{})
        if 'instance' in office:key=str(hit['_source'].get('node','unknown'))+':'+str(office['instance'])
        old=self.db.execute('select revision,session_key from fragments where index_name=? and id=?',(hit['_index'],hit['_id'])).fetchone()
        if old and old[0]==rev and self.db.execute('select 1 from feature_atoms where index_name=? and id=? limit 1',(hit['_index'],hit['_id'])).fetchone():return False
        with self.db if commit else contextlib.nullcontext():
            self.db.execute('insert or ignore into revisions values(?,?,?,?)',(hit['_index'],hit['_id'],rev,raw))
            self.db.execute('insert into fragments values(?,?,?,?,?,?) on conflict(index_name,id) do update set revision=excluded.revision,session_key=excluded.session_key,source_json=excluded.source_json',(hit['_index'],hit['_id'],rev,key,self.generation,raw))
            self.db.execute('delete from feature_atoms where index_name=? and id=?',(hit['_index'],hit['_id']))
            for path,value in flatten(hit['_source']):
                # SPI arrays represent distinct observations, except packet
                # bookkeeping arrays, whose complete ordering is kept in raw SPI.
                administrative=path in ('packetPos','fileId','fileLen')
                if administrative:continue  # Complete arrays remain in raw SPI and per-fragment EAV.
                shape='array' if isinstance(value,list) and not administrative else 'scalar'
                atoms=value if shape=='array' and value else [value]
                for atom in atoms:self.db.execute('insert or ignore into feature_atoms values(?,?,?,?,?,?)',(hit['_index'],hit['_id'],key,path,compact(atom),shape))
            self.update_totals(key,hit['_source'],rebuild=bool(old))
            if old and old[1]!=key:self.update_totals(old[1],{},rebuild=True)
        return True
    def register_chunk(self,path,sha256,size):
        path=str(Path(path).resolve());old=self.db.execute('select sha256 from chunks where path=?',(path,)).fetchone()
        if old and old[0]!=sha256:raise ValueError('input changed under registered path')
        with self.db:self.db.execute('insert or ignore into chunks(path,sha256,bytes) values(?,?,?)',(path,sha256,size))
    def commit_chunk(self,path,packets,rows_ok,arkime_ok):
        with self.db:self.db.execute('update chunks set packets=?,rows_ok=?,arkime_ok=? where path=?',(packets,int(rows_ok),int(arkime_ok),str(Path(path).resolve())))
    def acknowledge_fragments_before(self,path,ordinal,hold_from):
        with self.db:
            self.db.execute('update chunks set ordinal=? where path=?',(ordinal,str(Path(path).resolve())))
            self.db.execute('update chunks set arkime_ok=1 where ordinal<?',(hold_from,))
    def can_delete(self,path):
        row=self.db.execute('select rows_ok,arkime_ok from chunks where path=?',(str(Path(path).resolve()),)).fetchone();return bool(row and row==(1,1))
    def contiguous_sequence(self):
        current=self.db.execute("select coalesce((select value from meta where key='ack_seq'),0)").fetchone()[0]
        for (seq,) in self.db.execute("select json_extract(source_json,'$.office.seq') from fragments where json_extract(source_json,'$.office.seq')>? order by json_extract(source_json,'$.office.seq')",(current,)):
            if seq!=current+1:break
            current=seq
        with self.db:self.db.execute("insert into meta values('ack_seq',?) on conflict(key) do update set value=excluded.value",(current,))
        return current
    def close(self):self.db.close()

class OpenSearch:
    def __init__(self,url='http://127.0.0.1:19200'):self.url=url.rstrip('/')
    def call(self,method,path,data=None):
        req=urllib.request.Request(self.url+path,data=None if data is None else compact(data).encode(),method=method,headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=120) as r:return json.load(r)
    def hits(self,index,query=None,size=256):
        scroll = None
        try:
            response = self.call('POST', f'/{index}/_search?scroll=5m',
                                 dict(size=size, sort=['_doc'], query=query or {'match_all': {}}))
            while True:
                scroll = response.get('_scroll_id', scroll)
                if response.get('timed_out') or response.get('_shards', {}).get('failed', 0):
                    raise RuntimeError('incomplete OpenSearch search')
                page = response['hits']['hits']
                if not page:
                    break
                yield from page
                response = self.call('POST', '/_search/scroll', {'scroll': '5m', 'scroll_id': scroll})
        finally:
            if scroll:
                self.call('DELETE', '/_search/scroll', {'scroll_id': [scroll]})

def fsync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def hash_file(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(4*1024*1024),b''):h.update(block)
    return h.hexdigest()

def write_table(path,schema,rows,batch=1024):
    import pyarrow as pa
    import pyarrow.parquet as pq
    path=Path(path);partial=path.with_suffix('.partial');count=0;buf=[];buffer_bytes=0
    try:
        with pq.ParquetWriter(partial,schema,compression='zstd',use_dictionary=True) as w:
            for row in rows:
                buf.append(row);buffer_bytes+=len(compact(row).encode())
                if len(buf)>=batch or buffer_bytes>=8*1024*1024:w.write_table(pa.Table.from_pylist(buf,schema=schema));count+=len(buf);buf=[];buffer_bytes=0
            if buf:w.write_table(pa.Table.from_pylist(buf,schema=schema));count+=len(buf)
        with partial.open('rb') as f:os.fsync(f.fileno())
        os.replace(partial,path)
        return dict(rows=count,bytes=path.stat().st_size,sha256=hash_file(path))
    except BaseException:partial.unlink(missing_ok=True);raise

def export_tables(store,out_dir,final=False,export_id='local',after_rowid=0):
    import pyarrow as pa
    destination=Path(out_dir)
    if destination.exists():raise FileExistsError(destination)
    destination.parent.mkdir(parents=True,exist_ok=True)
    out=destination.with_name(destination.name+'.staging-'+uuid.uuid4().hex)
    out.mkdir()
    frag_schema=pa.schema([(x,pa.string()) for x in ('index_name','fragment_id','session_key','revision','source_json')]+[('generation',pa.int64())])
    def frags():
        for idx,ident,rev,key,gen,raw in store.db.execute('select * from fragments where rowid>%d order by index_name,id'%after_rowid+''):yield dict(index_name=idx,fragment_id=ident,revision=rev,session_key=key,generation=gen,source_json=raw)
    field_schema=pa.schema([(x,pa.string()) for x in ('session_key','fragment_id','index_name','field_path','value_json','value_type')])
    def fields():
        for f in frags():
            for name,value in flatten(json.loads(f['source_json'])):yield dict(session_key=f['session_key'],fragment_id=f['fragment_id'],index_name=f['index_name'],field_path=name,value_json=compact(value),value_type=type(value).__name__)
    cols=[('session_key',pa.string()),('generation',pa.int64()),('final',pa.bool_()),('complete',pa.bool_())]+[(x,pa.int64()) for x in ('fragments','packets','bytes','src_packets','dst_packets','src_bytes','dst_bytes','first_packet_ms','last_packet_ms','duration_ms')]
    cols += [('entropy_src',pa.float64()),('entropy_dst',pa.float64())]
    def sessions():
        query='select session_key,generation,summary_json,ended,started,end_reason from session_totals where session_key in (select session_key from fragments where rowid>?) order by session_key'
        for key,gen,raw,ended,started,reason in store.db.execute(query,(after_rowid,)):
            summary=json.loads(raw);summary.pop('scalar_sums',None)
            yield dict(session_key=key,generation=gen,final=bool(ended),complete=bool(ended and started and reason),**summary)
    feature_schema=pa.schema([(x,pa.string()) for x in ('session_key','field_path','value_json','aggregation')])
    def feature_rows():
        query="select session_key,field_path,value_json,shape from feature_atoms where session_key in (select session_key from fragments where rowid>?) and session_key in (select session_key from fragments where json_extract(source_json,'$.office.final')=1) group by session_key,field_path,value_json,shape order by session_key,field_path,value_json"
        for key,path,value,shape in store.db.execute(query,(after_rowid,)):
            yield dict(session_key=key,field_path=path,value_json=value,aggregation='set_union' if shape=='array' else 'distinct_observation')
        # *Cnt in native SPI counts the unique values in THAT fragment. A sum
        # would double count repeated names. Derive full-session set counts.
        query="select session_key,field_path,count(distinct case when value_json!='[]' then value_json end) from feature_atoms where shape='array' and session_key in (select session_key from fragments where rowid>?) and session_key in (select session_key from fragments where json_extract(source_json,'$.office.final')=1) group by session_key,field_path"
        for key,path,count in store.db.execute(query,(after_rowid,)):
            yield dict(session_key=key,field_path=path+'Cnt',value_json=str(count),aggregation='unique_count')
        for key,raw in store.db.execute('select session_key,summary_json from session_totals where ended=1 and session_key in (select session_key from fragments where rowid>?)',(after_rowid,)):
            for path,value in json.loads(raw).get('scalar_sums',{}).items():yield dict(session_key=key,field_path=path,value_json=str(value),aggregation='sum')
    chunk_schema=pa.schema([(x,pa.string()) for x in ('path','sha256')]+[(x,pa.int64()) for x in ('bytes','packets')]+[(x,pa.bool_()) for x in ('rows_ok','arkime_ok')])
    def chunks():
        for path,sha,size,packets,rows_ok,arkime_ok in store.db.execute('select path,sha256,bytes,packets,rows_ok,arkime_ok from chunks where ordinal is null or %d=1'%int(final)+' order by path'):
            yield dict(path=path,sha256=sha,bytes=size,packets=packets,rows_ok=bool(rows_ok),arkime_ok=bool(arkime_ok))
    manifest=dict(export_id=export_id,generation=store.generation,final=final,schema_version=1,semantics='raw SPI + protocol set unions + derived unique counts; other scalars retained as observations; entropy cumulative observed payload',files={})
    for name,schema,rows in [('arkime_fragments',frag_schema,frags()),('arkime_field_values',field_schema,fields()),('arkime_sessions',pa.schema(cols),sessions()),('arkime_session_field_values',feature_schema,feature_rows()),('arkime_input_ledger',chunk_schema,chunks())]:manifest['files'][name+'.parquet']=write_table(out/(name+'.parquet'),schema,rows)
    partial=out/'manifest.json.partial'
    with partial.open('w') as f:f.write(compact(manifest)+'\n');f.flush();os.fsync(f.fileno())
    os.replace(partial,out/'manifest.json')
    for name,info in manifest['files'].items():
        if hash_file(out/name)!=info['sha256']:raise RuntimeError('Parquet hash mismatch')
        import pyarrow.parquet as pq
        if pq.read_metadata(out/name).num_rows!=info['rows']:raise RuntimeError('Parquet row mismatch')
    fsync_dir(out)
    os.rename(out,destination)
    fsync_dir(destination.parent)
    return manifest

def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['sync','export']);p.add_argument('--state',type=Path,required=True);p.add_argument('--out',type=Path);p.add_argument('--tag');p.add_argument('--final',action='store_true');p.add_argument('--export-id',default='local');a=p.parse_args();s=Store(a.state)
    try:
        if a.command=='sync':
            api=OpenSearch();api.call('POST','/office_arkime_sessions3-*/_refresh');query={'term':{'tags':a.tag}} if a.tag else {'match_all':{}};count=0
            for hit in api.hits('office_arkime_sessions3-*',query):count+=s.put_fragment(hit)
            print(compact(dict(updated=count,total=s.db.execute('select count(*) from fragments').fetchone()[0])))
        else:
            if not a.out:p.error('--out required')
            print(compact(export_tables(s,a.out,a.final,a.export_id)))
    finally:s.close()
if __name__=='__main__':main()
