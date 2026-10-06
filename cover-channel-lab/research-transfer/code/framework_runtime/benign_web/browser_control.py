"""Local Chrome CDP: graceful close and fixed read-only page proof; no arbitrary JS."""
import argparse,base64,hashlib,json,secrets,socket,struct,time
from urllib.parse import urlsplit

MARKERS=('Example Domain','Python','Wikipedia')

def endpoint(url,kind='browser'):
    u=urlsplit(url)
    if kind not in ('browser','page') or u.scheme!='ws' or u.hostname!='127.0.0.1' or not u.port or u.username or u.password or not u.path.startswith('/devtools/'+kind+'/') or u.query or u.fragment or any(x in u.path for x in ('\r','\n',' ')):
        raise ValueError('only local Chrome endpoint permitted')
    return u

def page_expression(marker):
    if marker not in MARKERS:raise ValueError('only fixed public page markers')
    return 'JSON.stringify({ready:document.readyState,marker:(document.title.includes('+json.dumps(marker)+') || (!!document.body && document.body.textContent.includes('+json.dumps(marker)+'))),title:document.title,url:document.URL,snippet:document.body?document.body.textContent.slice(0,120):null})'

def _read(channel,size):
    out=b''
    while len(out)<size:
        p=channel.recv(size-len(out))
        if not p:return None
        out+=p
    return out

def exchange(url,kind,message,allow_close=False):
    u=endpoint(url,kind);key=base64.b64encode(secrets.token_bytes(16)).decode()
    request=f'GET {u.path} HTTP/1.1\r\nHost: 127.0.0.1:{u.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n'
    with socket.create_connection(('127.0.0.1',u.port),timeout=5) as channel:
        channel.sendall(request.encode());header=b''
        # Read bytewise to avoid consuming part of the first WebSocket frame.
        while not header.endswith(b'\r\n\r\n'):
            part=channel.recv(1)
            if not part or len(header)>65536:raise ValueError('incomplete WebSocket upgrade')
            header+=part
        lines=header.split(b'\r\n');fields={p.split(b':',1)[0].lower():p.split(b':',1)[1].strip() for p in lines[1:] if b':' in p}
        expected=base64.b64encode(hashlib.sha1(key.encode()+b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
        if b' 101 ' not in lines[0] or fields.get(b'sec-websocket-accept')!=expected:raise ValueError('WebSocket upgrade not verified')
        payload=json.dumps(message,separators=(',',':')).encode();mask=secrets.token_bytes(4);size=len(payload)
        prefix=bytes((0x81,0x80|size)) if size<126 else bytes((0x81,0x80|126))+struct.pack('!H',size)
        channel.sendall(prefix+mask+bytes(v^mask[i%4] for i,v in enumerate(payload)))
        for _ in range(32):
            head=_read(channel,2)
            if head is None:
                if allow_close:return None
                raise ValueError('page proof connection closed')
            size=head[1]&127
            if size in (126,127):
                raw=_read(channel,2 if size==126 else 8)
                if raw is None:raise ValueError('incomplete CDP response')
                size=struct.unpack('!H' if size==126 else '!Q',raw)[0]
            if size>1<<20:raise ValueError('CDP response exceeds bound')
            if head[1]&128:raise ValueError('unexpected masked server frame')
            payload=_read(channel,size)
            if (head[0]&15)==8 and allow_close:return None
            if (head[0]&15)!=1 or payload is None:raise ValueError('unsupported CDP frame')
            r=json.loads(payload)
            if r.get('id')==1:return r
        raise ValueError('CDP response not observed')

def close_browser(url):return exchange(url,'browser',{'id':1,'method':'Browser.close'},True)

def prove_page(url,marker):
    for attempt in range(16):
        response=exchange(url,'page',{'id':1,'method':'Runtime.evaluate','params':{'expression':page_expression(marker),'returnByValue':True}})
        if response.get('error') or response.get('result',{}).get('exceptionDetails'):raise ValueError('page evaluation failed')
        result=json.loads(response['result']['result']['value'])
        if result.get('ready')=='complete' and result.get('marker') is True:return {'ready':'complete','marker':True}
        if attempt<15:time.sleep(.5)
    raise ValueError('target page not complete/content not found: '+json.dumps(result))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--url',required=True);p.add_argument('--marker',choices=MARKERS);a=p.parse_args()
    if a.marker:print(json.dumps(prove_page(a.url,a.marker)))
    else:close_browser(a.url)
