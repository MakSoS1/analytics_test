import struct, socket, json
from pathlib import Path

def checksum(b):
    if len(b)%2:b+=b'\0'
    s=sum(struct.unpack('!%dH'%(len(b)//2),b));s=(s&65535)+(s>>16);s=(s&65535)+(s>>16);return (~s)&65535

def tcp(src,dst,sp,dp,seq,ack,flags,payload=b''):
    a=socket.inet_aton(src);b=socket.inet_aton(dst)
    h=struct.pack('!HHIIBBHHH',sp,dp,seq,ack,80,flags,65535,0,0)
    check=checksum(a+b+struct.pack('!BBH',0,6,len(h)+len(payload))+h+payload)
    h=h[:16]+struct.pack('!H',check)+h[18:]
    ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(h)+len(payload),0,0,64,6,0,a,b)
    ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    return bytes.fromhex('00112233445566778899aabb0800')+ip+h+payload

HEADER=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
def record(t,frame):
    sec=int(t);return struct.pack('<IIII',sec,int(round((t-sec)*1e6)),len(frame),len(frame))+frame

def long_session(root,packets=30000,duration=1200,bucket_seconds=10):
    root=Path(root);root.mkdir(parents=True,exist_ok=True);split=root/'split';split.mkdir(exist_ok=True)
    t0=1700000000;paths=[];current=None;fh=None;total=0
    src='192.0.2.10';dst='198.51.100.20';sp=43210;dp=80;seq=1001;ack=2001
    def emit(t,frame):
        nonlocal current,fh,total
        raw=record(t,frame);whole.write(raw);bucket=int((t-t0)//bucket_seconds)
        if bucket!=current:
            if fh:fh.close()
            current=bucket;path=split/f'chunk-{bucket:06d}.pcap';paths.append(str(path.resolve()));fh=path.open('wb');fh.write(HEADER)
        fh.write(raw);total+=1
    with (root/'whole.pcap').open('wb') as whole:
        whole.write(HEADER)
        emit(t0,tcp(src,dst,sp,dp,1000,0,2));emit(t0+.001,tcp(dst,src,dp,sp,2000,1001,18));emit(t0+.002,tcp(src,dst,sp,dp,seq,ack,16))
        payload=b'GET /long HTTP/1.1\r\nHost: fixture.example\r\nCookie: one=two\r\n\r\n'
        for i in range(packets):
            t=t0+.01+(duration-.1)*i/packets
            emit(t,tcp(src,dst,sp,dp,seq,ack,24,payload));seq+=len(payload)
            emit(t+.001,tcp(dst,src,dp,sp,ack,seq,16))
        emit(t0+duration,tcp(src,dst,sp,dp,seq,ack,17));emit(t0+duration+.001,tcp(dst,src,dp,sp,ack,seq+1,17))
    if fh:fh.close()
    (root/'files.txt').write_text('\n'.join(paths)+'\n');m=dict(packets=total,duration=duration,files=len(paths),whole=str((root/'whole.pcap').resolve()))
    (root/'expected.json').write_text(json.dumps(m));return m

def reused(root):
    root=Path(root);root.mkdir(parents=True,exist_ok=True);p=root/'reused.pcap';t0=1700000000
    with p.open('wb') as f:
        f.write(HEADER)
        for t,seq in [(t0,100),(t0+70,200)]:f.write(record(t,tcp('192.0.2.1','198.51.100.1',40000,443,seq,0,2)))
    return p
if __name__=='__main__':
    import sys;print(json.dumps(long_session(sys.argv[1])))
