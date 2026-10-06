"""Fixed local TCP round trip for the Stage M WSS tunnel fixture.

No target parameter, arbitrary forwarding, command interpretation or external
route. This is a semantic WSS tunnel with actual bounded local TCP forwarding;
it does not claim a standards-compliant SOCKS implementation.
"""
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import struct
import time

LIMIT=65536


async def echo_handler(reader,writer):
    try:
        n=struct.unpack('!I',await asyncio.wait_for(reader.readexactly(4),5))[0]
        if n>LIMIT:raise ValueError('bounded payload exceeded')
        data=await asyncio.wait_for(reader.readexactly(n),5)
        writer.write(struct.pack('!I',n)+data);await writer.drain()
    finally:
        writer.close();await writer.wait_closed()


async def tunnel_reply(message):
    if any(k in message for k in ('target_host','target_port','command','url')):raise ValueError('fixed local fixture only')
    encoded=message.get('data','')
    if not isinstance(encoded,str) or len(encoded)>4*((LIMIT+2)//3):raise ValueError('bounded encoded payload exceeded')
    data=base64.b64decode(encoded,validate=True)
    if len(data)>LIMIT:raise ValueError('bounded payload exceeded')
    reader,writer=await asyncio.wait_for(asyncio.open_connection('127.0.0.1',9092),5)
    try:
        writer.write(struct.pack('!I',len(data))+data);await writer.drain()
        size=struct.unpack('!I',await asyncio.wait_for(reader.readexactly(4),5))[0]
        if size!=len(data):raise ValueError('forwarded byte length differs')
        returned=await asyncio.wait_for(reader.readexactly(size),5)
        if returned!=data:raise ValueError('forwarded bytes differ')
    finally:
        writer.close();await writer.wait_closed()
    sha=hashlib.sha256(data).hexdigest()
    journal=Path('/out/fixed_forwarding.jsonl')
    if journal.parent.exists():
        with journal.open('a') as f:f.write(json.dumps({'ts':time.time(),'bytes':len(data),'sha256':sha,'target':'fixed_loopback_9092'})+'\n')
    return {'type':'data_ack','conn_id':str(message.get('conn_id','0'))[:64],'n':len(data),
            'data':base64.b64encode(returned).decode(),'sha256':sha,'forwarding_status':'verified_fixed_local_tcp_roundtrip'}


async def main():
    server=await asyncio.start_server(echo_handler,'127.0.0.1',9092)
    async with server:await server.serve_forever()


if __name__=='__main__':asyncio.run(main())
