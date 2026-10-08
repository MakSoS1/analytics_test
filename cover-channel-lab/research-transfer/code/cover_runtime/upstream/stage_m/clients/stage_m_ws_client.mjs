import tls from 'node:tls';
import crypto from 'node:crypto';
import process from 'node:process';

function arg(name, fallback=null) {
  const i=process.argv.indexOf(name);
  return i>=0 ? process.argv[i+1] : fallback;
}
const target=arg('--url');
const events=Number(arg('--events','4'));
const seed=Number(arg('--seed','1'));
const mode=arg('--mode','wss');
if(!target) throw new Error('--url required');
const u=new URL(target);
if(u.protocol!=='wss:' || !['edge-ws.test','cover-ws.test'].includes(u.hostname)) {
  throw new Error('Stage M Node WSS is restricted to local allowlisted hosts');
}
const port=Number(u.port||8443);
const key=crypto.randomBytes(16).toString('base64');

function maskedTextFrame(text){
  const payload=Buffer.from(text);
  const mask=crypto.randomBytes(4);
  let head;
  if(payload.length<126){
    head=Buffer.from([0x81,0x80|payload.length]);
  }else if(payload.length<65536){
    head=Buffer.alloc(4); head[0]=0x81; head[1]=0x80|126; head.writeUInt16BE(payload.length,2);
  }else throw new Error('payload too large');
  const masked=Buffer.alloc(payload.length);
  for(let i=0;i<payload.length;i++) masked[i]=payload[i]^mask[i%4];
  return Buffer.concat([head,mask,masked]);
}
function token(i){
  const x=(seed*1103515245 + i*12345) >>> 0;
  return x.toString(16).padStart(8,'0');
}
function parseFrames(buf){
  const frames=[]; let off=0;
  while(off+2<=buf.length){
    const b0=buf[off], b1=buf[off+1];
    let len=b1&0x7f, h=2;
    if(len===126){ if(off+4>buf.length) break; len=buf.readUInt16BE(off+2); h=4; }
    else if(len===127){ break; }
    if(off+h+len>buf.length) break;
    frames.push(buf.subarray(off+h,off+h+len));
    off+=h+len;
  }
  return {frames,rest:buf.subarray(off)};
}

const socket=tls.connect({host:u.hostname,port,servername:u.hostname,rejectUnauthorized:false});
let handshake=Buffer.alloc(0), ready=false, frameBuf=Buffer.alloc(0), received=0;
const started=Date.now();

await new Promise((resolve,reject)=>{
  const timer=setTimeout(()=>reject(new Error('stage-m raw Node WSS timeout')),30000);
  socket.on('secureConnect',()=>{
    const req=[
      `GET ${u.pathname||'/ws'} HTTP/1.1`,
      `Host: ${u.hostname}:${port}`,
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Key: ${key}`,
      'Sec-WebSocket-Version: 13',
      'User-Agent: coverlab-stage-m-node/1',
      '', ''
    ].join('\r\n');
    socket.write(req);
  });
  socket.on('data',(chunk)=>{
    if(!ready){
      handshake=Buffer.concat([handshake,chunk]);
      const p=handshake.indexOf('\r\n\r\n');
      if(p<0) return;
      const head=handshake.subarray(0,p).toString('utf8');
      if(!/^HTTP\/1\.1 101 /m.test(head)) return reject(new Error('websocket upgrade failed: '+head.slice(0,200)));
      ready=true;
      frameBuf=handshake.subarray(p+4);
      for(let i=0;i<events;i++){
        const data=Buffer.from('NODE_STAGE_M_'+token(i)).toString('base64');
        const msg=mode==='tunnel'
          ? {type:'socks_data',conn_id:'n'+(i%4),data}
          : {action:i%2?'send':'recv',container:token(i),target:'LAB',message:'STATUS'};
        socket.write(maskedTextFrame(JSON.stringify(msg)));
      }
    }else{
      frameBuf=Buffer.concat([frameBuf,chunk]);
    }
    const parsed=parseFrames(frameBuf); frameBuf=parsed.rest;
    for(const fr of parsed.frames){
      console.log(JSON.stringify({
        event_id:'e'+String(received).padStart(3,'0'),
        event_type:'stage_m_wss_node',
        sent_at:new Date(started).toISOString(),
        completed_at:new Date().toISOString(),
        encoded_length:0,
        reply_len:fr.length,
        wss_client_impl:'node_websocket'
      }));
      received++;
      if(received>=events){ clearTimeout(timer); socket.end(); resolve(); break; }
    }
  });
  socket.on('error',(e)=>{clearTimeout(timer); reject(e);});
});
