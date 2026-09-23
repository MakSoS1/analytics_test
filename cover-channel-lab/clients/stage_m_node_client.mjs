import process from 'node:process';
import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';
import dns from 'node:dns';

const chunks=[]; for await (const c of process.stdin) chunks.push(c);
const q=JSON.parse(Buffer.concat(chunks).toString('utf8'));
process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';

const sleep=(ms)=>new Promise(r=>setTimeout(r,ms));

async function runDns(){
  const r=new dns.promises.Resolver();
  r.setServers([q.server]);
  let ans;
  if(q.qtype==='A') ans=await r.resolve4(q.qname);
  else if(q.qtype==='AAAA') ans=await r.resolve6(q.qname);
  else ans=await r.resolveTxt(q.qname);
  console.log(JSON.stringify({ok:true,count:ans.length}));
}

function encodeFrame(data, framing){
  const b=Buffer.from(data);
  if(framing==='len16'){const h=Buffer.alloc(2);h.writeUInt16BE(b.length);return Buffer.concat([h,b]);}
  if(framing==='len32'){const h=Buffer.alloc(4);h.writeUInt32BE(b.length);return Buffer.concat([h,b]);}
  if(framing==='newline') return Buffer.concat([Buffer.from(data.replaceAll('\n','.')),Buffer.from('\n')]);
  return Buffer.concat([b.subarray(0,64),Buffer.alloc(Math.max(0,64-b.length),46)]);
}
async function runTunnel(){
  await new Promise((resolve,reject)=>{
    const s=net.createConnection({host:q.host,port:q.port},async()=>{
      s.write(JSON.stringify({campaign_id:q.campaign_id,framing:q.framing,direction:q.direction})+'\n');
    });
    let ready=false, received=0, idx=0;
    s.on('data',async(d)=>{
      received+=d.length;
      if(!ready){ready=true; for(idx=0;idx<q.payloads.length;idx++){s.write(encodeFrame(q.payloads[idx],q.framing)); if(q.delay_ms) await sleep(q.delay_ms);} s.end();}
    });
    s.on('end',()=>{console.log(JSON.stringify({ok:true,received}));resolve();});
    s.on('error',reject);
  });
}

async function runWs(){
  await new Promise((resolve,reject)=>{
    const u=new URL(q.url);
    const key=crypto.randomBytes(16).toString('base64');
    const s=tls.connect({host:u.hostname,port:Number(u.port||443),servername:u.hostname,rejectUnauthorized:false},()=>{
      s.write(`GET ${u.pathname||'/'} HTTP/1.1\r\nHost: ${u.host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`);
    });
    let header=Buffer.alloc(0), upgraded=false, sent=false, events=[];
    function frame(text){
      const data=Buffer.from(text); const mask=crypto.randomBytes(4); let h;
      if(data.length<126) h=Buffer.from([0x81,0x80|data.length]);
      else {h=Buffer.alloc(4);h[0]=0x81;h[1]=0x80|126;h.writeUInt16BE(data.length,2);}
      const m=Buffer.alloc(data.length); for(let i=0;i<data.length;i++)m[i]=data[i]^mask[i%4];
      return Buffer.concat([h,mask,m]);
    }
    s.on('data',async(d)=>{
      if(!upgraded){
        header=Buffer.concat([header,d]);
        const pos=header.indexOf('\r\n\r\n'); if(pos<0)return;
        if(!header.subarray(0,pos).toString().includes(' 101 ')){reject(new Error('websocket upgrade failed'));s.destroy();return;}
        upgraded=true;
      }
      if(upgraded && !sent){
        sent=true;
        try{
          for(let i=0;i<q.messages.length;i++){
            const ms=Date.now();s.write(frame(q.messages[i]));events.push({index:i,ms});if(q.delay_ms)await sleep(q.delay_ms);
          }
          setTimeout(()=>s.end(),80);
        }catch(e){reject(e)}
      }
    });
    s.on('end',()=>{console.log(JSON.stringify({ok:true,events}));resolve();});
    s.on('error',reject);
  });
}

try{
  if(q.mode==='dns') await runDns();
  else if(q.mode==='tunnel') await runTunnel();
  else if(q.mode==='ws') await runWs();
  else throw new Error('unknown mode');
}catch(e){console.error(String(e?.stack||e));process.exit(2)}
