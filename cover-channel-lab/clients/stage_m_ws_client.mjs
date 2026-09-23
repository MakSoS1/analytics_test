import process from 'node:process';

function arg(name, fallback=null) {
  const i=process.argv.indexOf(name);
  return i>=0 ? process.argv[i+1] : fallback;
}
const url=arg('--url');
const events=Number(arg('--events','4'));
const seed=Number(arg('--seed','1'));
const mode=arg('--mode','wss');
if(!url) throw new Error('--url required');
process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';

let WS=globalThis.WebSocket;
if(!WS){
  try { WS=(await import('undici')).WebSocket; }
  catch { throw new Error('Node WebSocket implementation unavailable'); }
}
function token(i){
  const x=(seed*1103515245 + i*12345) >>> 0;
  return x.toString(16).padStart(8,'0');
}
const ws=new WS(url);
let sent=0;
let received=0;
const started=Date.now();

await new Promise((resolve,reject)=>{
  const timer=setTimeout(()=>reject(new Error('stage-m websocket timeout')),30000);
  ws.addEventListener('open',()=>{
    for(let i=0;i<events;i++){
      const data=Buffer.from('NODE_STAGE_M_'+token(i)).toString('base64');
      const msg=mode==='tunnel'
        ? {type:'socks_data',conn_id:'n'+(i%4),data}
        : {action:i%2?'send':'recv',container:token(i),target:'LAB',message:'STATUS'};
      ws.send(JSON.stringify(msg));
      sent++;
    }
  });
  ws.addEventListener('message',(ev)=>{
    received++;
    console.log(JSON.stringify({
      event_id:'e'+String(received-1).padStart(3,'0'),
      event_type:'stage_m_wss_node',
      sent_at:new Date(started).toISOString(),
      completed_at:new Date().toISOString(),
      encoded_length:0,
      reply_len:typeof ev.data==='string'?ev.data.length:(ev.data?.byteLength||0),
      wss_client_impl:'node_websocket'
    }));
    if(received>=events){ clearTimeout(timer); ws.close(); resolve(); }
  });
  ws.addEventListener('error',(e)=>{clearTimeout(timer); reject(new Error('websocket error '+String(e?.message||e)));});
});
