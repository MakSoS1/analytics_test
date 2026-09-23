import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import {URL} from 'node:url';

const args=Object.fromEntries(process.argv.slice(2).map((x,i,a)=>x.startsWith('--')?[x.slice(2),a[i+1]]:null).filter(Boolean));
const host=args.host||'10.20.0.20', hp=Number(args['http-port']||9081), sp=Number(args['https-port']||9445);
function size(path){ if(path.startsWith('/api/detail')) return 4096; if(path.startsWith('/api/upload')) return 96; if(path.startsWith('/public/')) return 192; return 512; }
async function collect(req){const chunks=[];let n=0;for await(const c of req){n+=c.length;if(n<=65536)chunks.push(c)}return Buffer.concat(chunks).subarray(0,65536)}
async function handler(req,res){
  const u=new URL(req.url,'http://stage-m-node.test');
  if(u.pathname==='/healthz'){res.writeHead(200,{'content-type':'application/json'});return res.end('{"ok":true}')}
  if(u.pathname==='/api/unavailable'){res.writeHead(503);return res.end('temporarily unavailable')}
  if(u.pathname==='/dns-query'){
    let b;if(req.method==='GET'){let t=u.searchParams.get('dns')||''; t+= '='.repeat((4-t.length%4)%4); b=Buffer.from(t,'base64url')} else b=await collect(req);
    if(!b.length)b=Buffer.from([0,0,1,0,0,1,0,0,0,0,0,0]);res.writeHead(200,{'content-type':'application/dns-message','content-length':b.length});return res.end(b)
  }
  await collect(req); const n=size(u.pathname), b=Buffer.alloc(n,82);res.writeHead(200,{'content-type':'application/octet-stream','content-length':n});res.end(b)
}
http.createServer(handler).listen(hp,host);
https.createServer({cert:fs.readFileSync(args.cert),key:fs.readFileSync(args.key),minVersion:'TLSv1.2'},handler).listen(sp,host);
