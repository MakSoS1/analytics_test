import process from 'node:process';
const chunks=[]; for await (const c of process.stdin) chunks.push(c);
const q=JSON.parse(Buffer.concat(chunks).toString('utf8'));
const body=q.body_b64 ? Buffer.from(q.body_b64,'base64') : undefined;
process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';
try {
  const r=await fetch(q.url,{method:q.method,headers:q.headers,body,redirect:'manual'});
  await r.arrayBuffer(); console.log(r.status);
} catch(e) { console.error(String(e)); process.exit(2); }
